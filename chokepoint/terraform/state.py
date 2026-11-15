"""Terraform state parser (plan Section 6: collectors).

Parses a ``terraform.tfstate`` file (version 4, tolerant of 3)
into resources, and maps resource addresses to Chokepoint graph
node ids so a fix can be tied back to the graph it was ranked
from. Only resources that have a graph node map — an instance, a
role, a bucket, a database. Everything else (security groups,
policies, profiles, VPC pieces) returns ``None``: it is real
infrastructure, it just is not a node in the graph.

This parser reads state only. It never writes state, never calls
Terraform, and never touches real infrastructure.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class TerraformResource:
    """One managed resource instance from a tfstate file."""

    address: str  # e.g. "aws_instance.web"
    type: str  # e.g. "aws_instance"
    name: str  # e.g. "web"
    attributes: dict = field(default_factory=dict)
    dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class TerraformState:
    """A parsed tfstate file."""

    terraform_version: str
    resources: tuple[TerraformResource, ...] = ()

    def by_address(self, address: str) -> TerraformResource | None:
        for resource in self.resources:
            if resource.address == address:
                return resource
        return None

    def by_type(self, type_: str) -> list[TerraformResource]:
        return [r for r in self.resources if r.type == type_]


class StateParseError(ValueError):
    """The tfstate file is not usable state."""


def parse_state(data: dict) -> TerraformState:
    """Parse already-loaded tfstate JSON.

    Raises :class:`StateParseError` on anything that is not a
    recognisable state file — a plan file, a config file, or
    garbage. ``resources`` entries without instances are skipped:
    a resource with no instances is not provisioned anywhere.
    """
    if not isinstance(data, dict):
        raise StateParseError("tfstate must be a JSON object")
    version = data.get("version")
    if version not in (3, 4):
        raise StateParseError(
            f"unsupported tfstate version {version!r} (expected 3 or 4)"
        )
    raw_resources = data.get("resources")
    if not isinstance(raw_resources, list):
        raise StateParseError("tfstate has no 'resources' list")

    resources: list[TerraformResource] = []
    for raw in raw_resources:
        if not isinstance(raw, dict):
            raise StateParseError("tfstate resource entry is not an object")
        if raw.get("mode", "managed") != "managed":
            continue  # data sources are reads, not resources
        rtype = raw.get("type")
        name = raw.get("name")
        if not rtype or not name:
            raise StateParseError("tfstate resource without type/name")
        instances = raw.get("instances")
        if not isinstance(instances, list):
            raise StateParseError(
                f"resource {rtype}.{name} has no 'instances' list"
            )
        for i, instance in enumerate(instances):
            if not isinstance(instance, dict):
                raise StateParseError(
                    f"resource {rtype}.{name} instance is not an object"
                )
            attrs = instance.get("attributes")
            if not isinstance(attrs, dict):
                raise StateParseError(
                    f"resource {rtype}.{name} instance has no attributes"
                )
            index = instance.get("index_key")
            address = f"{rtype}.{name}"
            if index is not None:
                address += f'[{json.dumps(index)}]'
            elif len(instances) > 1:
                address += f"[{i}]"
            resources.append(
                TerraformResource(
                    address=address,
                    type=rtype,
                    name=name,
                    attributes=attrs,
                    dependencies=tuple(
                        d for d in instance.get("dependencies", []) or []
                        if isinstance(d, str)
                    ),
                )
            )

    return TerraformState(
        terraform_version=str(data.get("terraform_version", "")),
        resources=tuple(resources),
    )


def load_state(path: str | Path) -> TerraformState:
    """Read and parse a tfstate file from disk."""
    text = Path(path).read_text()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise StateParseError(f"{path}: not valid JSON: {exc}") from exc
    return parse_state(data)


# -- address -> graph node id ---------------------------------------------
#
# The mapping keys off the resource type and the attribute the graph
# uses as the node id. It is deliberately narrow: only node kinds
# the graph has (Workload, Identity, DataStore) map. A security
# group, a policy, or an instance profile is not a graph node, so
# it maps to None — the fix templates resolve those through the
# config reader instead.

_TYPE_NODE_ATTR = {
    "aws_instance": ("ec2", "id"),
    "aws_iam_role": ("iam-role", "name"),
    "aws_iam_user": ("iam-user", "name"),
    "aws_s3_bucket": ("s3", "bucket"),
    "aws_db_instance": ("rds", "identifier"),
}


def address_to_node_id(resource: TerraformResource) -> str | None:
    """The graph node id for a state resource, or None.

    Returns None for resources that are not graph nodes (security
    groups, policies, profiles, network pieces) and for resources
    missing the attribute the mapping needs.
    """
    mapping = _TYPE_NODE_ATTR.get(resource.type)
    if mapping is None:
        return None
    prefix, attr = mapping
    value = resource.attributes.get(attr)
    if not isinstance(value, str) or not value:
        return None
    return f"{prefix}:{value}"


def node_id_to_address(state: TerraformState, node_id: str) -> str | None:
    """The reverse lookup: graph node id -> state address, or None."""
    for resource in state.resources:
        if address_to_node_id(resource) == node_id:
            return resource.address
    return None
