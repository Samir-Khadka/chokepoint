"""IAM collector: roles, trust policies, resolved policy documents.

Read-only calls only: list_roles, get_role, list_attached_role_policies,
get_policy, get_policy_version, list_role_policies, get_role_policy,
get_instance_profile.

Managed policies are resolved to their default-version documents
here, so the graph builder and the IAM evaluator work with plain
policy JSON regardless of where a statement came from. Each resolved
policy is kept under a name that records its origin, e.g.
``attached:AdministratorAccess`` or ``inline:web-policy``.

Note: IAM returns some policy documents as URL-encoded JSON strings
(GetRole's AssumeRolePolicyDocument, GetRolePolicy's PolicyDocument).
``_parse_policy_doc`` handles dict, plain JSON and URL-encoded JSON.
"""

from __future__ import annotations

import json
import urllib.parse

from botocore.exceptions import ClientError

from .records import IAMRole, tags_to_dict


def _parse_policy_doc(doc) -> dict | None:
    """Parse a policy document in any form IAM returns it."""
    if isinstance(doc, dict):
        return doc
    if not isinstance(doc, str):
        return None
    for candidate in (doc, urllib.parse.unquote(doc)):
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _resolve_attached_policy(iam_client, policy_arn: str) -> dict | None:
    try:
        meta = iam_client.get_policy(PolicyArn=policy_arn)
        version_id = meta["Policy"]["DefaultVersionId"]
        version = iam_client.get_policy_version(
            PolicyArn=policy_arn, VersionId=version_id
        )
        doc = version["PolicyVersion"]["Document"]
    except ClientError:
        return None
    return _parse_policy_doc(doc)


def _collect_role_policies(iam_client, role_name: str) -> list[tuple[str, dict]]:
    policies: list[tuple[str, dict]] = []
    # Attached managed policies, resolved to documents.
    attached = iam_client.list_attached_role_policies(RoleName=role_name)
    for p in attached.get("AttachedPolicies", []):
        doc = _resolve_attached_policy(iam_client, p["PolicyArn"])
        if doc is not None:
            policies.append((f"attached:{p['PolicyName']}", doc))
    # Inline policies.
    inline = iam_client.list_role_policies(RoleName=role_name)
    for name in inline.get("PolicyNames", []):
        try:
            resp = iam_client.get_role_policy(RoleName=role_name, PolicyName=name)
        except ClientError:
            continue
        doc = _parse_policy_doc(resp.get("PolicyDocument"))
        if doc is not None:
            policies.append((f"inline:{name}", doc))
    return policies


def resolve_instance_profile_roles(
    iam_client, profile_arns: list[str]
) -> dict[str, str]:
    """Map instance-profile ARN -> role ARN it carries.

    Uses iam:GetInstanceProfile (read-only). A profile carries at
    most one role in practice; the first is used.
    """
    out: dict[str, str] = {}
    for arn in profile_arns:
        name = arn.rsplit("/", 1)[-1]
        try:
            resp = iam_client.get_instance_profile(InstanceProfileName=name)
        except ClientError:
            continue
        roles = resp.get("InstanceProfile", {}).get("Roles", [])
        if roles:
            out[arn] = roles[0]["Arn"]
    return out


def collect_roles(iam_client) -> list[IAMRole]:
    roles = []
    paginator = iam_client.get_paginator("list_roles")
    for page in paginator.paginate():
        for r in page.get("Roles", []):
            name = r["RoleName"]
            detail = iam_client.get_role(RoleName=name).get("Role", r)
            trust = _parse_policy_doc(detail.get("AssumeRolePolicyDocument")) or {}
            boundary = None
            boundary_arn = detail.get("PermissionsBoundary", {}).get(
                "PermissionsBoundaryArn"
            )
            if boundary_arn:
                boundary = _resolve_attached_policy(iam_client, boundary_arn)
            roles.append(
                IAMRole(
                    name=name,
                    arn=r["Arn"],
                    trust_policy=trust if isinstance(trust, dict) else {},
                    policies=tuple(_collect_role_policies(iam_client, name)),
                    permission_boundary=boundary,
                    tags=tags_to_dict(detail.get("Tags")),
                )
            )
    return roles
