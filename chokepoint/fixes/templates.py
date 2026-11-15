"""Template-based fix generation (plan Section 7).

Templates first, no LLM anywhere in this phase. Each template
takes a ranked candidate fix and the demo Terraform fixture and
returns the modified ``.tf`` text plus the graph effect the change
is expected to have, declared as edge/node exclusions — the same
exclusion mechanism the ranking module scores with. The generator
(``generate.py``) then *measures* that effect by re-running path
finding and refuses the fix if it removes no paths or opens a new
one.

A template's graph effect is declared from the change itself, not
copied from the ranking: narrowing a policy removes only the edges
that policy statement granted, even when the ranked candidate
assumed the whole role was removed. The PR body reports the
measured numbers and says so when they differ from the ranked
estimate.

Scope: the templates assume the fixture's known structure
(resource naming, ``jsonencode`` policies, one policy per
statement list). General-purpose HCL editing — variables,
modules, ``for_each``, heredoc policies, computed values — is
future work, and every template says so in its docstring.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..graph.model import EdgeKind, NodeKind
from ..graph.store import GraphStore
from ..ranking.candidates import CandidateFix
from ..terraform import (
    TerraformState,
    find_nested_blocks,
    find_resource_block,
    remove_span,
    replace_span,
)
from . import _hcl as hcl

# Canonical S3 action that reads objects; the worked example in the
# plan narrows an over-broad GetObject to the one bucket the
# workload actually uses.
S3_GET_OBJECT = "s3:GetObject"


class UnsupportedFix(ValueError):
    """No template can express this candidate fix."""


class NoOpFix(ValueError):
    """A template matched, but the change would alter nothing."""


@dataclass(frozen=True)
class TemplateApplication:
    """What one template did to the fixture."""

    template_name: str
    new_tf_text: str
    changed_addresses: tuple[str, ...]
    exclude_edges: frozenset[tuple[str, str, str]]
    exclude_nodes: frozenset[str]
    summary: str


# ----------------------------------------------------------------------
# helpers: state lookups
# ----------------------------------------------------------------------

def _state_resource_by_attr(
    state: TerraformState, rtype: str, attr: str, value: str
):
    for resource in state.by_type(rtype):
        if resource.attributes.get(attr) == value:
            return resource
    return None


def _instance_address(state: TerraformState, node_id: str) -> str | None:
    """TF address of the EC2 instance behind ``ec2:<id>``."""
    instance_id = node_id.split(":", 1)[1]
    resource = _state_resource_by_attr(state, "aws_instance", "id", instance_id)
    return resource.address if resource else None


def _role_address(state: TerraformState, node_id: str) -> str | None:
    """TF address of the IAM role behind ``iam-role:<name>``."""
    name = node_id.split(":", 1)[1]
    resource = _state_resource_by_attr(state, "aws_iam_role", "name", name)
    return resource.address if resource else None


def _bucket_address(state: TerraformState, node_id: str) -> str | None:
    """TF address of the S3 bucket behind ``s3:<name>``."""
    name = node_id.split(":", 1)[1]
    resource = _state_resource_by_attr(state, "aws_s3_bucket", "bucket", name)
    return resource.address if resource else None


def _sg_addresses(state: TerraformState, sg_ids: list[str]) -> list[str]:
    out = []
    for sg_id in sg_ids:
        resource = _state_resource_by_attr(
            state, "aws_security_group", "id", sg_id
        )
        if resource is not None:
            out.append(resource.address)
    return out


def _bucket_policy_address(state: TerraformState, bucket: str) -> str | None:
    resource = _state_resource_by_attr(
        state, "aws_s3_bucket_policy", "bucket", bucket
    )
    return resource.address if resource else None


def _public_access_block_address(
    state: TerraformState, bucket: str
) -> str | None:
    resource = _state_resource_by_attr(
        state, "aws_s3_bucket_public_access_block", "bucket", bucket
    )
    return resource.address if resource else None


def _policy_resource_address(
    state: TerraformState, policy_label: str
) -> str | None:
    """TF address of the policy behind ``inline:<name>`` / ``attached:<name>``.

    Inline policies live in ``aws_iam_role_policy`` resources,
    attached ones in ``aws_iam_policy`` resources; both carry the
    policy name in their ``name`` attribute.
    """
    try:
        kind, name = policy_label.split(":", 1)
    except ValueError:
        return None
    rtype = (
        "aws_iam_role_policy" if kind == "inline" else "aws_iam_policy"
    )
    resource = _state_resource_by_attr(state, rtype, "name", name)
    return resource.address if resource else None


# ----------------------------------------------------------------------
# helpers: policy reading (hcl2, read-only) and statement surgery
# ----------------------------------------------------------------------

_STATEMENT_REF_RE = re.compile(
    r"^(inline|attached):([A-Za-z0-9_.-]+) Allow statement (\d+)"
)


def _statement_ref(evidence: str) -> tuple[str, int] | None:
    """(policy label, statement index) from an edge's evidence.

    Evidence looks like ``inline:web-policy Allow statement 0
    covers action and resource on arn:aws:s3:::backups/*``.
    """
    match = _STATEMENT_REF_RE.match(evidence)
    if not match:
        return None
    kind, name, index = match.groups()
    return f"{kind}:{name}", int(index)


def _statement_spans(policy_text: str) -> list[tuple[int, int]]:
    """Spans of the objects in the policy's ``Statement = [...]`` list."""
    match = re.search(r"Statement\s*=\s*\[", policy_text)
    if not match:
        return []
    array_start = match.end() - 1  # the `[`
    spans: list[tuple[int, int]] = []
    i = array_start + 1
    n = len(policy_text)
    while i < n:
        ch = policy_text[i]
        if ch in " \t\r\n,":
            i += 1
            continue
        if ch == "]":
            break
        if ch == "{":
            end = hcl.matching_brace(policy_text, i)
            spans.append((i, end))
            i = end
            continue
        i += 1
    return spans


def _statement_field(stmt_text: str, field: str) -> str | None:
    match = re.search(
        rf"{re.escape(field)}\s*=\s*\"([^\"]*)\"", stmt_text
    )
    return match.group(1) if match else None


def _narrow_statement_resource(
    policy_text: str, span: tuple[int, int], new_resources: list[str]
) -> str:
    """Replace the Resource of one statement span with ``new_resources``."""
    start, end = span
    stmt = policy_text[start:end]
    if len(new_resources) == 1:
        replacement = f'Resource = "{new_resources[0]}"'
    else:
        items = ", ".join(f'"{r}"' for r in new_resources)
        replacement = f"Resource = [{items}]"
    new_stmt, count = re.subn(
        r"Resource\s*=\s*(\"[^\"]*\"|\[[^\]]*\])",
        replacement,
        stmt,
        count=1,
    )
    if count == 0:
        raise NoOpFix("statement has no Resource to narrow")
    return policy_text[:start] + new_stmt + policy_text[end:]


def _remove_statement(policy_text: str, span: tuple[int, int]) -> str:
    """Delete one statement object, tidying the comma it leaves."""
    start, end = span
    out = policy_text[:start] + policy_text[end:]
    # A trailing comma before `]` (last element removed) or a
    # leading comma after `[` (first element removed).
    out = re.sub(r",\s*(\])", r"\1", out)
    out = re.sub(r"(\[)\s*,", r"\1", out)
    return out


def _narrow_buckets_from_policies(
    tf_text: str, state: TerraformState, role_node_id: str
) -> set[str]:
    """Buckets named by narrow Resource ARNs in the role's policies.

    Reads every inline/attached policy of the role (via hcl2,
    read-only) and collects bucket names from Resource values of
    the form ``arn:aws:s3:::<bucket>/*``. ``*`` resources are
    skipped — they are the over-broad statements being fixed.
    """
    role_name = role_node_id.split(":", 1)[1]
    buckets: set[str] = set()
    addresses: list[str] = []
    for resource in state.by_type("aws_iam_role_policy"):
        if resource.attributes.get("role") == role_name:
            addresses.append(resource.address)
    attached_arns = {
        resource.attributes.get("policy_arn")
        for resource in state.by_type("aws_iam_role_policy_attachment")
        if resource.attributes.get("role") == role_name
    }
    for resource in state.by_type("aws_iam_policy"):
        if resource.attributes.get("arn") in attached_arns:
            addresses.append(resource.address)
    for address in addresses:
        block = find_resource_block(tf_text, address)
        if block is None:
            continue
        policy = hcl.policy_document(block.text)
        if policy is None:
            continue
        for stmt in hcl.statements(policy):
            resource_value = stmt.get("Resource")
            values = (
                resource_value
                if isinstance(resource_value, list)
                else [resource_value]
            )
            for value in values:
                if not isinstance(value, str):
                    continue
                match = re.fullmatch(r"arn:aws:s3:::([A-Za-z0-9_.-]+)/\*", value)
                if match:
                    buckets.add(match.group(1))
    return buckets


def _edges_evidenced_by(
    store: GraphStore, prefix: str
) -> list[tuple[str, str, str]]:
    """Edge keys whose evidence starts with ``prefix``."""
    return [
        (edge.source, edge.target, edge.kind.value)
        for edge in store.edges()
        if edge.evidence.startswith(prefix)
    ]


def _edge_by_key(store: GraphStore, key: tuple[str, str, str]):
    for edge in store.edges():
        if (edge.source, edge.target, edge.kind.value) == key:
            return edge
    return None


# ----------------------------------------------------------------------
# templates
# ----------------------------------------------------------------------

def _detach_instance_profile(candidate, tf_text, state, store):
    """Remove ``iam_instance_profile`` from the instance block.

    The workload keeps running; it simply no longer carries the
    role, so every path that rode on the role's permissions dies.
    """
    assert candidate.edge_key is not None
    src, tgt, _ = candidate.edge_key
    address = _instance_address(state, src)
    if address is None:
        raise UnsupportedFix(f"no Terraform instance for {src}")
    block = find_resource_block(tf_text, address)
    if block is None:
        raise UnsupportedFix(f"{address} not in the fixture")
    new_block, count = re.subn(
        r"^[ \t]*iam_instance_profile\s*=.*\n",
        "",
        block.text,
        count=1,
        flags=re.MULTILINE,
    )
    if count == 0:
        raise NoOpFix(f"{address} has no iam_instance_profile to remove")
    new_text = tf_text[:block.start] + new_block + tf_text[block.end:]
    return TemplateApplication(
        template_name="detach_instance_profile",
        new_tf_text=new_text,
        changed_addresses=(address,),
        exclude_edges=frozenset({candidate.edge_key}),
        exclude_nodes=frozenset(),
        summary=f"Removed iam_instance_profile from {address}",
    )


def _close_sg_ingress(candidate, tf_text, state, store):
    """Remove public (0.0.0.0/0, ::/0) ingress rules from the SG(s).

    The security-group address comes from the CAN_REACH edge's
    evidence_ref, which the builder sets to the instance's SG ids.
    """
    assert candidate.edge_key is not None
    edge = _edge_by_key(store, candidate.edge_key)
    if edge is None:
        raise UnsupportedFix("edge not in the graph")
    sg_ids = [s for s in edge.evidence_ref.split(",") if s] if edge.evidence_ref else []
    if not sg_ids:
        raise UnsupportedFix("CAN_REACH edge names no security group")
    addresses = _sg_addresses(state, sg_ids)
    if not addresses:
        raise UnsupportedFix("security groups not in the fixture state")
    new_text = tf_text
    changed: list[str] = []
    for address in addresses:
        block = find_resource_block(new_text, address)
        if block is None:
            continue
        # Collect public ingress spans first, then remove them in
        # reverse offset order so earlier spans stay valid.
        doomed = [
            nested
            for nested in find_nested_blocks(block, "ingress")
            if "0.0.0.0/0" in nested.text or "::/0" in nested.text
        ]
        for nested in sorted(doomed, key=lambda b: b.start, reverse=True):
            new_text = remove_span(new_text, nested.start, nested.end)
        if doomed:
            changed.append(address)
    if not changed:
        raise NoOpFix("no public ingress rule to remove")
    return TemplateApplication(
        template_name="close_sg_ingress",
        new_tf_text=new_text,
        changed_addresses=tuple(changed),
        exclude_edges=frozenset({candidate.edge_key}),
        exclude_nodes=frozenset(),
        summary=f"Removed public ingress from {', '.join(changed)}",
    )


def _make_workload_private(candidate, tf_text, state, store):
    """Close public ingress AND drop the instance's public IP.

    The node fix "make the workload private" is the graph removal
    of the CAN_REACH edge; in Terraform that is the ingress rule
    plus ``associate_public_ip_address = false``.
    """
    node_id = candidate.target_id
    address = _instance_address(state, node_id)
    if address is None:
        raise UnsupportedFix(f"no Terraform instance for {node_id}")
    # Close the ingress first (same edit as the edge template).
    edge_key = ("internet", node_id, EdgeKind.CAN_REACH.value)
    edge_candidate = CandidateFix(
        id=f"edge:internet->{node_id}:can_reach",
        kind="edge",
        target_id=node_id,
        edge_key=edge_key,
        title=candidate.title,
        explanation=candidate.explanation,
        evidence=candidate.evidence,
        what_could_break=candidate.what_could_break,
    )
    try:
        application = _close_sg_ingress(edge_candidate, tf_text, state, store)
    except NoOpFix:
        application = None
    new_text = application.new_tf_text if application else tf_text
    changed = list(application.changed_addresses) if application else []
    block = find_resource_block(new_text, address)
    if block is None:
        raise UnsupportedFix(f"{address} not in the fixture")
    new_block, count = re.subn(
        r"associate_public_ip_address\s*=\s*true",
        "associate_public_ip_address = false",
        block.text,
        count=1,
    )
    if count:
        new_text = new_text[:block.start] + new_block + new_text[block.end:]
        changed.append(address)
    if not changed:
        raise NoOpFix(f"{address} is already private")
    return TemplateApplication(
        template_name="make_workload_private",
        new_tf_text=new_text,
        changed_addresses=tuple(dict.fromkeys(changed)),
        exclude_edges=frozenset({edge_key}),
        exclude_nodes=frozenset(),
        summary=f"Closed public ingress and removed the public IP of {address}",
    )


def _make_bucket_private(candidate, tf_text, state, store):
    """Remove the bucket policy and block all public access.

    The public bucket policy is deleted outright; the
    public-access-block resource is created if absent, or set to
    block everything if present. The bucket itself is untouched.
    """
    if candidate.kind == "edge":
        assert candidate.edge_key is not None
        bucket_node = candidate.edge_key[1]
        edge_key = candidate.edge_key
    else:
        bucket_node = candidate.target_id
        edge_key = ("internet", bucket_node, EdgeKind.CAN_REACH.value)
    bucket = bucket_node.split(":", 1)[1]
    bucket_address = _bucket_address(state, bucket_node)
    if bucket_address is None:
        raise UnsupportedFix(f"no Terraform bucket for {bucket_node}")
    new_text = tf_text
    changed: list[str] = []
    policy_address = _bucket_policy_address(state, bucket)
    if policy_address is not None:
        block = find_resource_block(new_text, policy_address)
        if block is not None:
            new_text = remove_span(new_text, block.start, block.end)
            changed.append(policy_address)
    pab_address = _public_access_block_address(state, bucket)
    if pab_address is not None:
        block = find_resource_block(new_text, pab_address)
        if block is not None:
            new_block = block.text
            edited = False
            for attr in (
                "block_public_acls",
                "block_public_policy",
                "ignore_public_acls",
                "restrict_public_buckets",
            ):
                new_block, count = re.subn(
                    rf"{attr}\s*=\s*false",
                    f"{attr} = true",
                    new_block,
                    count=1,
                )
                if count:
                    edited = True
                elif attr not in new_block:
                    # Attribute missing: add it before the closing brace.
                    new_block = new_block.rstrip()
                    assert new_block.endswith("}")
                    new_block = (
                        new_block[:-1].rstrip()
                        + f"\n  {attr} = true\n}}\n"
                    )
                    edited = True
            if edited:
                new_text = new_text[:block.start] + new_block + new_text[block.end:]
                changed.append(pab_address)
    if pab_address is None:
        resource_name = bucket.replace("-", "_")
        new_block = (
            f'\nresource "aws_s3_bucket_public_access_block" "{resource_name}" {{\n'
            f"  bucket = {bucket_address}.id\n\n"
            "  block_public_acls       = true\n"
            "  block_public_policy     = true\n"
            "  ignore_public_acls      = true\n"
            "  restrict_public_buckets = true\n"
            "}\n"
        )
        new_text = new_text.rstrip() + "\n" + new_block
        changed.append(
            f"aws_s3_bucket_public_access_block.{resource_name}"
        )
    if not changed:
        raise NoOpFix(f"{bucket_node} is already private")
    return TemplateApplication(
        template_name="make_bucket_private",
        new_tf_text=new_text,
        changed_addresses=tuple(changed),
        exclude_edges=frozenset({edge_key}),
        exclude_nodes=frozenset(),
        summary=f"Removed the public bucket policy and blocked all public access to {bucket_address}",
    )


def _narrow_policy_statement(
    candidate, tf_text, state, store, role_node_id: str,
    statement_index: int | None,
) -> TemplateApplication:
    """Narrow an over-broad policy statement to the legitimate bucket(s).

    The legitimate scope comes from the role's own narrow grants
    in the fixture (the plan's worked example: the web tier writes
    the assets bucket, so GetObject narrows to assets). If the role
    has no narrow grant anywhere, the statement is removed
    instead — a permission with no observed legitimate use is not
    narrowed, it is deleted.
    """
    role_name = role_node_id.split(":", 1)[1]
    buckets = _narrow_buckets_from_policies(tf_text, state, role_node_id)
    # The statement to change: by index when the evidence names one,
    # otherwise every over-broad statement in the role's policies.
    targets: list[tuple[str, int | None]] = []
    if statement_index is not None:
        # Find which policy resource holds that statement: the
        # evidence names the policy label.
        evidence = candidate.evidence[0] if candidate.evidence else ""
        ref = _statement_ref(evidence)
        if ref is None:
            raise UnsupportedFix("evidence names no policy statement")
        policy_label, index = ref
        address = _policy_resource_address(state, policy_label)
        if address is None:
            raise UnsupportedFix(f"policy {policy_label} not in the fixture state")
        targets.append((address, index))
    else:
        for resource in state.by_type("aws_iam_role_policy"):
            if resource.attributes.get("role") == role_name:
                targets.append((resource.address, None))

    new_text = tf_text
    changed: list[str] = []
    excluded: set[tuple[str, str, str]] = set()
    narrowed_any = False
    for address, index in targets:
        block = find_resource_block(new_text, address)
        if block is None:
            continue
        policy = hcl.policy_document(block.text)
        if policy is None:
            raise UnsupportedFix(f"cannot read the policy in {address}")
        spans = _statement_spans(hcl.policy_argument_text(block.text))
        statements = hcl.statements(policy)
        if len(spans) != len(statements):
            raise UnsupportedFix(
                f"cannot align statements in {address}: "
                f"{len(spans)} spans vs {len(statements)} parsed"
            )
        if index is not None:
            if index >= len(spans):
                raise UnsupportedFix(
                    f"statement {index} not found in {address}"
                )
            work = [(index, spans[index])]
        else:
            work = [
                (i, span)
                for i, (span, stmt) in enumerate(zip(spans, statements))
                if _is_over_broad(stmt)
            ]
        arg_text, arg_start, arg_end = hcl.policy_argument(block.text)
        # Work from the last statement backwards so offsets stay valid.
        for stmt_index, (span_start, span_end) in sorted(work, reverse=True):
            stmt = statements[stmt_index]
            label = _policy_label_for(address, state)
            prefix = f"{label} Allow statement {stmt_index} "
            if buckets:
                new_resources = [
                    f"arn:aws:s3:::{bucket}/*" for bucket in sorted(buckets)
                ]
                arg_text = _narrow_statement_resource(
                    arg_text, (span_start, span_end), new_resources
                )
            else:
                arg_text = _remove_statement(arg_text, (span_start, span_end))
            excluded.update(_edges_evidenced_by(store, prefix))
            narrowed_any = True
        new_block_text = hcl.replace_policy_argument(
            block.text, arg_text
        )
        new_text = new_text[:block.start] + new_block_text + new_text[block.end:]
        changed.append(address)

    if not narrowed_any:
        raise NoOpFix("no over-broad statement to narrow")
    if not excluded:
        raise NoOpFix("narrowing changes no graph edge")
    return TemplateApplication(
        template_name="narrow_policy_statement",
        new_tf_text=new_text,
        changed_addresses=tuple(changed),
        exclude_edges=frozenset(excluded),
        exclude_nodes=frozenset(),
        summary=(
            "Narrowed the over-broad policy statement to "
            + (
                ", ".join(f"s3://{b}" for b in sorted(buckets))
                if buckets
                else "nothing (statement removed)"
            )
        ),
    )


def _is_over_broad(stmt: dict) -> bool:
    """A statement granting a wildcard resource (or wildcard action on *)."""
    resource = stmt.get("Resource")
    values = resource if isinstance(resource, list) else [resource]
    return "*" in values


def _policy_label_for(address: str, state: TerraformState) -> str:
    resource = state.by_address(address)
    if resource is None:
        return "unknown"
    kind = "inline" if resource.type == "aws_iam_role_policy" else "attached"
    name = resource.attributes.get("name", resource.name)
    return f"{kind}:{name}"


def _remove_trust_principal(candidate, tf_text, state, store):
    """Remove the source role from the target role's trust policy."""
    assert candidate.edge_key is not None
    src, tgt, _ = candidate.edge_key
    src_arn = f"arn:aws:iam::123456789012:role/{src.split(':', 1)[1]}"
    # The source ARN is taken from the graph edge's evidence, which
    # names the full ARN — prefer it over reconstructing one.
    edge = _edge_by_key(store, candidate.edge_key)
    if edge is not None:
        match = re.search(r"(arn:aws:iam::[0-9]+:role/[A-Za-z0-9_.-]+)", edge.evidence)
        if match:
            src_arn = match.group(1)
    address = _role_address(state, tgt)
    if address is None:
        raise UnsupportedFix(f"no Terraform role for {tgt}")
    block = find_resource_block(tf_text, address)
    if block is None:
        raise UnsupportedFix(f"{address} not in the fixture")
    policy = hcl.policy_document(block.text)
    if policy is None:
        raise UnsupportedFix(f"cannot read the trust policy in {address}")
    arg_text, _, _ = hcl.policy_argument(block.text)
    spans = _statement_spans(arg_text)
    statements = hcl.statements(policy)
    removed = False
    for (span_start, span_end), stmt in sorted(
        zip(spans, statements), reverse=True
    ):
        principal = stmt.get("Principal") or {}
        aws_value = principal.get("AWS") if isinstance(principal, dict) else None
        values = aws_value if isinstance(aws_value, list) else [aws_value]
        if src_arn not in values:
            continue
        if len(values) > 1:
            # Another principal shares the statement: drop only this ARN.
            stmt_text = arg_text[span_start:span_end]
            new_stmt = re.sub(
                rf'"?{re.escape(src_arn)}"?\s*,?\s*', "", stmt_text, count=1
            )
            arg_text = arg_text[:span_start] + new_stmt + arg_text[span_end:]
        else:
            arg_text = _remove_statement(arg_text, (span_start, span_end))
        removed = True
    if not removed:
        raise NoOpFix(f"trust policy of {address} does not allow {src_arn}")
    new_block_text = hcl.replace_policy_argument(block.text, arg_text)
    new_text = tf_text[:block.start] + new_block_text + tf_text[block.end:]
    return TemplateApplication(
        template_name="remove_trust_principal",
        new_tf_text=new_text,
        changed_addresses=(address,),
        exclude_edges=frozenset({candidate.edge_key}),
        exclude_nodes=frozenset(),
        summary=f"Removed {src_arn} from the trust policy of {address}",
    )


def _remove_credential_object(candidate, tf_text, state, store):
    """Delete the S3 object holding the stored credential."""
    if candidate.kind == "edge":
        assert candidate.edge_key is not None
        bucket_node = candidate.edge_key[0]
        secret_node = candidate.edge_key[1]
    else:
        secret_node = candidate.target_id
        bucket_node = None
    secret = store.get_node(secret_node)
    if secret is None:
        raise UnsupportedFix(f"secret node {secret_node} not in the graph")
    bucket = secret.attributes.get("bucket") or (
        bucket_node.split(":", 1)[1] if bucket_node else None
    )
    key = secret.attributes.get("object_key")
    if not bucket or not key:
        raise UnsupportedFix("secret node names no bucket object")
    address = None
    for resource in state.by_type("aws_s3_object"):
        if (
            resource.attributes.get("bucket") == bucket
            and resource.attributes.get("key") == key
        ):
            address = resource.address
            break
    if address is None:
        raise UnsupportedFix(f"no Terraform object for s3://{bucket}/{key}")
    block = find_resource_block(tf_text, address)
    if block is None:
        raise UnsupportedFix(f"{address} not in the fixture")
    new_text = remove_span(tf_text, block.start, block.end)
    return TemplateApplication(
        template_name="remove_credential_object",
        new_tf_text=new_text,
        changed_addresses=(address,),
        exclude_edges=frozenset(),
        exclude_nodes=frozenset({secret_node}),
        summary=f"Removed the stored credential object {address}",
    )


# ----------------------------------------------------------------------
# selection
# ----------------------------------------------------------------------

def select_template(candidate: CandidateFix, store: GraphStore) -> str:
    """Name of the template that implements this candidate.

    Raises :class:`UnsupportedFix` when no template can express it.
    Selection is by candidate kind and edge kind, in order from the
    most specific to the most general.
    """
    if candidate.kind == "edge":
        assert candidate.edge_key is not None
        src, tgt, kind = candidate.edge_key
        if kind == EdgeKind.HAS_ROLE.value:
            return "detach_instance_profile"
        if kind == EdgeKind.CAN_ASSUME.value:
            return "remove_trust_principal"
        if kind == EdgeKind.CONTAINS_CRED.value:
            return "remove_credential_object"
        if kind == EdgeKind.CAN_REACH.value:
            target = store.get_node(tgt)
            if target is not None and target.kind is NodeKind.DATASTORE:
                return "make_bucket_private"
            return "close_sg_ingress"
        if kind in (
            EdgeKind.CAN_READ.value,
            EdgeKind.CAN_WRITE.value,
            EdgeKind.CAN_ADMIN.value,
        ):
            if src.startswith("secret:"):
                return "remove_credential_object"
            return "narrow_policy_statement"
        raise UnsupportedFix(f"no template for edge kind {kind}")
    # Node candidates.
    node = store.get_node(candidate.target_id)
    if node is None:
        raise UnsupportedFix(f"node {candidate.target_id} not in the graph")
    if node.kind is NodeKind.IDENTITY:
        return "narrow_policy_statement"
    if node.kind is NodeKind.WORKLOAD:
        return "make_workload_private"
    if node.kind is NodeKind.DATASTORE:
        return "make_bucket_private"
    if node.kind is NodeKind.SECRET:
        return "remove_credential_object"
    raise UnsupportedFix(f"no template for node kind {node.kind.value}")


_TEMPLATES = {
    "detach_instance_profile": _detach_instance_profile,
    "close_sg_ingress": _close_sg_ingress,
    "make_workload_private": _make_workload_private,
    "make_bucket_private": _make_bucket_private,
    "narrow_policy_statement": None,  # needs the statement index; see below
    "remove_trust_principal": _remove_trust_principal,
    "remove_credential_object": _remove_credential_object,
}


def apply_template(
    template_name: str,
    candidate: CandidateFix,
    tf_text: str,
    state: TerraformState,
    store: GraphStore,
) -> TemplateApplication:
    """Run one template against the fixture text."""
    if template_name == "narrow_policy_statement":
        if candidate.kind == "edge":
            assert candidate.edge_key is not None
            src = candidate.edge_key[0]
            ref = _statement_ref(
                candidate.evidence[0] if candidate.evidence else ""
            )
            index = ref[1] if ref else None
            return _narrow_policy_statement(
                candidate, tf_text, state, store, src, index
            )
        return _narrow_policy_statement(
            candidate, tf_text, state, store, candidate.target_id, None
        )
    fn = _TEMPLATES.get(template_name)
    if fn is None:
        raise UnsupportedFix(f"unknown template {template_name}")
    return fn(candidate, tf_text, state, store)
