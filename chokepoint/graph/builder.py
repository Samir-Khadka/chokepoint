"""Build the Phase 1 graph from a collected Inventory.

Rules, per the plan's Section 6 schema. An edge is added only when
its evidence is in hand; anything the evaluator cannot decide is
added with ``confidence=unknown`` and never used by the path
finder (which follows proven edges only).

* Internet --CAN_REACH--> Workload: public IP + a security group
  ingress rule open to 0.0.0.0/0 (or ::/0) + a route to an internet
  gateway in the subnet's route table. All three are required.
* Internet --CAN_REACH--> DataStore (S3): bucket policy allows
  Principal "*" to read, or a public ACL grant. A Condition on the
  policy statement makes the edge ``unknown``.
* Internet --CAN_REACH--> DataStore (RDS): publicly accessible +
  an open security group rule.
* Workload --HAS_ROLE--> Identity: instance profile carries the role.
* Identity --CAN_ASSUME--> Identity: target's trust policy allows
  the source role (``sts:AssumeRole``).
* Identity --CAN_READ/CAN_WRITE/CAN_ADMIN--> DataStore: evaluated
  IAM permission (s3:GetObject / PutObject / s3:* on buckets;
  rds-db:connect / rds:* on databases), permission boundary applied.
* DataStore --CONTAINS_CRED--> Secret, Secret --CAN_ADMIN-->
  DataStore: a bucket that declares credentials for a database
  (Phase 1 records this from inventory metadata — see
  ``collectors/records.py`` — it does not read object contents).

NetworkEntry nodes (ALB / SG rule as its own node) are reserved for
a later phase; Phase 1 cites the security-group rule as the
evidence on the CAN_REACH edge directly, matching the plan's
Figure 1 chain (Internet -> EC2 -> role -> S3 -> DB).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..collectors.records import Inventory
from .iam_eval import policy_allows, role_can, trust_allows_assume
from .model import (
    INTERNET_NODE,
    Confidence,
    Edge,
    EdgeKind,
    Node,
    NodeKind,
)
from .store import GraphStore

PUBLIC_CIDRS = ("0.0.0.0/0", "::/0")


@dataclass
class BuildReport:
    nodes_added: int = 0
    edges_added: int = 0
    unknown_edges: list[Edge] = field(default_factory=list)


def _sg_allows_public(sg, rules) -> str | None:
    """Return the rule description if an SG ingress rule is public."""
    for rule in rules:
        if rule.cidr in PUBLIC_CIDRS:
            port = (
                "all ports"
                if rule.from_port is None
                else f"port {rule.from_port}"
                if rule.from_port == rule.to_port
                else f"ports {rule.from_port}-{rule.to_port}"
            )
            return f"{sg.id} allows {rule.cidr} {rule.protocol} {port}"
    return None


def _subnet_has_igw_route(route_tables, subnet_id: str) -> str | None:
    """Return the IGW route description for a subnet, if any."""
    main_table = None
    for table in route_tables:
        if subnet_id in table.subnet_ids:
            for route in table.routes:
                if route.destination in PUBLIC_CIDRS and route.target.startswith("igw-"):
                    return f"{table.id} routes {route.destination} -> {route.target}"
        if not table.subnet_ids:
            main_table = table
    # Fall back to the VPC main route table (no explicit association).
    if main_table is not None:
        for route in main_table.routes:
            if route.destination in PUBLIC_CIDRS and route.target.startswith("igw-"):
                return f"{main_table.id} (main) routes {route.destination} -> {route.target}"
    return None


def _bucket_policy_public(policy: dict | None) -> tuple[bool, Confidence, str]:
    """Is this bucket policy public? Returns (public, confidence, evidence)."""
    if not policy:
        return False, Confidence.PROVEN, ""
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for i, stmt in enumerate(statements):
        if str(stmt.get("Effect", "")).lower() != "allow":
            continue
        principal = stmt.get("Principal", {})
        aws_principal = principal.get("AWS") if isinstance(principal, dict) else None
        is_public = principal == "*" or aws_principal == "*" or (
            isinstance(aws_principal, list) and "*" in aws_principal
        )
        if not is_public:
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        reads = any(
            a in ("s3:GetObject", "s3:*", "s3:Get*", "*")
            or a.startswith("s3:Get")
            for a in actions
        )
        if not reads:
            continue
        if stmt.get("Condition"):
            return True, Confidence.UNKNOWN, (
                f"bucket policy statement {i} allows public read "
                "but has a Condition this evaluator does not support"
            )
        return True, Confidence.PROVEN, f"bucket policy statement {i} allows Principal * s3:GetObject"
    return False, Confidence.PROVEN, ""


def build_graph(inventory: Inventory, store: GraphStore) -> BuildReport:
    """Populate ``store`` from ``inventory``. Returns a build report."""
    report = BuildReport()
    collected_at = inventory.collected_at

    def add_node(node: Node) -> None:
        store.add_node(node)
        report.nodes_added += 1

    def add_edge(edge: Edge) -> None:
        store.add_edge(edge)
        report.edges_added += 1
        if edge.confidence is Confidence.UNKNOWN:
            report.unknown_edges.append(edge)

    add_node(INTERNET_NODE)

    sg_by_id = {sg.id: sg for sg in inventory.security_groups}
    role_by_arn = {r.arn: r for r in inventory.roles}
    role_by_name = {r.name: r for r in inventory.roles}

    # -- DataStores: S3 buckets and RDS instances ---------------------------
    for bucket in inventory.buckets:
        add_node(
            Node(
                id=f"s3:{bucket.name}",
                kind=NodeKind.DATASTORE,
                label=f"s3://{bucket.name}",
                attributes={"arn": bucket.arn, "tags": bucket.tags},
            )
        )
    for db in inventory.db_instances:
        add_node(
            Node(
                id=f"rds:{db.identifier}",
                kind=NodeKind.DATASTORE,
                label=f"rds:{db.identifier}",
                attributes={
                    "arn": db.arn,
                    "engine": db.engine,
                    "publicly_accessible": db.publicly_accessible,
                    "tags": db.tags,
                },
            )
        )

    # -- Identities: IAM roles ------------------------------------------------
    for role in inventory.roles:
        add_node(
            Node(
                id=f"iam-role:{role.name}",
                kind=NodeKind.IDENTITY,
                label=f"role/{role.name}",
                attributes={"arn": role.arn, "tags": role.tags},
            )
        )

    # -- Workloads: EC2 instances --------------------------------------------
    for inst in inventory.instances:
        if inst.state and inst.state.lower() not in ("running", "pending"):
            continue
        node_id = f"ec2:{inst.id}"
        add_node(
            Node(
                id=node_id,
                kind=NodeKind.WORKLOAD,
                label=f"ec2:{inst.id}",
                attributes={
                    "arn": inst.arn,
                    "public_ip": inst.public_ip or "",
                    "tags": inst.tags,
                },
            )
        )
        # HAS_ROLE edge.
        if inst.role_arn and inst.role_arn in role_by_arn:
            role = role_by_arn[inst.role_arn]
            add_edge(
                Edge(
                    source=node_id,
                    target=f"iam-role:{role.name}",
                    kind=EdgeKind.HAS_ROLE,
                    evidence=f"instance profile {inst.instance_profile_arn} carries role {role.name}",
                    evidence_ref=inst.instance_profile_arn or "",
                    collected_at=collected_at,
                )
            )
        # CAN_REACH from the Internet: public IP + open SG + IGW route.
        if inst.public_ip:
            open_rule = None
            for sg_id in inst.security_group_ids:
                sg = sg_by_id.get(sg_id)
                if sg is None:
                    continue
                open_rule = _sg_allows_public(sg, sg.ingress)
                if open_rule:
                    break
            igw_route = _subnet_has_igw_route(inventory.route_tables, inst.subnet_id)
            if open_rule and igw_route:
                add_edge(
                    Edge(
                        source="internet",
                        target=node_id,
                        kind=EdgeKind.CAN_REACH,
                        evidence=(
                            f"public IP {inst.public_ip}; {open_rule}; {igw_route}"
                        ),
                        evidence_ref=",".join(inst.security_group_ids),
                        collected_at=collected_at,
                    )
                )

    # -- Public RDS: publicly accessible + open security group ----------------
    for db in inventory.db_instances:
        if not db.publicly_accessible:
            continue
        open_rule = None
        for sg_id in db.vpc_security_group_ids:
            sg = sg_by_id.get(sg_id)
            if sg is None:
                continue
            open_rule = _sg_allows_public(sg, sg.ingress)
            if open_rule:
                break
        if open_rule:
            add_edge(
                Edge(
                    source="internet",
                    target=f"rds:{db.identifier}",
                    kind=EdgeKind.CAN_REACH,
                    evidence=f"publicly accessible; {open_rule}",
                    evidence_ref=",".join(db.vpc_security_group_ids),
                    collected_at=collected_at,
                )
            )

    # -- Public S3 (pattern P2) ------------------------------------------------
    for bucket in inventory.buckets:
        public, confidence, evidence = _bucket_policy_public(bucket.policy)
        if not public and bucket.acl_public:
            public, confidence = True, Confidence.PROVEN
            evidence = "bucket ACL grants AllUsers/AuthenticatedUsers READ"
        if public:
            # The public read IS the entry hop: CAN_REACH from the
            # Internet to the bucket. (There is no IAM identity on
            # the Internet side, so no CAN_READ edge is drawn here.)
            add_edge(
                Edge(
                    source="internet",
                    target=f"s3:{bucket.name}",
                    kind=EdgeKind.CAN_REACH,
                    evidence=evidence,
                    evidence_ref=bucket.arn,
                    confidence=confidence,
                    collected_at=collected_at,
                )
            )

    # -- Role assumption chains -------------------------------------------------
    for target in inventory.roles:
        target_node = f"iam-role:{target.name}"
        for source in inventory.roles:
            if source.arn == target.arn:
                continue
            result = trust_allows_assume(target.trust_policy, source.arn)
            if result.allowed:
                add_edge(
                    Edge(
                        source=f"iam-role:{source.name}",
                        target=target_node,
                        kind=EdgeKind.CAN_ASSUME,
                        evidence=f"trust policy of {target.name} allows {source.arn} sts:AssumeRole",
                        evidence_ref=target.arn,
                        collected_at=collected_at,
                    )
                )
            elif result.confidence is Confidence.UNKNOWN:
                add_edge(
                    Edge(
                        source=f"iam-role:{source.name}",
                        target=target_node,
                        kind=EdgeKind.CAN_ASSUME,
                        evidence=f"trust policy of {target.name}: {result.reason}",
                        evidence_ref=target.arn,
                        confidence=Confidence.UNKNOWN,
                        collected_at=collected_at,
                    )
                )

    # -- Role -> datastore permissions ------------------------------------------
    for role in inventory.roles:
        role_node = f"iam-role:{role.name}"
        for bucket in inventory.buckets:
            bucket_node = f"s3:{bucket.name}"
            bucket_arn = bucket.arn
            for action, kind in (
                ("s3:*", EdgeKind.CAN_ADMIN),
                ("s3:GetObject", EdgeKind.CAN_READ),
                ("s3:PutObject", EdgeKind.CAN_WRITE),
            ):
                result, evidence = role_can(role, action, f"{bucket_arn}/*")
                if result.allowed:
                    add_edge(
                        Edge(
                            source=role_node,
                            target=bucket_node,
                            kind=kind,
                            evidence=f"{evidence} on {bucket_arn}/*",
                            evidence_ref=bucket_arn,
                            collected_at=collected_at,
                        )
                    )
                elif result.confidence is Confidence.UNKNOWN:
                    add_edge(
                        Edge(
                            source=role_node,
                            target=bucket_node,
                            kind=kind,
                            evidence=f"unevaluated: {evidence}",
                            evidence_ref=bucket_arn,
                            confidence=Confidence.UNKNOWN,
                            collected_at=collected_at,
                        )
                    )
        for db in inventory.db_instances:
            db_node = f"rds:{db.identifier}"
            for action, kind in (
                ("rds:*", EdgeKind.CAN_ADMIN),
                ("rds-db:connect", EdgeKind.CAN_READ),
            ):
                result, evidence = role_can(role, action, db.arn)
                if result.allowed:
                    add_edge(
                        Edge(
                            source=role_node,
                            target=db_node,
                            kind=kind,
                            evidence=f"{evidence} on {db.arn}",
                            evidence_ref=db.arn,
                            collected_at=collected_at,
                        )
                    )
                elif result.confidence is Confidence.UNKNOWN:
                    add_edge(
                        Edge(
                            source=role_node,
                            target=db_node,
                            kind=kind,
                            evidence=f"unevaluated: {evidence}",
                            evidence_ref=db.arn,
                            confidence=Confidence.UNKNOWN,
                            collected_at=collected_at,
                        )
                    )

    # -- Credentials in buckets ---------------------------------------------------
    for bucket in inventory.buckets:
        cred = bucket.credential
        if not cred:
            continue
        target_id = cred.get("credential_for", "")
        target_node = store.get_node(target_id)
        if target_node is None:
            continue
        secret_id = f"secret:{bucket.name}:{cred.get('object_key', 'credential')}"
        add_node(
            Node(
                id=secret_id,
                kind=NodeKind.SECRET,
                label=f"credential in s3://{bucket.name}",
                attributes={
                    "object_key": cred.get("object_key", ""),
                    "credential_for": target_id,
                },
            )
        )
        add_edge(
            Edge(
                source=f"s3:{bucket.name}",
                target=secret_id,
                kind=EdgeKind.CONTAINS_CRED,
                evidence=f"object s3://{bucket.name}/{cred.get('object_key', '')} holds credentials for {target_id}",
                evidence_ref=bucket.arn,
                collected_at=collected_at,
            )
        )
        add_edge(
            Edge(
                source=secret_id,
                target=target_id,
                kind=EdgeKind.CAN_ADMIN,
                evidence=f"credentials stored in s3://{bucket.name}/{cred.get('object_key', '')} grant access to {target_id}",
                evidence_ref=bucket.arn,
                collected_at=collected_at,
            )
        )

    return report
