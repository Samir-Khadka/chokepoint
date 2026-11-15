"""Graph model for Chokepoint Phase 1.

Follows the plan's Section 6 v1 schema:

Nodes: Internet, Workload (EC2/ECS/Lambda), Identity (Role/User),
DataStore (S3/RDS/DynamoDB), Secret, NetworkEntry (ALB/SG rule).

Edges: CAN_REACH, HAS_ROLE, CAN_ASSUME, CAN_READ, CAN_WRITE,
CAN_ADMIN, CONTAINS_CRED.

Every edge carries ``evidence`` (which policy statement, rule or
attachment created it) and a ``confidence`` of ``proven`` or
``unknown``. An edge the evaluator could not decide is labelled
unknown, never silently assumed allowed or denied.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class NodeKind(str, Enum):
    INTERNET = "internet"
    WORKLOAD = "workload"
    IDENTITY = "identity"
    DATASTORE = "datastore"
    SECRET = "secret"
    NETWORK_ENTRY = "network_entry"


class EdgeKind(str, Enum):
    CAN_REACH = "can_reach"
    HAS_ROLE = "has_role"
    CAN_ASSUME = "can_assume"
    CAN_READ = "can_read"
    CAN_WRITE = "can_write"
    CAN_ADMIN = "can_admin"
    CONTAINS_CRED = "contains_cred"


class Confidence(str, Enum):
    PROVEN = "proven"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Node:
    """One thing in the account graph.

    ``id`` is a stable, human-readable identifier, e.g.
    ``ec2:i-0abc123``, ``iam-role:web-role``, ``s3:backups``,
    ``rds:prod-db``, ``internet``.
    """

    id: str
    kind: NodeKind
    label: str
    attributes: dict = field(default_factory=dict)
    crown_jewel: bool = False


@dataclass(frozen=True)
class Edge:
    """One typed, evidenced fact about what a node can do to another."""

    source: str
    target: str
    kind: EdgeKind
    evidence: str
    evidence_ref: str = ""
    confidence: Confidence = Confidence.PROVEN
    collected_at: str = ""


# The single Internet node every P1/P2 path starts from.
INTERNET_NODE = Node(
    id="internet",
    kind=NodeKind.INTERNET,
    label="Internet",
    attributes={"description": "Unauthenticated public internet"},
)
