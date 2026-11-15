"""Collector record types and the Inventory they assemble.

Collectors return plain dataclasses — never raw boto3 dicts — so the
graph builder, the demo loader and the tests all speak the same
shape. ``Inventory`` is the single input to the graph builder.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SGRule:
    cidr: str  # e.g. "0.0.0.0/0" or "::/0"
    protocol: str  # "tcp", "udp", "icmp", "-1" (all)
    from_port: int | None
    to_port: int | None


@dataclass(frozen=True)
class SecurityGroup:
    id: str
    vpc_id: str
    ingress: tuple[SGRule, ...] = ()
    egress: tuple[SGRule, ...] = ()


@dataclass(frozen=True)
class Route:
    destination: str  # e.g. "0.0.0.0/0"
    target: str  # e.g. "igw-0123456789abcdef0", "local", "nat-..."


@dataclass(frozen=True)
class RouteTable:
    id: str
    vpc_id: str
    subnet_ids: tuple[str, ...] = ()
    routes: tuple[Route, ...] = ()


@dataclass(frozen=True)
class EC2Instance:
    id: str
    arn: str
    state: str
    public_ip: str | None
    private_ip: str | None
    subnet_id: str
    vpc_id: str
    security_group_ids: tuple[str, ...] = ()
    instance_profile_arn: str | None = None
    # Resolved by scan_account via iam:GetInstanceProfile: the ARN
    # of the role the instance profile carries (None if no profile).
    role_arn: str | None = None
    tags: dict = field(default_factory=dict)


@dataclass(frozen=True)
class S3Bucket:
    name: str
    arn: str
    policy: dict | None = None  # bucket policy document, if any
    public_access_block: dict = field(default_factory=dict)
    acl_public: bool = False  # a public ACL grant (READ) exists
    tags: dict = field(default_factory=dict)
    # Phase 1 cannot read object contents (that needs a secrets
    # scanner). A bucket declares credentials explicitly via this
    # field, populated by the demo loader or a future integration:
    #   {"object_key": ..., "credential_for": "rds:prod-db"}
    credential: dict | None = None


@dataclass(frozen=True)
class IAMRole:
    name: str
    arn: str
    trust_policy: dict = field(default_factory=dict)
    # Resolved policy documents: list of (policy_name, document).
    # Attached managed policies are resolved to their documents by
    # the collector; inline policies are included as-is.
    policies: tuple[tuple[str, dict], ...] = ()
    permission_boundary: dict | None = None
    tags: dict = field(default_factory=dict)


@dataclass(frozen=True)
class DBInstance:
    identifier: str
    arn: str
    engine: str
    publicly_accessible: bool
    vpc_security_group_ids: tuple[str, ...] = ()
    tags: dict = field(default_factory=dict)


@dataclass
class Inventory:
    """Everything one scan collected, for one account/region."""

    account_id: str = ""
    region: str = ""
    collected_at: str = ""
    instances: list[EC2Instance] = field(default_factory=list)
    security_groups: list[SecurityGroup] = field(default_factory=list)
    route_tables: list[RouteTable] = field(default_factory=list)
    buckets: list[S3Bucket] = field(default_factory=list)
    roles: list[IAMRole] = field(default_factory=list)
    db_instances: list[DBInstance] = field(default_factory=list)


def tags_to_dict(tag_list) -> dict:
    """Convert AWS ``[{Key, Value}]`` tag lists to a dict."""
    out = {}
    for t in tag_list or []:
        key = t.get("Key")
        if key is not None:
            out[key] = t.get("Value", "")
    return out
