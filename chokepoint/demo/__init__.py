"""Demo mode: a small, realistic mock AWS account as JSON.

The demo account is hand-built so its paths are known exactly
(plan Section 10 accuracy bar: every planted path found, zero
invented paths). It contains:

* web-1 — public EC2 whose over-permissioned role (web-role,
  s3:GetObject on *) can read a backups bucket holding the
  production database credentials. The choke point.
* admin-role — assumable by web-role, can connect to prod-db.
* customer-data — a public bucket tagged as a crown jewel (P2).
* Decoys that must produce NO path: worker-1 (private), bastion-1
  (public IP but SG open only to one office IP), logs (public
  bucket, nothing sensitive), orphan-role (broad permissions, no
  way in).

``python -m chokepoint scan --demo`` runs end-to-end with zero
credentials. The same loader feeds the test suite.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..collectors.records import (
    DBInstance,
    EC2Instance,
    IAMRole,
    Inventory,
    Route,
    RouteTable,
    S3Bucket,
    SecurityGroup,
    SGRule,
)


def _sg(data: dict) -> SecurityGroup:
    def rules(raw):
        return tuple(
            SGRule(
                cidr=r["cidr"],
                protocol=r.get("protocol", "tcp"),
                from_port=r.get("from_port"),
                to_port=r.get("to_port"),
            )
            for r in raw
        )

    return SecurityGroup(
        id=data["id"],
        vpc_id=data.get("vpc_id", ""),
        ingress=rules(data.get("ingress", [])),
        egress=rules(data.get("egress", [])),
    )


def _route_table(data: dict) -> RouteTable:
    return RouteTable(
        id=data["id"],
        vpc_id=data.get("vpc_id", ""),
        subnet_ids=tuple(data.get("subnet_ids", [])),
        routes=tuple(
            Route(destination=r["destination"], target=r["target"])
            for r in data.get("routes", [])
        ),
    )


def load_demo_inventory() -> Inventory:
    """Load the bundled demo account into the same Inventory the
    real collectors produce."""
    raw = json.loads(Path(__file__).with_name("inventory.json").read_text())
    return Inventory(
        account_id=raw.get("account_id", "123456789012"),
        region=raw.get("region", "us-east-1"),
        collected_at=raw.get("collected_at", ""),
        instances=[
            EC2Instance(
                id=i["id"],
                arn=i.get("arn", ""),
                state=i.get("state", "running"),
                public_ip=i.get("public_ip"),
                private_ip=i.get("private_ip"),
                subnet_id=i.get("subnet_id", ""),
                vpc_id=i.get("vpc_id", ""),
                security_group_ids=tuple(i.get("security_group_ids", [])),
                instance_profile_arn=i.get("instance_profile_arn"),
                role_arn=i.get("role_arn"),
                tags=i.get("tags", {}),
            )
            for i in raw.get("instances", [])
        ],
        security_groups=[_sg(g) for g in raw.get("security_groups", [])],
        route_tables=[_route_table(t) for t in raw.get("route_tables", [])],
        buckets=[
            S3Bucket(
                name=b["name"],
                arn=b.get("arn", f"arn:aws:s3:::{b['name']}"),
                policy=b.get("policy"),
                public_access_block=b.get("public_access_block", {}),
                acl_public=b.get("acl_public", False),
                tags=b.get("tags", {}),
                credential=b.get("credential"),
            )
            for b in raw.get("buckets", [])
        ],
        roles=[
            IAMRole(
                name=r["name"],
                arn=r.get("arn", ""),
                trust_policy=r.get("trust_policy", {}),
                policies=tuple(
                    (name, doc) for name, doc in r.get("policies", [])
                ),
                permission_boundary=r.get("permission_boundary"),
                tags=r.get("tags", {}),
            )
            for r in raw.get("roles", [])
        ],
        db_instances=[
            DBInstance(
                identifier=d["identifier"],
                arn=d.get("arn", ""),
                engine=d.get("engine", ""),
                publicly_accessible=d.get("publicly_accessible", False),
                vpc_security_group_ids=tuple(d.get("vpc_security_group_ids", [])),
                tags=d.get("tags", {}),
            )
            for d in raw.get("db_instances", [])
        ],
    )
