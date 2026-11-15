"""Tests for crown-jewel tagging and P1/P2 path finding.

Accuracy bar (plan Section 10): on the seeded demo account every
planted path is found and no invented path is shown. The demo
account plants exactly four paths; the decoys must appear in none.
"""

from chokepoint.collectors.records import (
    DBInstance,
    IAMRole,
    Inventory,
    S3Bucket,
)
from chokepoint.demo import load_demo_inventory
from chokepoint.graph.builder import build_graph
from chokepoint.graph.memory import InMemoryGraphStore
from chokepoint.graph.model import Node
from chokepoint.paths.crown_jewels import suggest_crown_jewels
from chokepoint.paths.patterns import choke_point, find_paths, paths_through


def _store_with_jewels(inventory, extra=()):
    store = InMemoryGraphStore()
    build_graph(inventory, store)
    for node_id in list(suggest_crown_jewels(inventory)) + list(extra):
        node = store.get_node(node_id)
        if node is not None:
            store.add_node(
                Node(id=node.id, kind=node.kind, label=node.label,
                     attributes=node.attributes, crown_jewel=True)
            )
    return store


def test_suggested_crown_jewels_demo():
    inv = load_demo_inventory()
    assert sorted(suggest_crown_jewels(inv)) == ["rds:prod-db", "s3:customer-data"]


def test_suggest_crown_jewels_tag_rules():
    inv = Inventory(
        db_instances=[
            DBInstance(identifier="db1", arn="arn:aws:rds:us-east-1:1:db:db1",
                       engine="postgres", publicly_accessible=False,
                       tags={"crown-jewel": "true"})
        ],
        buckets=[
            S3Bucket(name="b1", arn="arn:aws:s3:::b1",
                     tags={"sensitivity": "restricted"})
        ],
        roles=[
            IAMRole(name="root-admin", arn="arn:aws:iam::1:role/root-admin",
                    tags={"admin": "true"})
        ],
    )
    assert sorted(suggest_crown_jewels(inv)) == [
        "iam-role:root-admin", "rds:db1", "s3:b1",
    ]


def test_demo_paths_exactly_four():
    store = _store_with_jewels(load_demo_inventory())
    paths = find_paths(store)
    assert len(paths) == 4
    by_pattern = {}
    for p in paths:
        by_pattern.setdefault(p.pattern, []).append(p)
    assert len(by_pattern["P1"]) == 3
    assert len(by_pattern["P2"]) == 1

    # P1 via credentials: web-1 -> web-role -> backups -> secret -> prod-db
    cred = [p for p in paths if "secret:backups:db-creds.json" in
            [n.id for n in p.nodes]]
    assert len(cred) == 1
    assert [n.id for n in cred[0].nodes] == [
        "internet", "ec2:i-web00001", "iam-role:web-role", "s3:backups",
        "secret:backups:db-creds.json", "rds:prod-db",
    ]
    assert cred[0].crown_jewel.id == "rds:prod-db"

    # P1 via assume-role: web-1 -> web-role -> admin-role -> prod-db
    assume = [p for p in paths if "iam-role:admin-role" in [n.id for n in p.nodes]]
    assert len(assume) == 1
    assert [n.id for n in assume[0].nodes] == [
        "internet", "ec2:i-web00001", "iam-role:web-role",
        "iam-role:admin-role", "rds:prod-db",
    ]

    # P1 to the public customer-data bucket through the web role.
    via_role = [p for p in paths
                if p.crown_jewel.id == "s3:customer-data" and p.pattern == "P1"]
    assert len(via_role) == 1

    # P2 direct: internet -> customer-data.
    direct = [p for p in paths
              if p.crown_jewel.id == "s3:customer-data" and p.pattern == "P2"]
    assert len(direct) == 1
    assert [n.id for n in direct[0].nodes] == ["internet", "s3:customer-data"]


def test_decoys_appear_in_no_path():
    store = _store_with_jewels(load_demo_inventory())
    paths = find_paths(store)
    decoy_ids = {
        "ec2:i-wrk00001", "ec2:i-bas00001",
        "iam-role:worker-role", "iam-role:bastion-role", "iam-role:orphan-role",
    }
    for p in paths:
        assert not decoy_ids.intersection({n.id for n in p.nodes})
    # The public logs bucket is not a crown jewel, so it ends no path.
    assert all(p.crown_jewel.id != "s3:logs" for p in paths)


def test_choke_point_is_web_role():
    store = _store_with_jewels(load_demo_inventory())
    paths = find_paths(store)
    cp = choke_point(paths)
    assert cp is not None
    assert cp.id == "iam-role:web-role"
    assert paths_through(paths, "iam-role:web-role") == 3


def test_no_paths_without_crown_jewels():
    store = InMemoryGraphStore()
    build_graph(load_demo_inventory(), store)
    assert find_paths(store) == []


def test_no_paths_when_nothing_is_public():
    from dataclasses import replace

    inv = load_demo_inventory()
    # Make web-1 private and both buckets private: no entry point left.
    inv.instances = [
        replace(inst, public_ip=None) if inst.id == "i-web00001" else inst
        for inst in inv.instances
    ]
    inv.buckets = [
        replace(b, policy=None) if b.name in ("customer-data", "logs") else b
        for b in inv.buckets
    ]
    store = _store_with_jewels(inv)
    assert find_paths(store) == []


def test_unknown_edges_are_never_followed():
    # A bucket policy with a Condition: the public edge is unknown,
    # so the P2 path must not be reported even though the bucket is
    # tagged a crown jewel.
    inv = Inventory(
        buckets=[
            S3Bucket(
                name="cond-bucket",
                arn="arn:aws:s3:::cond-bucket",
                policy={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::cond-bucket/*",
                            "Condition": {
                                "IpAddress": {"aws:SourceIp": "10.0.0.0/8"}
                            },
                        }
                    ],
                },
                tags={"sensitivity": "customer-data"},
            )
        ]
    )
    store = _store_with_jewels(inv)
    assert find_paths(store) == []
    from chokepoint.graph.model import Confidence, EdgeKind

    edge = next(
        e for e in store.outgoing("internet")
        if e.kind is EdgeKind.CAN_REACH
    )
    assert edge.confidence is Confidence.UNKNOWN


def test_path_render_includes_evidence():
    store = _store_with_jewels(load_demo_inventory())
    paths = find_paths(store)
    text = paths[0].render()
    assert "Internet" in text
    assert "can_reach" in text
    assert "sg-web" in text or "bucket policy" in text
