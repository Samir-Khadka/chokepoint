"""Tests for the graph store and the graph builder.

The builder is where collected facts become edges. The demo
inventory is the fixture: its planted paths are known, and its
decoys (private worker, office-only bastion, public-but-empty logs
bucket, orphan role) must produce no edge that could start a path.
"""

from chokepoint.demo import load_demo_inventory
from chokepoint.graph.builder import build_graph
from chokepoint.graph.memory import InMemoryGraphStore
from chokepoint.graph.model import Confidence, EdgeKind


def _built_store():
    store = InMemoryGraphStore()
    report = build_graph(load_demo_inventory(), store)
    return store, report


def _edge(store, source, target, kind):
    for e in store.outgoing(source):
        if e.target == target and e.kind is kind:
            return e
    return None


def test_demo_graph_node_and_edge_counts():
    store, report = _built_store()
    ids = {n.id for n in store.nodes()}
    assert ids == {
        "internet",
        "ec2:i-web00001", "ec2:i-wrk00001", "ec2:i-bas00001",
        "iam-role:web-role", "iam-role:admin-role", "iam-role:worker-role",
        "iam-role:bastion-role", "iam-role:orphan-role",
        "s3:backups", "s3:assets", "s3:customer-data", "s3:logs",
        "rds:prod-db",
        "secret:backups:db-creds.json",
    }
    # Every edge carries evidence.
    assert all(e.evidence for e in store.edges())
    assert report.nodes_added == len(ids)


def test_public_instance_reachable_but_decoys_are_not():
    store, _ = _built_store()
    # web-1: public IP + open SG + IGW route.
    e = _edge(store, "internet", "ec2:i-web00001", EdgeKind.CAN_REACH)
    assert e is not None
    assert e.confidence is Confidence.PROVEN
    assert "54.10.20.30" in e.evidence
    assert "sg-web" in e.evidence
    # worker-1: no public IP.
    assert _edge(store, "internet", "ec2:i-wrk00001", EdgeKind.CAN_REACH) is None
    # bastion-1: public IP + IGW route, but SG open only to 203.0.113.0/32.
    assert _edge(store, "internet", "ec2:i-bas00001", EdgeKind.CAN_REACH) is None


def test_has_role_and_assume_role_edges():
    store, _ = _built_store()
    assert _edge(store, "ec2:i-web00001", "iam-role:web-role", EdgeKind.HAS_ROLE)
    assert _edge(store, "ec2:i-wrk00001", "iam-role:worker-role", EdgeKind.HAS_ROLE)
    # web-role can assume admin-role (trust policy names its ARN).
    assert _edge(store, "iam-role:web-role", "iam-role:admin-role", EdgeKind.CAN_ASSUME)
    # No other role-to-role assumption exists in the demo account.
    assume = [e for e in store.edges() if e.kind is EdgeKind.CAN_ASSUME]
    assert len(assume) == 1


def test_role_read_edges_follow_policies():
    store, _ = _built_store()
    # web-role: s3:GetObject on * -> can read every bucket.
    assert _edge(store, "iam-role:web-role", "s3:backups", EdgeKind.CAN_READ)
    assert _edge(store, "iam-role:web-role", "s3:customer-data", EdgeKind.CAN_READ)
    # web-role cannot read prod-db directly (no rds permission).
    assert _edge(store, "iam-role:web-role", "rds:prod-db", EdgeKind.CAN_READ) is None
    # admin-role can connect to prod-db.
    assert _edge(store, "iam-role:admin-role", "rds:prod-db", EdgeKind.CAN_READ)
    # worker-role reads only the assets bucket.
    assert _edge(store, "iam-role:worker-role", "s3:assets", EdgeKind.CAN_READ)
    assert _edge(store, "iam-role:worker-role", "s3:backups", EdgeKind.CAN_READ) is None
    # orphan-role has s3:* / rds:* but no way in; edges exist, paths do not.
    assert _edge(store, "iam-role:orphan-role", "s3:backups", EdgeKind.CAN_ADMIN)


def test_public_buckets_reachable():
    store, _ = _built_store()
    assert _edge(store, "internet", "s3:customer-data", EdgeKind.CAN_REACH)
    assert _edge(store, "internet", "s3:logs", EdgeKind.CAN_REACH)
    assert _edge(store, "internet", "s3:backups", EdgeKind.CAN_REACH) is None
    assert _edge(store, "internet", "rds:prod-db", EdgeKind.CAN_REACH) is None


def test_credential_chain_edges():
    store, _ = _built_store()
    assert _edge(store, "s3:backups", "secret:backups:db-creds.json", EdgeKind.CONTAINS_CRED)
    assert _edge(
        store, "secret:backups:db-creds.json", "rds:prod-db", EdgeKind.CAN_ADMIN
    )


def test_in_memory_store_crown_jewel_merge():
    from chokepoint.graph.model import Node, NodeKind

    store = InMemoryGraphStore()
    store.add_node(Node(id="rds:x", kind=NodeKind.DATASTORE, label="x"))
    assert store.get_node("rds:x").crown_jewel is False
    store.add_node(
        Node(id="rds:x", kind=NodeKind.DATASTORE, label="x", crown_jewel=True)
    )
    assert store.get_node("rds:x").crown_jewel is True
    # A later untagged add must not clear the tag.
    store.add_node(Node(id="rds:x", kind=NodeKind.DATASTORE, label="x"))
    assert store.get_node("rds:x").crown_jewel is True


def test_in_memory_store_unknown_upgraded_by_proven():
    from chokepoint.graph.model import Edge, Node, NodeKind

    store = InMemoryGraphStore()
    store.add_node(Node(id="a", kind=NodeKind.INTERNET, label="a"))
    store.add_node(Node(id="b", kind=NodeKind.WORKLOAD, label="b"))
    store.add_edge(
        Edge(source="a", target="b", kind=EdgeKind.CAN_REACH,
             evidence="uncertain", confidence=Confidence.UNKNOWN)
    )
    store.add_edge(
        Edge(source="a", target="b", kind=EdgeKind.CAN_REACH,
             evidence="proven", confidence=Confidence.PROVEN)
    )
    edges = store.outgoing("a")
    assert len(edges) == 1
    assert edges[0].confidence is Confidence.PROVEN
