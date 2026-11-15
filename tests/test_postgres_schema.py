"""Postgres schema + backend tests.

The DDL and the recursive-CTE view are validated statically in
every run. The live-database test is skipped unless
``CHOKEPOINT_TEST_DSN`` points at a Postgres the test can use
(e.g. ``postgresql://postgres@localhost/chokepoint_test``) — the
suite must pass without a database.
"""

import os
from pathlib import Path

import pytest

SCHEMA = Path(__file__).resolve().parent.parent / "chokepoint" / "graph" / "schema.sql"


def test_schema_sql_exists_and_defines_tables():
    text = SCHEMA.read_text()
    assert "CREATE TABLE IF NOT EXISTS cp_nodes" in text
    assert "CREATE TABLE IF NOT EXISTS cp_edges" in text
    assert "WITH RECURSIVE" in text
    assert "cp_reachable_crown_jewels" in text
    assert "confidence" in text and "'proven', 'unknown'" in text


@pytest.mark.skipif(
    not os.environ.get("CHOKEPOINT_TEST_DSN"),
    reason="needs CHOKEPOINT_TEST_DSN pointing at a test Postgres",
)
def test_postgres_store_roundtrip_and_reachability():
    from chokepoint.graph.memory import InMemoryGraphStore  # noqa: F401
    from chokepoint.graph.model import Confidence, Edge, EdgeKind, Node, NodeKind
    from chokepoint.graph.postgres import PostgresGraphStore
    from chokepoint.demo import load_demo_inventory
    from chokepoint.graph.builder import build_graph
    from chokepoint.paths.crown_jewels import suggest_crown_jewels

    store = PostgresGraphStore(os.environ["CHOKEPOINT_TEST_DSN"])
    try:
        store.ensure_schema()
        store.clear()
        store.add_node(Node(id="internet", kind=NodeKind.INTERNET, label="Internet"))
        store.add_node(
            Node(id="rds:prod-db", kind=NodeKind.DATASTORE, label="prod-db",
                 crown_jewel=True)
        )
        store.add_edge(
            Edge(source="internet", target="rds:prod-db", kind=EdgeKind.CAN_REACH,
                 evidence="test", confidence=Confidence.PROVEN)
        )
        assert store.get_node("rds:prod-db").crown_jewel is True
        assert len(store.outgoing("internet")) == 1
        reachable = store.reachable_crown_jewels()
        assert [n.id for n in reachable] == ["rds:prod-db"]

        # Full demo inventory round-trips through Postgres too.
        store.clear()
        build_graph(load_demo_inventory(), store)
        for node_id in suggest_crown_jewels(load_demo_inventory()):
            node = store.get_node(node_id)
            store.add_node(
                Node(id=node.id, kind=node.kind, label=node.label,
                     attributes=node.attributes, crown_jewel=True)
            )
        assert sorted(n.id for n in store.reachable_crown_jewels()) == [
            "rds:prod-db", "s3:customer-data",
        ]
    finally:
        store.clear()
        store.close()
