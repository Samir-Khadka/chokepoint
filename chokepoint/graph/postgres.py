"""Postgres graph backend (plan Section 6: Postgres first).

Requires ``psycopg`` (``pip install chokepoint[postgres]``). The
connection is opened lazily; the schema in ``schema.sql`` is applied
on first use via :meth:`ensure_schema`. All reads/writes go through
plain SQL — no ORM — so the queries stay auditable.

If ``psycopg`` is not installed, importing this module still works,
but constructing a store raises a clear error telling the user how
to install it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .model import Confidence, Edge, EdgeKind, Node, NodeKind
from .store import GraphStore

_SCHEMA_PATH = Path(__file__).with_name("schema.sql")


class PostgresGraphStore:
    """A GraphStore backed by Postgres (see ``schema.sql``)."""

    def __init__(self, dsn: str) -> None:
        try:
            import psycopg  # noqa: PLC0415  (optional dependency)
        except ImportError as exc:  # pragma: no cover - import guard
            raise RuntimeError(
                "psycopg is required for the Postgres backend: "
                "pip install chokepoint[postgres]"
            ) from exc
        self._psycopg = psycopg
        self._dsn = dsn
        self._conn = None
        self._schema_done = False

    # -- connection handling -------------------------------------------------
    def _connect(self):
        if self._conn is None:
            self._conn = self._psycopg.connect(self._dsn, autocommit=True)
        return self._conn

    def ensure_schema(self) -> None:
        """Create the cp_nodes / cp_edges tables if they do not exist."""
        if self._schema_done:
            return
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(_SCHEMA_PATH.read_text())
        self._schema_done = True

    # -- GraphStore protocol -------------------------------------------------
    def add_node(self, node: Node) -> None:
        self.ensure_schema()
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO cp_nodes (id, kind, label, attributes, crown_jewel)
                VALUES (%s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (id) DO UPDATE
                  SET kind = EXCLUDED.kind,
                      label = EXCLUDED.label,
                      attributes = cp_nodes.attributes || EXCLUDED.attributes,
                      crown_jewel = cp_nodes.crown_jewel OR EXCLUDED.crown_jewel
                """,
                (
                    node.id,
                    node.kind.value,
                    node.label,
                    json.dumps(node.attributes),
                    node.crown_jewel,
                ),
            )

    def add_edge(self, edge: Edge) -> None:
        self.ensure_schema()
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO cp_edges
                    (source, target, kind, evidence, evidence_ref,
                     confidence, collected_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (source, target, kind) DO UPDATE
                  SET confidence = CASE
                        WHEN cp_edges.confidence = 'unknown'
                         AND EXCLUDED.confidence = 'proven'
                        THEN 'proven' ELSE cp_edges.confidence END,
                      evidence = CASE
                        WHEN cp_edges.confidence = 'unknown'
                         AND EXCLUDED.confidence = 'proven'
                        THEN EXCLUDED.evidence ELSE cp_edges.evidence END
                """,
                (
                    edge.source,
                    edge.target,
                    edge.kind.value,
                    edge.evidence,
                    edge.evidence_ref,
                    edge.confidence.value,
                    edge.collected_at or None,
                ),
            )

    def get_node(self, node_id: str) -> Node | None:
        self.ensure_schema()
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, kind, label, attributes, crown_jewel "
                "FROM cp_nodes WHERE id = %s",
                (node_id,),
            )
            row = cur.fetchone()
        return self._row_to_node(row) if row else None

    def nodes(self) -> list[Node]:
        self.ensure_schema()
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute("SELECT id, kind, label, attributes, crown_jewel FROM cp_nodes")
            return [self._row_to_node(r) for r in cur.fetchall()]

    def edges(self) -> list[Edge]:
        self.ensure_schema()
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT source, target, kind, evidence, evidence_ref, "
                "confidence, collected_at FROM cp_edges"
            )
            return [self._row_to_edge(r) for r in cur.fetchall()]

    def outgoing(self, node_id: str) -> list[Edge]:
        self.ensure_schema()
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT source, target, kind, evidence, evidence_ref, "
                "confidence, collected_at FROM cp_edges WHERE source = %s",
                (node_id,),
            )
            return [self._row_to_edge(r) for r in cur.fetchall()]

    def reachable_crown_jewels(self) -> list[Node]:
        """Crown jewels reachable from the Internet, via the SQL
        recursive-CTE view in ``schema.sql`` (proven edges only)."""
        self.ensure_schema()
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, kind, label FROM cp_reachable_crown_jewels"
            )
            return [
                Node(id=r[0], kind=NodeKind(r[1]), label=r[2], crown_jewel=True)
                for r in cur.fetchall()
            ]

    def clear(self) -> None:
        self.ensure_schema()
        conn = self._connect()
        with conn.cursor() as cur:
            cur.execute("TRUNCATE cp_edges, cp_nodes")

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # -- row mapping ---------------------------------------------------------
    @staticmethod
    def _row_to_node(row) -> Node:
        node_id, kind, label, attributes, crown_jewel = row
        if isinstance(attributes, str):
            attributes = json.loads(attributes)
        return Node(
            id=node_id,
            kind=NodeKind(kind),
            label=label,
            attributes=attributes or {},
            crown_jewel=bool(crown_jewel),
        )

    @staticmethod
    def _row_to_edge(row) -> Edge:
        source, target, kind, evidence, evidence_ref, confidence, collected_at = row
        return Edge(
            source=source,
            target=target,
            kind=EdgeKind(kind),
            evidence=evidence,
            evidence_ref=evidence_ref or "",
            confidence=Confidence(confidence),
            collected_at=collected_at.isoformat() if collected_at else "",
        )


def postgres_store_from_env() -> PostgresGraphStore:
    """Build a Postgres store from ``CHOKEPOINT_DSN``."""
    dsn = os.environ.get("CHOKEPOINT_DSN", "")
    if not dsn:
        raise RuntimeError(
            "Postgres backend needs a DSN: pass --postgres or set "
            "CHOKEPOINT_DSN (e.g. postgresql://user:pass@localhost/chokepoint)"
        )
    return PostgresGraphStore(dsn)


# Re-export for isinstance checks in tests.
__all__ = ["GraphStore", "PostgresGraphStore", "postgres_store_from_env"]
