"""Graph store interface.

Two backends implement this protocol:

* :class:`InMemoryGraphStore` (``memory.py``) — used by tests and
  demo mode, so the suite runs without a live database.
* :class:`PostgresGraphStore` (``postgres.py``) — the real store,
  Postgres-first per the plan (Section 6). Reachability uses
  recursive CTEs; see ``schema.sql``.

The path engine only talks to this interface, so backends are
interchangeable.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .model import Edge, Node


@runtime_checkable
class GraphStore(Protocol):
    """Minimal graph operations the path engine needs."""

    def add_node(self, node: Node) -> None: ...

    def add_edge(self, edge: Edge) -> None: ...

    def get_node(self, node_id: str) -> Node | None: ...

    def nodes(self) -> list[Node]: ...

    def edges(self) -> list[Edge]: ...

    def outgoing(self, node_id: str) -> list[Edge]: ...

    def clear(self) -> None: ...

    def close(self) -> None: ...
