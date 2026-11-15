"""In-memory graph backend.

Used by the test suite and demo mode. No external services, no
database — a plain dict of nodes and an adjacency list of edges.
Edges are de-duplicated on (source, target, kind): a later add of
the same edge keeps the first (proven beats unknown if the first
was unknown and the second proven — see :meth:`add_edge`).
"""

from __future__ import annotations

from .model import Confidence, Edge, Node


class InMemoryGraphStore:
    """A GraphStore held entirely in memory."""

    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._edges: dict[tuple[str, str, str], Edge] = {}

    def add_node(self, node: Node) -> None:
        existing = self._nodes.get(node.id)
        if existing is not None and existing.crown_jewel and not node.crown_jewel:
            # Never lose a crown-jewel tag to a later, untagged add.
            node = Node(
                id=node.id,
                kind=node.kind,
                label=node.label,
                attributes={**node.attributes, **existing.attributes},
                crown_jewel=True,
            )
        self._nodes[node.id] = node

    def add_edge(self, edge: Edge) -> None:
        key = (edge.source, edge.target, edge.kind.value)
        existing = self._edges.get(key)
        if existing is None:
            self._edges[key] = edge
        elif (
            existing.confidence is Confidence.UNKNOWN
            and edge.confidence is Confidence.PROVEN
        ):
            self._edges[key] = edge
        # Otherwise keep the first edge: evidence is equivalent for
        # the same (source, target, kind).

    def get_node(self, node_id: str) -> Node | None:
        return self._nodes.get(node_id)

    def nodes(self) -> list[Node]:
        return list(self._nodes.values())

    def edges(self) -> list[Edge]:
        return list(self._edges.values())

    def outgoing(self, node_id: str) -> list[Edge]:
        return [e for e in self._edges.values() if e.source == node_id]

    def clear(self) -> None:
        self._nodes.clear()
        self._edges.clear()

    def close(self) -> None:
        pass
