"""Path finding for the two Phase 1 patterns (plan Section 5).

P1 — public entry + role chain: Internet -> public workload
(EC2) -> role -> (assume-role)* -> crown jewel.
P2 — public storage: Internet -> public S3 bucket -> crown jewel
(the bucket itself, or a credential it holds leading to one).

Search is a depth-capped DFS from the ``internet`` node following
``proven`` edges only. Unknown edges are never followed — a path
the evaluator could not prove is not shown. Cycles are handled with
a per-path visited set. Search stops at a crown jewel: paths do not
extend past what matters.

A path's pattern is classified from its first hop: a CAN_REACH to a
WORKLOAD is P1; a CAN_REACH to a DATASTORE is P2.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..graph.model import Confidence, Edge, EdgeKind, Node, NodeKind
from ..graph.store import GraphStore


@dataclass(frozen=True)
class Path:
    """One route from the Internet to a crown jewel."""

    pattern: str  # "P1" or "P2"
    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]

    @property
    def crown_jewel(self) -> Node:
        return self.nodes[-1]

    def render(self) -> str:
        """One-line readable chain with evidence per hop."""
        parts = [self.nodes[0].label]
        for edge, node in zip(self.edges, self.nodes[1:]):
            parts.append(f"--{edge.kind.value}[{edge.evidence}]--> {node.label}")
        return " ".join(parts)


def classify_pattern(first_edge: Edge, first_node: Node) -> str:
    if first_edge.kind is EdgeKind.CAN_REACH and first_node.kind is NodeKind.DATASTORE:
        return "P2"
    return "P1"


def find_paths(store: GraphStore, max_depth: int = 8) -> list[Path]:
    """Enumerate all proven paths from the Internet to crown jewels."""
    internet = store.get_node("internet")
    if internet is None:
        return []
    crown_ids = {n.id for n in store.nodes() if n.crown_jewel}
    if not crown_ids:
        return []

    found: list[Path] = []

    def dfs(node: Node, path_nodes: list[Node], path_edges: list[Edge]) -> None:
        if len(path_edges) >= max_depth:
            return
        for edge in store.outgoing(node.id):
            if edge.confidence is not Confidence.PROVEN:
                continue
            target = store.get_node(edge.target)
            if target is None or target in path_nodes:
                continue
            new_nodes = path_nodes + [target]
            new_edges = path_edges + [edge]
            if target.id in crown_ids:
                found.append(
                    Path(
                        pattern=classify_pattern(new_edges[0], new_nodes[1]),
                        nodes=tuple(new_nodes),
                        edges=tuple(new_edges),
                    )
                )
                # Do not extend past a crown jewel.
                continue
            dfs(target, new_nodes, new_edges)

    dfs(internet, [internet], [])
    return found


def choke_point(paths: list[Path]) -> Node | None:
    """The node the most paths pass through (excluding Internet and
    crown jewels). Phase 1's simple stand-in for the Phase 3
    choke-point ranking: count paths per intermediate node.
    """
    counts: dict[str, int] = {}
    by_id: dict[str, Node] = {}
    for path in paths:
        for node in path.nodes[1:-1]:
            counts[node.id] = counts.get(node.id, 0) + 1
            by_id[node.id] = node
    if not counts:
        return None
    top_id = max(counts, key=lambda nid: (counts[nid], nid))
    return by_id[top_id]


def paths_through(paths: list[Path], node_id: str) -> int:
    """How many of ``paths`` pass through ``node_id``."""
    return sum(1 for p in paths if any(n.id == node_id for n in p.nodes))
