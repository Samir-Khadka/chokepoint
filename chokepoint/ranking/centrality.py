"""Path-graph betweenness centrality (Brandes, directed, unweighted).

Computed over the subgraph induced by the attack paths: nodes and
proven edges that appear in at least one path. It is a *tiebreak*
only — when two candidate fixes remove the same number of paths,
the one sitting on more shortest routes ranks first. It never
overrides the paths-removed count.

Node and edge betweenness share a unit (number of shortest-path
pairs whose shortest route passes through the node/edge), so the
two are comparable across candidate kinds. Parallel edges between
the same node pair share that pair's betweenness equally: the
shortest-path count cannot tell them apart, so each gets an equal
share rather than all of it.

Determinism: adjacency is sorted and sources are processed in
sorted node-id order, so the same input always yields the same
scores.
"""

from __future__ import annotations

from collections import deque

from ..paths.patterns import Path


def _path_subgraph(paths: list[Path]):
    """Nodes and (source, target) pairs used by at least one path,
    plus the number of *distinct* edge kinds per pair (parallel
    edges). The count is over distinct edges, not occurrences:
    the same edge appearing in three paths is still one edge."""
    nodes: set[str] = set()
    edge_keys: set[tuple[str, str, str]] = set()
    for path in paths:
        nodes.update(node.id for node in path.nodes)
        for edge in path.edges:
            edge_keys.add((edge.source, edge.target, edge.kind.value))
    pairs: dict[tuple[str, str], int] = {}
    for (source, target, _kind) in edge_keys:
        pair = (source, target)
        pairs[pair] = pairs.get(pair, 0) + 1
    return nodes, pairs


def betweenness(paths: list[Path]):
    """Return ``(node_betweenness, edge_betweenness)``.

    ``node_betweenness`` maps node id -> float; ``edge_betweenness``
    maps ``(source, target, kind)`` -> float. Both are 0.0 for
    nodes/edges that appear in no shortest path.
    """
    nodes, pairs = _path_subgraph(paths)
    successors: dict[str, list[str]] = {
        node: sorted({t for (s, t) in pairs if s == node}) for node in nodes
    }
    node_b: dict[str, float] = {node: 0.0 for node in nodes}
    pair_b: dict[tuple[str, str], float] = {pair: 0.0 for pair in pairs}

    for source in sorted(nodes):
        # Breadth-first search from ``source`` (Brandes).
        stack: list[str] = []
        predecessors: dict[str, list[str]] = {node: [] for node in nodes}
        sigma: dict[str, float] = {node: 0.0 for node in nodes}
        sigma[source] = 1.0
        dist: dict[str, int] = {node: -1 for node in nodes}
        dist[source] = 0
        queue: deque[str] = deque([source])
        while queue:
            current = queue.popleft()
            stack.append(current)
            for nxt in successors[current]:
                if dist[nxt] < 0:
                    dist[nxt] = dist[current] + 1
                    queue.append(nxt)
                if dist[nxt] == dist[current] + 1:
                    sigma[nxt] += sigma[current]
                    predecessors[nxt].append(current)
        # Accumulate dependencies back down the stack.
        delta: dict[str, float] = {node: 0.0 for node in nodes}
        while stack:
            w = stack.pop()
            for v in predecessors[w]:
                coeff = (sigma[v] / sigma[w]) * (1.0 + delta[w]) if sigma[w] else 0.0
                pair_b[(v, w)] += coeff
                delta[v] += coeff
            if w != source:
                node_b[w] += delta[w]

    edge_b: dict[tuple[str, str, str], float] = {}
    for path in paths:
        for edge in path.edges:
            key = (edge.source, edge.target, edge.kind.value)
            if key not in edge_b:
                pair = (edge.source, edge.target)
                edge_b[key] = pair_b[pair] / pairs[pair]
    return node_b, edge_b
