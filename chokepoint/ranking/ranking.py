"""Score and rank candidate fixes (plan Section 5, Rank).

Scoring is empirical, not estimated: a candidate's
``paths_removed`` is measured by re-running the path search with
the candidate applied (edge removed, or node plus its incident
edges removed) and counting how many paths disappear. Only
proven-confidence edges are ever scored — the path search never
follows unknown edges, so an unknown edge can never appear in a
candidate or a score.

Ranking order: paths removed (descending), then path-graph
betweenness (descending), then candidate id (ascending, for a
fully deterministic order).

Minimum disconnecting set: greedy set cover. Repeatedly pick the
candidate that removes the most *still-uncovered* paths until
every path is disconnected or candidates run out. This is an
approximation of a minimum cut, not an exact one — a greedy pick
can miss the smallest possible set — and it is labelled as such
wherever it is shown.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..graph.store import GraphStore
from ..paths.patterns import Path, find_paths
from .candidates import CandidateFix, enumerate_candidates
from .centrality import betweenness


@dataclass(frozen=True)
class ScoredFix:
    """A candidate fix with its measured effect."""

    candidate: CandidateFix
    paths_removed: int
    removed_path_indexes: tuple[int, ...]
    crown_jewels_protected: tuple[str, ...]
    betweenness: float


@dataclass(frozen=True)
class Ranking:
    """The ranked result for one account scan."""

    total_paths: int
    top_fixes: tuple[ScoredFix, ...]
    disconnecting_set: tuple[ScoredFix, ...]
    disconnects_all: bool


def _path_signature(path: Path) -> tuple[str, ...]:
    return tuple(node.id for node in path.nodes)


def score_candidate(
    store: GraphStore,
    paths: list[Path],
    candidate: CandidateFix,
    max_depth: int = 8,
) -> ScoredFix:
    """Measure a candidate by re-running path finding without it."""
    if candidate.kind == "edge":
        assert candidate.edge_key is not None
        remaining = find_paths(
            store, max_depth=max_depth, exclude_edges={candidate.edge_key}
        )
    else:
        remaining = find_paths(
            store, max_depth=max_depth, exclude_nodes={candidate.target_id}
        )
    remaining_signatures = {_path_signature(p) for p in remaining}
    removed = tuple(
        i for i, p in enumerate(paths)
        if _path_signature(p) not in remaining_signatures
    )
    # A crown jewel is protected when no path to it survives.
    surviving_jewels = {p.crown_jewel.id for p in remaining}
    protected = tuple(sorted(
        {p.crown_jewel.id for p in paths} - surviving_jewels
    ))
    return ScoredFix(
        candidate=candidate,
        paths_removed=len(removed),
        removed_path_indexes=removed,
        crown_jewels_protected=protected,
        betweenness=0.0,  # filled in by rank_fixes()
    )


def _rank_key(scored: ScoredFix):
    return (-scored.paths_removed, -scored.betweenness, scored.candidate.id)


def greedy_disconnecting_set(
    scored: list[ScoredFix], total_paths: int
) -> tuple[tuple[ScoredFix, ...], bool]:
    """Greedy set cover over the scored candidates.

    Returns (chosen fixes, disconnects_all). Greedy is an
    approximation of a minimum cut, not an exact one.
    """
    uncovered: set[int] = set(range(total_paths))
    chosen: list[ScoredFix] = []
    ordered = sorted(scored, key=_rank_key)
    while uncovered:
        best: ScoredFix | None = None
        best_cover = 0
        for candidate in ordered:
            cover = len(set(candidate.removed_path_indexes) & uncovered)
            if cover > best_cover:
                best, best_cover = candidate, cover
        if best is None or best_cover == 0:
            break
        chosen.append(best)
        uncovered -= set(best.removed_path_indexes)
    return tuple(chosen), not uncovered


def rank_fixes(
    store: GraphStore, paths: list[Path], top: int = 5, max_depth: int = 8
) -> Ranking:
    """Rank all candidate fixes for ``paths`` and pick the minimum
    disconnecting set. Deterministic: same input, same order."""
    if not paths:
        return Ranking(total_paths=0, top_fixes=(), disconnecting_set=(),
                       disconnects_all=True)
    node_b, edge_b = betweenness(paths)
    scored: list[ScoredFix] = []
    for candidate in enumerate_candidates(paths):
        measured = score_candidate(store, paths, candidate, max_depth)
        if candidate.kind == "node":
            centrality = node_b.get(candidate.target_id, 0.0)
        else:
            assert candidate.edge_key is not None
            centrality = edge_b.get(candidate.edge_key, 0.0)
        scored.append(
            ScoredFix(
                candidate=measured.candidate,
                paths_removed=measured.paths_removed,
                removed_path_indexes=measured.removed_path_indexes,
                crown_jewels_protected=measured.crown_jewels_protected,
                betweenness=centrality,
            )
        )
    scored.sort(key=_rank_key)
    chosen, disconnects_all = greedy_disconnecting_set(scored, len(paths))
    return Ranking(
        total_paths=len(paths),
        top_fixes=tuple(scored[:top]),
        disconnecting_set=chosen,
        disconnects_all=disconnects_all,
    )
