"""Before/after validation for generated fixes (plan Section 7).

The safety rule, non-negotiable: a fix is only emitted when the
graph proves it helps. Validation re-runs path finding on a copy
of the in-memory graph with the fix applied (the same exclusion
mechanism the ranking module uses — ``find_paths`` with
``exclude_edges`` / ``exclude_nodes``), and requires two things:

* at least one path disappears (``paths_removed > 0``), and
* no new path appears (the after-set is a subset of the before-set).

A fix that does not reduce paths, or that opens a new route, is
refused and nothing is written. The plan's other safety rule is
enforced here too: no fix is generated for a path containing an
unknown-confidence edge — the product says "verify manually"
instead. (``find_paths`` only follows proven edges, so this is
normally vacuous; it is checked explicitly so a future path
source cannot silently bypass it.)
"""

from __future__ import annotations

from dataclasses import dataclass

from ..graph.model import Confidence
from ..graph.store import GraphStore
from ..paths.patterns import Path, find_paths


@dataclass(frozen=True)
class ValidationResult:
    """The measured effect of a fix on the graph."""

    valid: bool
    reason: str
    before_count: int
    after_count: int
    paths_removed: int
    removed_paths: tuple[Path, ...]
    new_paths: tuple[Path, ...]
    after_paths: tuple[Path, ...]


def _path_signature(path: Path) -> tuple[str, ...]:
    return tuple(node.id for node in path.nodes)


def validate_fix(
    store: GraphStore,
    before_paths: list[Path],
    exclude_edges: set[tuple[str, str, str]] | None = None,
    exclude_nodes: set[str] | None = None,
    max_depth: int = 8,
) -> ValidationResult:
    """Measure a fix by re-running path finding without it.

    The store is never mutated: exclusions are passed to
    ``find_paths``, exactly as the ranking module scores
    candidates.
    """
    for path in before_paths:
        for edge in path.edges:
            if edge.confidence is not Confidence.PROVEN:
                return ValidationResult(
                    valid=False,
                    reason=(
                        "refused: a path to fix contains an "
                        "unknown-confidence edge — verify manually"
                    ),
                    before_count=len(before_paths),
                    after_count=len(before_paths),
                    paths_removed=0,
                    removed_paths=(),
                    new_paths=(),
                    after_paths=tuple(before_paths),
                )

    after_paths = find_paths(
        store,
        max_depth=max_depth,
        exclude_edges=set(exclude_edges or ()),
        exclude_nodes=set(exclude_nodes or ()),
    )
    before_sigs = {_path_signature(p) for p in before_paths}
    after_sigs = {_path_signature(p) for p in after_paths}
    removed = tuple(p for p in before_paths if _path_signature(p) not in after_sigs)
    new = tuple(p for p in after_paths if _path_signature(p) not in before_sigs)

    if not removed:
        return ValidationResult(
            valid=False,
            reason="refused: the fix removes no attack paths",
            before_count=len(before_paths),
            after_count=len(after_paths),
            paths_removed=0,
            removed_paths=(),
            new_paths=new,
            after_paths=tuple(after_paths),
        )
    if new:
        return ValidationResult(
            valid=False,
            reason=(
                f"refused: the fix opens {len(new)} new attack path(s)"
            ),
            before_count=len(before_paths),
            after_count=len(after_paths),
            paths_removed=len(removed),
            removed_paths=removed,
            new_paths=new,
            after_paths=tuple(after_paths),
        )
    return ValidationResult(
        valid=True,
        reason=(
            f"removes {len(removed)} of {len(before_paths)} path(s); "
            "no new paths introduced"
        ),
        before_count=len(before_paths),
        after_count=len(after_paths),
        paths_removed=len(removed),
        removed_paths=removed,
        new_paths=(),
        after_paths=tuple(after_paths),
    )
