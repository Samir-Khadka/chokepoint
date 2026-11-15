"""Fix generation: pick a template, apply it, prove it helps.

The pipeline for one ranked fix:

1. :func:`select_template` picks the template for the candidate.
2. The template edits the fixture ``.tf`` text and declares the
   graph effect of its change as edge/node exclusions.
3. :func:`validate_fix` re-runs path finding with those exclusions
   and requires paths removed > 0 and zero new paths.
4. A unified diff of the ``.tf`` change is produced for the PR body.

Nothing is written to disk here — the caller writes the returned
``new_tf_text`` only after generation succeeds. A refused fix
raises :class:`FixRejected` and produces no output at all. The
generator never applies a change to real infrastructure: there is
no ``--apply`` anywhere in this phase.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

from ..graph.store import GraphStore
from ..paths.patterns import Path
from ..ranking.candidates import CandidateFix
from ..ranking.ranking import ScoredFix
from ..terraform import TerraformState
from .templates import (
    NoOpFix,
    TemplateApplication,
    UnsupportedFix,
    apply_template,
    select_template,
)
from .validation import ValidationResult, validate_fix

__all__ = ["FixRejected", "GeneratedFix", "fix_id", "generate_fix"]


class FixRejected(ValueError):
    """The fix was refused: it does not provably help."""


@dataclass(frozen=True)
class GeneratedFix:
    """A validated, ready-to-write fix."""

    candidate: CandidateFix
    template_name: str
    fix_id: str
    new_tf_text: str
    diff: str
    changed_addresses: tuple[str, ...]
    summary: str
    validation: ValidationResult
    ranked_paths_removed: int
    measured_paths_removed: int
    note: str


def fix_id(candidate: CandidateFix) -> str:
    """A filesystem-safe slug for a candidate, e.g.
    ``edge-ec2-i-web00001-iam-role-web-role-has_role``."""
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", candidate.id)
    return re.sub(r"-+", "-", slug).strip("-")


def generate_fix(
    candidate: CandidateFix,
    store: GraphStore,
    before_paths: list[Path],
    tf_text: str,
    state: TerraformState,
    max_depth: int = 8,
    ranked_paths_removed: int | None = None,
    scored: ScoredFix | None = None,
) -> GeneratedFix:
    """Generate a validated fix for one ranked candidate.

    Raises :class:`FixRejected` (or :class:`UnsupportedFix` /
    :class:`NoOpFix` from the template layer, both subclasses of
    ``ValueError``) when the fix cannot be generated or does not
    provably help. On refusal nothing is returned and the caller
    must write nothing.
    """
    if scored is not None and ranked_paths_removed is None:
        ranked_paths_removed = scored.paths_removed
    template_name = select_template(candidate, store)
    application = apply_template(
        template_name, candidate, tf_text, state, store
    )
    validation = validate_fix(
        store,
        before_paths,
        exclude_edges=set(application.exclude_edges),
        exclude_nodes=set(application.exclude_nodes),
        max_depth=max_depth,
    )
    if not validation.valid:
        raise FixRejected(
            f"{candidate.title}: {validation.reason}"
        )
    measured = validation.paths_removed
    ranked = ranked_paths_removed if ranked_paths_removed is not None else measured
    note = ""
    if measured != ranked:
        note = (
            f"Note: the ranked fix estimated {ranked} path(s) removed, "
            f"but this template removes {measured} — it implements "
            "the fix as a scoped Terraform change, not a deletion. "
            "The surviving path(s) are listed in the validation record."
        )
    diff = "".join(
        difflib.unified_diff(
            tf_text.splitlines(keepends=True),
            application.new_tf_text.splitlines(keepends=True),
            fromfile="main.tf",
            tofile="main.tf",
        )
    )
    return GeneratedFix(
        candidate=candidate,
        template_name=template_name,
        fix_id=fix_id(candidate),
        new_tf_text=application.new_tf_text,
        diff=diff,
        changed_addresses=application.changed_addresses,
        summary=application.summary,
        validation=validation,
        ranked_paths_removed=ranked,
        measured_paths_removed=measured,
        note=note,
    )
