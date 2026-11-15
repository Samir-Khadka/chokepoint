"""Tests for fix generation + mandatory validation (Phase 4).

The validation rule: a fix is only emitted if, applied to a copy
of the in-memory graph, it removes paths and introduces none.
A no-op fix is refused and writes no output files.
"""

import json

import pytest

from chokepoint.cli import _write_fix_files
from chokepoint.fixes import (
    FixRejected,
    generate_fix,
    render_pr_body,
)
from chokepoint.fixes.templates import (
    NoOpFix,
    TemplateApplication,
    UnsupportedFix,
)
from chokepoint.fixes.validation import validate_fix
from chokepoint.ranking.candidates import CandidateFix


def _ranked(demo_ranking, rank):
    return demo_ranking.top_fixes[rank - 1]


def test_top_fix_takes_demo_from_4_paths_to_1(
    demo_graph, demo_ranking, demo_fixture
):
    main_tf, state = demo_fixture
    scored = _ranked(demo_ranking, 1)
    generated = generate_fix(
        scored.candidate,
        demo_graph["store"],
        demo_graph["paths"],
        main_tf,
        state,
        scored=scored,
    )
    assert generated.validation.valid is True
    assert generated.validation.before_count == 4
    assert generated.validation.after_count == 1
    assert generated.measured_paths_removed == 3
    assert generated.validation.new_paths == ()
    # The one surviving path is the direct public-bucket path:
    # Internet -> s3://customer-data (P2), which detaching the role
    # cannot touch.
    remaining = generated.validation.after_paths
    assert len(remaining) == 1
    assert remaining[0].pattern == "P2"
    assert [n.id for n in remaining[0].nodes] == [
        "internet",
        "s3:customer-data",
    ]
    # Exactly which paths disappeared is reported.
    removed = generated.validation.removed_paths
    assert len(removed) == 3
    assert {p.pattern for p in removed} == {"P1"}
    assert {p.crown_jewel.id for p in removed} == {
        "rds:prod-db",
        "s3:customer-data",
    }


def test_scope_fix_measures_less_than_ranked(
    demo_graph, demo_ranking, demo_fixture
):
    """Fix #2: the ranked estimate was 3 removed; the template
    measures 2, because the path via admin-role survives. The
    generator reports the measured number and notes the gap."""
    main_tf, state = demo_fixture
    scored = _ranked(demo_ranking, 2)
    generated = generate_fix(
        scored.candidate,
        demo_graph["store"],
        demo_graph["paths"],
        main_tf,
        state,
        scored=scored,
    )
    assert generated.validation.before_count == 4
    assert generated.validation.after_count == 2
    assert generated.ranked_paths_removed == 3
    assert generated.measured_paths_removed == 2
    assert generated.note != ""
    assert generated.validation.valid is True


def test_validation_refuses_noop_fix(demo_graph, demo_fixture):
    """A fix whose exclusions remove no paths is invalid."""
    result = validate_fix(
        demo_graph["store"],
        demo_graph["paths"],
        exclude_edges=set(),
        exclude_nodes=set(),
    )
    assert result.valid is False
    assert result.before_count == 4
    assert result.after_count == 4
    assert result.paths_removed == 0
    assert "removes no attack paths" in result.reason


def test_validation_refuses_fix_that_adds_paths(demo_graph):
    """The new-path guard: if the before-set is incomplete (here
    deliberately missing the direct public-bucket path), the fix is
    refused, because the after-set contains a path the before-set
    did not know about. Exclusions can only remove edges, so a
    complete before-set can never gain paths — this guard catches
    a stale or partial before-set instead of blessing it."""
    before_paths = [
        p for p in demo_graph["paths"] if p.pattern == "P1"
    ]
    assert len(before_paths) == 3
    result = validate_fix(
        demo_graph["store"],
        before_paths,
        exclude_edges={("ec2:i-web00001", "iam-role:web-role", "has_role")},
    )
    assert result.valid is False
    assert len(result.new_paths) == 1
    assert result.new_paths[0].pattern == "P2"
    assert "new attack path" in result.reason


def test_generate_fix_rejects_unsupported(demo_graph, demo_fixture):
    main_tf, state = demo_fixture
    candidate = CandidateFix(
        id="edge:x->y:can_delete",
        kind="edge",
        target_id="y",
        edge_key=("x", "y", "can_delete"),
        title="t",
        explanation="e",
        evidence=(),
        what_could_break="b",
    )
    with pytest.raises(UnsupportedFix):
        generate_fix(
            candidate, demo_graph["store"], demo_graph["paths"], main_tf, state
        )


def test_generate_fix_rejects_noop(demo_graph, demo_ranking, demo_fixture):
    main_tf, state = demo_fixture
    scored = _ranked(demo_ranking, 9)  # admin-role, already scoped
    with pytest.raises(NoOpFix):
        generate_fix(
            scored.candidate,
            demo_graph["store"],
            demo_graph["paths"],
            main_tf,
            state,
            scored=scored,
        )


def test_generate_fix_rejects_validation_failure(demo_graph, demo_fixture):
    """A template that declares an empty exclusion is refused by
    validation (FixRejected), not by the template layer."""
    main_tf, state = demo_fixture
    noop = TemplateApplication(
        template_name="noop",
        new_tf_text=main_tf,
        changed_addresses=(),
        exclude_edges=frozenset(),
        exclude_nodes=frozenset(),
        summary="nothing changes",
    )
    result = validate_fix(
        demo_graph["store"],
        demo_graph["paths"],
        exclude_edges=set(noop.exclude_edges),
        exclude_nodes=set(noop.exclude_nodes),
    )
    assert result.valid is False
    assert result.reason.startswith("refused:")


def test_validation_json_round_trip(demo_graph, demo_ranking, demo_fixture, tmp_path):
    """The record the CLI writes is complete and JSON-serialisable."""
    main_tf, state = demo_fixture
    scored = _ranked(demo_ranking, 1)
    generated = generate_fix(
        scored.candidate,
        demo_graph["store"],
        demo_graph["paths"],
        main_tf,
        state,
        scored=scored,
    )
    out_dir = tmp_path / "fix1"
    record = _write_fix_files(
        out_dir, generated, render_pr_body(generated, "123456789012")
    )
    assert record["before_paths"] == 4
    assert record["after_paths"] == 1
    assert record["paths_removed"] == 3
    assert record["new_paths"] == []
    assert len(record["removed_paths"]) == 3
    assert record["valid"] is True
    assert record["crown_jewels_protected"] == ["rds:prod-db", "s3:customer-data"]
    on_disk = json.loads((out_dir / "validation.json").read_text())
    assert on_disk == record


def test_determinism(demo_graph, demo_ranking, demo_fixture):
    """Same input -> same output, byte for byte."""
    main_tf, state = demo_fixture
    scored = _ranked(demo_ranking, 2)
    first = generate_fix(
        scored.candidate,
        demo_graph["store"],
        demo_graph["paths"],
        main_tf,
        state,
        scored=scored,
    )
    second = generate_fix(
        scored.candidate,
        demo_graph["store"],
        demo_graph["paths"],
        main_tf,
        state,
        scored=scored,
    )
    assert first.new_tf_text == second.new_tf_text
    assert first.diff == second.diff
    assert first.validation == second.validation
    assert (
        render_pr_body(first, "123456789012")
        == render_pr_body(second, "123456789012")
    )


def test_pr_body_contains_counts_and_diff(demo_graph, demo_ranking, demo_fixture):
    main_tf, state = demo_fixture
    scored = _ranked(demo_ranking, 1)
    generated = generate_fix(
        scored.candidate,
        demo_graph["store"],
        demo_graph["paths"],
        main_tf,
        state,
        scored=scored,
    )
    body = render_pr_body(generated, "123456789012")
    assert "Attack paths before: **4**" in body
    assert "Attack paths after: **1**" in body
    assert "Paths removed: **3**" in body
    assert "```diff" in body
    assert "iam_instance_profile" in body
    assert "review before merging" in body.lower()
    assert "No infrastructure was changed" in body
    assert "## What could break" in body
    assert "123456789012" in body
