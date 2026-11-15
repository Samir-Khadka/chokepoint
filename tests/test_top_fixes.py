"""End-to-end CLI tests for `top-fixes` (demo mode only — no
credentials, no AWS)."""

import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "chokepoint", *args],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )


def test_top_fixes_demo_text_output():
    result = _run_cli("top-fixes", "--demo")
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "Detach role/web-role from ec2:i-web00001" in out
    assert "removes 3 of 4 path(s)" in out
    assert "Minimum disconnecting set" in out
    assert "2 fix(es) disconnect all 4 paths" in out
    assert "greedy approximation" in out
    assert "not validated Terraform changes" in out
    assert "What could break" in out


def test_top_fixes_demo_json_shape():
    result = _run_cli("top-fixes", "--demo", "--output", "json")
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["total_paths"] == 4
    assert sorted(data["crown_jewels"]) == ["rds:prod-db", "s3:customer-data"]
    assert len(data["top_fixes"]) == 5
    top = data["top_fixes"][0]
    assert top["paths_removed"] == 3
    assert top["paths_remaining"] == 1
    assert "web-role" in top["id"]
    assert "web-role" in top["title"]
    assert top["explanation"]
    assert "not a validated Terraform change" in top["explanation"]
    assert top["evidence"]
    assert top["what_could_break"]
    assert "Heuristic" in top["what_could_break"]
    assert top["crown_jewels_protected"] == ["rds:prod-db"]
    assert top["betweenness"] == 11.0
    assert len(top["removed_paths"]) == 3
    assert all(
        set(p) == {"pattern", "crown_jewel"} for p in top["removed_paths"]
    )
    disc = data["minimum_disconnecting_set"]
    assert disc["count"] == 2
    assert disc["disconnects_all"] is True
    assert len(disc["fixes"]) == 2


def test_top_fixes_top_n_limits_output():
    result = _run_cli("top-fixes", "--demo", "--top", "2", "--output", "json")
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert len(data["top_fixes"]) == 2
    # The disconnecting set still covers all paths.
    assert data["minimum_disconnecting_set"]["disconnects_all"] is True
    assert data["minimum_disconnecting_set"]["count"] == 2


def test_top_fixes_output_is_deterministic():
    first = _run_cli("top-fixes", "--demo", "--output", "json")
    second = _run_cli("top-fixes", "--demo", "--output", "json")
    assert first.returncode == 0 and second.returncode == 0
    assert first.stdout == second.stdout
    text_first = _run_cli("top-fixes", "--demo")
    text_second = _run_cli("top-fixes", "--demo")
    assert text_first.stdout == text_second.stdout


def test_top_fixes_with_extra_crown_jewel():
    # Tagging the logs bucket adds two paths (P2 direct + P1 via
    # web-role); the web-role cut then removes 4 of 6. The empty
    # (no-path) case is covered by the unit tests.
    result = _run_cli(
        "top-fixes", "--demo", "--crown-jewel", "s3:logs", "--output", "json"
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    # Tagging logs adds two paths (P2 direct + P1 via web-role).
    assert data["total_paths"] == 6
    assert data["top_fixes"][0]["paths_removed"] == 4
