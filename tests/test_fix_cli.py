"""End-to-end CLI tests for `chokepoint fix` (Phase 4)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest


def _run_fix(*args, cwd=None):
    result = subprocess.run(
        [sys.executable, "-m", "chokepoint", "fix", *args],
        capture_output=True,
        text=True,
        cwd=cwd or Path(__file__).resolve().parent.parent,
    )
    return result


def test_fix_1_writes_files(tmp_path):
    result = _run_fix("--demo", "--out-dir", str(tmp_path / "fix1"))
    assert result.returncode == 0, result.stderr
    assert "4 -> 1" in result.stdout
    assert "3 removed" in result.stdout
    out = tmp_path / "fix1"
    assert (out / "main.tf").exists()
    assert (out / "pr-body.md").exists()
    assert (out / "validation.json").exists()
    body = (out / "pr-body.md").read_text()
    assert "Attack paths before: **4**" in body
    assert "Attack paths after: **1**" in body
    assert "Detach role/web-role" in body
    record = json.loads((out / "validation.json").read_text())
    assert record["before_paths"] == 4
    assert record["after_paths"] == 1
    assert record["paths_removed"] == 3
    assert record["valid"] is True
    assert record["crown_jewels_protected"] == ["rds:prod-db", "s3:customer-data"]


def test_fix_2_writes_files_and_reports_measured_count(tmp_path):
    result = _run_fix("--demo", "--fix", "2", "--out-dir", str(tmp_path / "fix2"))
    assert result.returncode == 0, result.stderr
    assert "4 -> 2" in result.stdout
    record = json.loads((tmp_path / "fix2" / "validation.json").read_text())
    assert record["before_paths"] == 4
    assert record["after_paths"] == 2
    assert record["paths_removed"] == 2
    assert record["ranked_paths_removed"] == 3
    # The honest note about the measured-vs-ranked gap is shown.
    assert "Note:" in result.stdout


def test_fix_default_out_dir(tmp_path):
    """Without --out-dir, files land in fixes/<fix-id>/ under the cwd."""
    result = _run_fix("--demo", cwd=tmp_path)
    assert result.returncode == 0, result.stderr
    out = tmp_path / "fixes" / "edge-ec2-i-web00001-iam-role-web-role-has_role"
    assert (out / "main.tf").exists()
    assert (out / "pr-body.md").exists()
    assert (out / "validation.json").exists()


def test_fix_out_of_range(tmp_path):
    result = _run_fix("--demo", "--fix", "99", "--out-dir", str(tmp_path / "x"))
    assert result.returncode == 2
    assert "out of range" in result.stderr
    assert not (tmp_path / "x").exists()


def test_fix_requires_demo(tmp_path):
    result = _run_fix("--out-dir", str(tmp_path / "x"))
    assert result.returncode == 2
    assert "run with --demo" in result.stderr
    assert not (tmp_path / "x").exists()


def test_fix_refuses_noop_and_writes_nothing(tmp_path):
    """Fix #9 (admin-role, already scoped) is refused with no files."""
    result = _run_fix(
        "--demo", "--top", "15", "--fix", "9", "--out-dir", str(tmp_path / "fix9")
    )
    assert result.returncode == 1
    assert "Cannot generate this fix" in result.stderr
    assert not (tmp_path / "fix9").exists()


def test_fix_determinism(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    assert _run_fix("--demo", "--fix", "3", "--out-dir", str(a)).returncode == 0
    assert _run_fix("--demo", "--fix", "3", "--out-dir", str(b)).returncode == 0
    for name in ("main.tf", "pr-body.md", "validation.json"):
        assert (a / name).read_bytes() == (b / name).read_bytes()
