"""End-to-end CLI tests (demo mode only — no credentials, no AWS)."""

import json
import subprocess
import sys

import pytest

from chokepoint.demo import load_demo_inventory


def _run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "chokepoint", *args],
        capture_output=True,
        text=True,
        cwd=str(__import__("pathlib").Path(__file__).resolve().parent.parent),
    )


def test_scan_demo_text_output():
    result = _run_cli("scan", "--demo")
    assert result.returncode == 0, result.stderr
    out = result.stdout
    assert "Found 4 attack path(s)" in out
    assert "web-role" in out
    assert "Top choke point" in out
    assert "rds:prod-db" in out
    assert "s3:customer-data" in out


def test_list_paths_demo_json_output():
    result = _run_cli("list-paths", "--demo", "--output", "json")
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert len(data["paths"]) == 4
    assert data["choke_point"] == "iam-role:web-role"
    assert sorted(data["crown_jewels"]) == ["rds:prod-db", "s3:customer-data"]
    patterns = sorted(p["pattern"] for p in data["paths"])
    assert patterns == ["P1", "P1", "P1", "P2"]
    # Every hop carries evidence and a proven confidence.
    for path in data["paths"]:
        for hop in path["hops"]:
            assert hop["evidence"]
            assert hop["confidence"] == "proven"


def test_scan_demo_explicit_crown_jewel():
    # Tagging the logs bucket explicitly creates two more paths:
    # P2 direct (internet -> logs) and P1 via web-role's broad read.
    result = _run_cli(
        "scan", "--demo", "--crown-jewel", "s3:logs", "--output", "json"
    )
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert len(data["paths"]) == 6
    assert "s3:logs" in data["crown_jewels"]


def test_demo_inventory_loads():
    inv = load_demo_inventory()
    assert len(inv.instances) == 3
    assert len(inv.buckets) == 4
    assert len(inv.roles) == 5
    assert len(inv.db_instances) == 1
