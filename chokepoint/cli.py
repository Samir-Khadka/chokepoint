"""Chokepoint Phase 1 CLI.

Commands:
  scan        collect (or load --demo), build the graph, find paths
  list-paths  same as scan, but print only the paths

Read-only by design: ``scan`` against real AWS uses the read-only
guard (``collectors.aws``) and a least-privilege read-only role.
``--demo`` needs no credentials at all.

Examples:
  python -m chokepoint scan --demo
  python -m chokepoint scan --demo --output json
  python -m chokepoint scan --region us-east-1 --profile my-ro
  python -m chokepoint scan --demo --postgres postgresql://localhost/chokepoint
"""

from __future__ import annotations

import argparse
import json
import sys

from .collectors import scan_account
from .demo import load_demo_inventory
from .graph.builder import build_graph
from .graph.memory import InMemoryGraphStore
from .graph.model import Node
from .graph.postgres import PostgresGraphStore
from .paths.crown_jewels import suggest_crown_jewels
from .paths.patterns import choke_point, find_paths, paths_through


def _build_store(args):
    if args.postgres:
        return PostgresGraphStore(args.postgres)
    return InMemoryGraphStore()


def _load_inventory(args):
    if args.demo:
        return load_demo_inventory()
    import boto3  # noqa: PLC0415  (only needed for real scans)

    session_kwargs = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    session = boto3.Session(**session_kwargs)
    return scan_account(session, args.region)


def _apply_crown_jewels(store, inventory, extra_ids):
    jewel_ids = set(suggest_crown_jewels(inventory)) | set(extra_ids)
    for node_id in jewel_ids:
        node = store.get_node(node_id)
        if node is not None:
            store.add_node(
                Node(
                    id=node.id,
                    kind=node.kind,
                    label=node.label,
                    attributes=node.attributes,
                    crown_jewel=True,
                )
            )
    return sorted(jewel_ids)


def _run(args):
    inventory = _load_inventory(args)
    store = _build_store(args)
    try:
        report = build_graph(inventory, store)
        jewel_ids = _apply_crown_jewels(store, inventory, args.crown_jewel)
        paths = find_paths(store, max_depth=args.max_depth)
    finally:
        if isinstance(store, PostgresGraphStore):
            store.close()

    return inventory, store, report, jewel_ids, paths


def _render_text(inventory, report, jewel_ids, paths) -> str:
    lines = [
        f"Chokepoint scan — account {inventory.account_id or '(demo)'} "
        f"region {inventory.region}",
        f"Graph: {report.nodes_added} nodes, {report.edges_added} edges "
        f"({len(report.unknown_edges)} unknown-confidence edges, not used for paths)",
        f"Crown jewels: {', '.join(jewel_ids) if jewel_ids else 'none tagged'}",
        "",
    ]
    if not paths:
        lines.append("No attack paths found from the Internet to a crown jewel.")
        return "\n".join(lines)
    cp = choke_point(paths)
    lines.append(f"Found {len(paths)} attack path(s):")
    for i, path in enumerate(paths, 1):
        lines.append(f"\n[{i}] {path.pattern}: {path.render()}")
        if cp and cp.id in [n.id for n in path.nodes[1:-1]]:
            lines.append(
                f"    choke point on this path: {cp.label} "
                f"({paths_through(paths, cp.id)} of {len(paths)} paths pass through it)"
            )
    if cp:
        lines.append(
            f"\nTop choke point: {cp.label} — {paths_through(paths, cp.id)} of "
            f"{len(paths)} paths pass through it. (Full ranking is Phase 3.)"
        )
    if report.unknown_edges:
        lines.append("\nUnknown-confidence edges (shown for transparency, not used):")
        for edge in report.unknown_edges:
            lines.append(f"  {edge.source} --{edge.kind.value}--> {edge.target}: {edge.evidence}")
    return "\n".join(lines)


def _render_json(inventory, report, jewel_ids, paths) -> str:
    cp = choke_point(paths)
    return json.dumps(
        {
            "account": inventory.account_id,
            "region": inventory.region,
            "nodes": report.nodes_added,
            "edges": report.edges_added,
            "unknown_edges": len(report.unknown_edges),
            "crown_jewels": jewel_ids,
            "choke_point": cp.id if cp else None,
            "paths": [
                {
                    "pattern": p.pattern,
                    "crown_jewel": p.crown_jewel.id,
                    "hops": [
                        {
                            "from": e.source,
                            "edge": e.kind.value,
                            "to": e.target,
                            "evidence": e.evidence,
                            "confidence": e.confidence.value,
                        }
                        for e in p.edges
                    ],
                }
                for p in paths
            ],
        },
        indent=2,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="chokepoint",
        description="Chokepoint Phase 1: read-only AWS attack-path finder (P1/P2).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("scan", "list-paths"):
        p = sub.add_parser(name, help="scan an account and find P1/P2 paths")
        p.add_argument("--demo", action="store_true",
                       help="use the bundled demo account (no credentials)")
        p.add_argument("--region", default="us-east-1",
                       help="AWS region to scan (default: us-east-1)")
        p.add_argument("--profile", default=None,
                       help="AWS profile name for a real scan")
        p.add_argument("--postgres", default=None, metavar="DSN",
                       help="store the graph in Postgres instead of memory")
        p.add_argument("--crown-jewel", action="append", default=[],
                       metavar="NODE-ID",
                       help="tag a node id as a crown jewel (repeatable)")
        p.add_argument("--max-depth", type=int, default=8,
                       help="max path length in hops (default: 8)")
        p.add_argument("--output", choices=("text", "json"), default="text")

    args = parser.parse_args(argv)
    if not args.demo and not args.profile and not _aws_credentials_configured():
        print(
            "No AWS credentials found and --demo not given. "
            "Run with --demo, or configure read-only credentials.",
            file=sys.stderr,
        )
        return 2
    inventory, store, report, jewel_ids, paths = _run(args)
    if args.command == "list-paths":
        if args.output == "json":
            print(_render_json(inventory, report, jewel_ids, paths))
        else:
            for i, path in enumerate(paths, 1):
                print(f"[{i}] {path.pattern}: {path.render()}")
            if not paths:
                print("No attack paths found.")
    else:
        if args.output == "json":
            print(_render_json(inventory, report, jewel_ids, paths))
        else:
            print(_render_text(inventory, report, jewel_ids, paths))
    return 0


def _aws_credentials_configured() -> bool:
    """Best-effort check for configured AWS credentials (env or files)."""
    import os  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    if os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_PROFILE"):
        return True
    if os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"):
        return True
    aws_dir = Path.home() / ".aws"
    return (aws_dir / "credentials").exists() or (aws_dir / "config").exists()


if __name__ == "__main__":
    raise SystemExit(main())
