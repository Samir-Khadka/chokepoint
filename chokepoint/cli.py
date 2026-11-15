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
from .ranking import rank_fixes


def _add_scan_args(p):
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
            f"{len(paths)} paths pass through it. "
            "(See `top-fixes` for the ranked fix list.)"
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


def _render_top_fixes_text(inventory, jewel_ids, paths, ranking) -> str:
    lines = [
        f"Chokepoint top fixes — account {inventory.account_id or '(demo)'} "
        f"region {inventory.region}",
        f"{ranking.total_paths} attack path(s) to {len(jewel_ids)} crown jewel(s). "
        "Fixes are graph-level removals, not validated Terraform changes "
        "(Phase 4). Review before changing anything.",
        "",
    ]
    if ranking.total_paths == 0:
        lines.append("No attack paths found — nothing to rank.")
        return "\n".join(lines)
    lines.append(
        "Top fixes (ranked by paths removed, then path-graph betweenness):"
    )
    for i, fix in enumerate(ranking.top_fixes, 1):
        cand = fix.candidate
        lines.append(
            f"\n[{i}] {cand.title} — removes {fix.paths_removed} of "
            f"{ranking.total_paths} path(s)"
        )
        if fix.crown_jewels_protected:
            lines.append(
                "    Protects: "
                + ", ".join(fix.crown_jewels_protected)
                + " (every path to it is removed)"
            )
        lines.append(f"    Why: {cand.explanation}")
        for ev in cand.evidence:
            lines.append(f"    Evidence: {ev}")
        lines.append(f"    What could break: {cand.what_could_break}")
    chosen = ranking.disconnecting_set
    if ranking.disconnects_all:
        lines.append(
            f"\nMinimum disconnecting set (greedy approximation, not an "
            f"exact minimum cut): {len(chosen)} fix(es) disconnect all "
            f"{ranking.total_paths} paths:"
        )
    else:
        lines.append(
            f"\nNo full disconnecting set found: {len(chosen)} fix(es) "
            f"disconnect some, but not all, of the "
            f"{ranking.total_paths} paths:"
        )
    for i, fix in enumerate(chosen, 1):
        lines.append(
            f"  {i}. {fix.candidate.title} "
            f"(removes {fix.paths_removed} path(s))"
        )
    return "\n".join(lines)


def _render_top_fixes_json(inventory, jewel_ids, paths, ranking) -> str:
    def _fix_dict(rank, fix):
        cand = fix.candidate
        return {
            "rank": rank,
            "id": cand.id,
            "kind": cand.kind,
            "title": cand.title,
            "explanation": cand.explanation,
            "evidence": list(cand.evidence),
            "what_could_break": cand.what_could_break,
            "paths_removed": fix.paths_removed,
            "paths_remaining": ranking.total_paths - fix.paths_removed,
            "crown_jewels_protected": list(fix.crown_jewels_protected),
            "betweenness": fix.betweenness,
            "removed_paths": [
                {"pattern": paths[i].pattern,
                 "crown_jewel": paths[i].crown_jewel.id}
                for i in fix.removed_path_indexes
            ],
        }

    return json.dumps(
        {
            "account": inventory.account_id,
            "region": inventory.region,
            "total_paths": ranking.total_paths,
            "crown_jewels": jewel_ids,
            "top_fixes": [
                _fix_dict(i, fix)
                for i, fix in enumerate(ranking.top_fixes, 1)
            ],
            "minimum_disconnecting_set": {
                "count": len(ranking.disconnecting_set),
                "disconnects_all": ranking.disconnects_all,
                "fixes": [
                    {
                        "id": fix.candidate.id,
                        "title": fix.candidate.title,
                        "paths_removed": fix.paths_removed,
                    }
                    for fix in ranking.disconnecting_set
                ],
            },
        },
        indent=2,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="chokepoint",
        description="Chokepoint: read-only AWS attack-path finder — "
                    "scan, list paths, rank choke-point fixes (Phase 3).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("scan", "list-paths"):
        p = sub.add_parser(name, help="scan an account and find P1/P2 paths")
        _add_scan_args(p)

    p = sub.add_parser(
        "top-fixes",
        help="rank the top choke-point fixes by paths removed",
    )
    _add_scan_args(p)
    p.add_argument("--top", type=int, default=5,
                   help="how many top fixes to show (default: 5)")

    args = parser.parse_args(argv)
    if not args.demo and not args.profile and not _aws_credentials_configured():
        print(
            "No AWS credentials found and --demo not given. "
            "Run with --demo, or configure read-only credentials.",
            file=sys.stderr,
        )
        return 2
    inventory, store, report, jewel_ids, paths = _run(args)
    if args.command == "top-fixes":
        ranking = rank_fixes(store, paths, top=args.top,
                             max_depth=args.max_depth)
        if args.output == "json":
            print(_render_top_fixes_json(inventory, jewel_ids, paths, ranking))
        else:
            print(_render_top_fixes_text(inventory, jewel_ids, paths, ranking))
        return 0
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
