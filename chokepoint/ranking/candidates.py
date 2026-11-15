"""Candidate fixes: one edge cut, or one node removed.

A candidate fix is a *graph-level* removal: cut this edge, or
remove this node and its incident edges. It names what to change,
in plain language, with the evidence behind it and a
blast-radius note. It is NOT a validated infrastructure-as-code
change — that is Phase 4. The "what could break" note is a
heuristic derived from the graph evidence only, and it says so:
a human must review it before anything changes.

Candidates are enumerated from the attack paths only: every edge
on at least one path, and every non-entry, non-crown-jewel node
on at least one path. Entry (Internet) and crown jewels are
never candidates — you cannot "fix" the Internet, and removing
what matters is not a fix.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..graph.model import Edge, EdgeKind, Node, NodeKind
from ..paths.patterns import Path

HEURISTIC_NOTE = (
    "Heuristic: this blast-radius guess is derived from the graph "
    "evidence only — a human must review it before changing anything."
)

NOT_A_TF_CHANGE = (
    " This is a graph-level removal: it names the edge or node to cut. "
    "It is not a validated Terraform change — that is Phase 4."
)


@dataclass(frozen=True)
class CandidateFix:
    """One proposed fix, before scoring."""

    id: str  # "edge:<src>-><tgt>:<kind>" or "node:<node-id>"
    kind: str  # "edge" or "node"
    target_id: str  # node id (node fix) or edge target id (edge fix)
    edge_key: tuple[str, str, str] | None  # (source, target, kind) for edge fixes
    title: str
    explanation: str
    evidence: tuple[str, ...]
    what_could_break: str


def _edge_candidate(edge: Edge, labels: dict[str, str]) -> CandidateFix:
    src, tgt = edge.source, edge.target
    src_label, tgt_label = labels.get(src, src), labels.get(tgt, tgt)
    evidence = (edge.evidence,) + (
        (f"ref: {edge.evidence_ref}",) if edge.evidence_ref else ()
    )
    kind = edge.kind
    if kind is EdgeKind.CAN_REACH and src == "internet":
        if tgt.startswith("s3:"):
            title = f"Make {tgt_label} private"
            explanation = (
                f"{tgt_label} allows public reads ({edge.evidence}). "
                "Removing the public grant breaks every attack path "
                "that starts here."
            )
            breaks = (
                f"Legitimate public reads of {tgt_label} stop. "
                f"{HEURISTIC_NOTE}"
            )
        else:
            title = f"Block public access to {tgt_label}"
            explanation = (
                f"{tgt_label} is reachable from the Internet "
                f"({edge.evidence}). Closing the public ingress rule "
                "— or removing its public IP — breaks every attack "
                "path that starts here."
            )
            breaks = (
                f"Legitimate public traffic to {tgt_label} stops until "
                "an alternative entry point (a load balancer, or "
                f"allow-listed IPs) is provided. {HEURISTIC_NOTE}"
            )
    elif kind is EdgeKind.HAS_ROLE:
        title = f"Detach {tgt_label} from {src_label}"
        explanation = (
            f"{src_label} runs with {tgt_label} attached "
            f"({edge.evidence}). Detaching the role breaks every "
            "attack path that rides on its permissions."
        )
        breaks = (
            f"Anything {src_label} does with {tgt_label}'s permissions "
            "fails until a scoped-down role replaces it. "
            f"{HEURISTIC_NOTE}"
        )
    elif kind is EdgeKind.CAN_ASSUME:
        title = f"Stop {src_label} assuming {tgt_label}"
        explanation = (
            f"{tgt_label}'s trust policy lets {src_label} assume it "
            f"({edge.evidence}). Removing that permission breaks "
            "every chain that escalates through it."
        )
        breaks = (
            f"Workflows that assume {tgt_label} through {src_label} "
            f"stop working. {HEURISTIC_NOTE}"
        )
    elif kind is EdgeKind.CAN_READ:
        title = f"Remove {src_label}'s read access to {tgt_label}"
        explanation = (
            f"{src_label} can read {tgt_label} ({edge.evidence}). "
            "Removing that permission breaks every attack path that "
            "reads through it."
        )
        breaks = (
            f"Legitimate reads of {tgt_label} by {src_label} stop. "
            f"{HEURISTIC_NOTE}"
        )
    elif kind is EdgeKind.CAN_WRITE:
        title = f"Remove {src_label}'s write access to {tgt_label}"
        explanation = (
            f"{src_label} can write to {tgt_label} ({edge.evidence}). "
            "Removing that permission breaks every attack path that "
            "writes through it."
        )
        breaks = (
            f"Legitimate writes to {tgt_label} by {src_label} stop. "
            f"{HEURISTIC_NOTE}"
        )
    elif kind is EdgeKind.CAN_ADMIN:
        if src.startswith("secret:"):
            title = f"Rotate the credential stored in {src_label}"
            explanation = (
                f"The credential {src_label} grants access to "
                f"{tgt_label} ({edge.evidence}). Rotating it breaks "
                "every attack path that uses the stored credential."
            )
            breaks = (
                "Systems using the old credential stop working until "
                f"they are updated to the new one. {HEURISTIC_NOTE}"
            )
        else:
            title = f"Remove {src_label}'s admin access to {tgt_label}"
            explanation = (
                f"{src_label} has admin access to {tgt_label} "
                f"({edge.evidence}). Removing it breaks every attack "
                "path that administers through it."
            )
            breaks = (
                f"Legitimate admin operations on {tgt_label} by "
                f"{src_label} stop. {HEURISTIC_NOTE}"
            )
    elif kind is EdgeKind.CONTAINS_CRED:
        title = f"Remove the credential object from {src_label}"
        explanation = (
            f"{src_label} holds credentials for {tgt_label} "
            f"({edge.evidence}). Removing the object breaks every "
            "attack path that uses the stored credential."
        )
        breaks = (
            "Anything that reads this credential from the bucket stops "
            "working until the credential is re-provisioned elsewhere; "
            f"rotate the credential as well. {HEURISTIC_NOTE}"
        )
    else:  # pragma: no cover - every EdgeKind is handled above
        title = f"Remove {kind.value} from {src_label} to {tgt_label}"
        explanation = f"{src_label} --{kind.value}--> {tgt_label} ({edge.evidence})."
        breaks = f"Legitimate use of this access stops. {HEURISTIC_NOTE}"

    return CandidateFix(
        id=f"edge:{src}->{tgt}:{kind.value}",
        kind="edge",
        target_id=tgt,
        edge_key=(src, tgt, kind.value),
        title=title,
        explanation=explanation + NOT_A_TF_CHANGE,
        evidence=evidence,
        what_could_break=breaks,
    )


def _node_candidate(
    node: Node, path_count: int, incident_evidence: list[str]
) -> CandidateFix:
    label = node.label
    if node.kind is NodeKind.WORKLOAD:
        title = f"Make {label} private"
        explanation = (
            f"{label} is a public entry point on {path_count} attack "
            "path(s). Removing its public IP — or closing its public "
            "ingress — disconnects every path that starts here."
        )
        breaks = (
            f"Legitimate public traffic to {label} stops until an "
            "alternative entry point is provided. "
            f"{HEURISTIC_NOTE}"
        )
    elif node.kind is NodeKind.IDENTITY:
        title = f"Scope down or remove {label}"
        explanation = (
            f"{label} sits on {path_count} attack path(s). Its "
            "permissions are the bridge between the entry point and "
            "the crown jewel(s): scoping it to only the permissions "
            "it actually needs breaks those paths."
        )
        breaks = (
            "Everything that relies on this role's permissions stops "
            f"until a narrower role replaces it. {HEURISTIC_NOTE}"
        )
    elif node.kind is NodeKind.DATASTORE:
        title = f"Make {label} private"
        explanation = (
            f"{label} sits on {path_count} attack path(s). Removing "
            "the over-broad access to it disconnects every path "
            "that passes through it."
        )
        breaks = (
            f"Legitimate readers of {label} lose access. "
            f"{HEURISTIC_NOTE}"
        )
    elif node.kind is NodeKind.SECRET:
        title = f"Rotate and remove the stored credential {label}"
        explanation = (
            f"{label} sits on {path_count} attack path(s). Rotating "
            "it and removing the stored copy breaks every path that "
            "uses it."
        )
        breaks = (
            "Systems using this credential stop working until they "
            f"are updated to the new one. {HEURISTIC_NOTE}"
        )
    else:  # pragma: no cover - NetworkEntry nodes carry no paths yet
        title = f"Restrict {label}"
        explanation = f"{label} sits on {path_count} attack path(s)."
        breaks = f"Legitimate use of {label} may stop. {HEURISTIC_NOTE}"

    return CandidateFix(
        id=f"node:{node.id}",
        kind="node",
        target_id=node.id,
        edge_key=None,
        title=title,
        explanation=explanation + NOT_A_TF_CHANGE,
        evidence=tuple(sorted(set(incident_evidence))),
        what_could_break=breaks,
    )


def enumerate_candidates(paths: list[Path]) -> list[CandidateFix]:
    """Every edge and every intermediate node on at least one path.

    The Internet (entry) and crown jewels are never candidates.
    """
    labels: dict[str, str] = {}
    edge_by_key: dict[tuple[str, str, str], Edge] = {}
    node_by_id: dict[str, Node] = {}
    node_path_count: dict[str, int] = {}
    node_evidence: dict[str, list[str]] = {}
    for path in paths:
        for node in path.nodes:
            labels[node.id] = node.label
        for edge in path.edges:
            edge_by_key[(edge.source, edge.target, edge.kind.value)] = edge
        for node in path.nodes[1:-1]:
            node_by_id[node.id] = node
            node_path_count[node.id] = node_path_count.get(node.id, 0) + 1
            node_evidence.setdefault(node.id, []).extend(
                edge.evidence for edge in path.edges
            )

    candidates = [
        _edge_candidate(edge, labels) for edge in edge_by_key.values()
    ]
    candidates.extend(
        _node_candidate(node_by_id[node_id], node_path_count[node_id],
                        node_evidence[node_id])
        for node_id in node_by_id
    )
    return candidates
