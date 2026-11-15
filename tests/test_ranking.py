"""Tests for Phase 3 choke-point ranking.

Hand-computed expectations on the demo account (4 paths):
paths 1-3 all pass through role/web-role and the public instance;
path 4 is the direct P2 hop Internet -> customer-data.

* Top fix removes 3 paths and involves web-role.
* Greedy set cover disconnects all 4 paths with 2 fixes.
* Path-graph betweenness (Brandes, directed): web-role node 9.0,
  ec2 node 5.0; ec2->web-role edge 11.0 (the highest edge value).
"""

from chokepoint.demo import load_demo_inventory
from chokepoint.graph.builder import build_graph
from chokepoint.graph.memory import InMemoryGraphStore
from chokepoint.graph.model import Node
from chokepoint.paths.crown_jewels import suggest_crown_jewels
from chokepoint.paths.patterns import find_paths
from chokepoint.ranking import rank_fixes, score_candidate
from chokepoint.ranking.candidates import CandidateFix
from chokepoint.ranking.centrality import betweenness


def _demo_store_and_paths():
    store = InMemoryGraphStore()
    build_graph(load_demo_inventory(), store)
    for node_id in suggest_crown_jewels(load_demo_inventory()):
        node = store.get_node(node_id)
        if node is not None:
            store.add_node(
                Node(id=node.id, kind=node.kind, label=node.label,
                     attributes=node.attributes, crown_jewel=True)
            )
    return store, find_paths(store)


def test_top_fix_removes_three_paths_and_involves_web_role():
    store, paths = _demo_store_and_paths()
    ranking = rank_fixes(store, paths)
    assert len(ranking.top_fixes) == 5
    top = ranking.top_fixes[0]
    assert top.paths_removed == 3
    assert "web-role" in top.candidate.id
    assert "web-role" in top.candidate.title
    assert top.crown_jewels_protected == ("rds:prod-db",)


def test_top_five_order_is_paths_removed_then_betweenness():
    store, paths = _demo_store_and_paths()
    ranking = rank_fixes(store, paths)
    removed = [fix.paths_removed for fix in ranking.top_fixes]
    assert removed == [3, 3, 3, 3, 1]
    # The 3-path fixes are ordered by betweenness: has_role edge
    # (11.0) > web-role node (9.0) > can_reach edge (6.0) > ec2 node (5.0).
    assert [fix.betweenness for fix in ranking.top_fixes[:4]] == [
        11.0, 9.0, 6.0, 5.0,
    ]
    assert ranking.top_fixes[0].candidate.kind == "edge"
    assert ranking.top_fixes[1].candidate.kind == "node"


def test_greedy_set_disconnects_all_paths_with_two_fixes():
    store, paths = _demo_store_and_paths()
    ranking = rank_fixes(store, paths)
    assert ranking.total_paths == 4
    assert ranking.disconnects_all
    assert len(ranking.disconnecting_set) == 2
    covered = set()
    for fix in ranking.disconnecting_set:
        covered.update(fix.removed_path_indexes)
    assert covered == {0, 1, 2, 3}


def test_betweenness_matches_hand_computation():
    _store, paths = _demo_store_and_paths()
    node_b, edge_b = betweenness(paths)
    assert node_b["iam-role:web-role"] == 9.0
    assert node_b["ec2:i-web00001"] == 5.0
    assert node_b["iam-role:web-role"] > node_b["ec2:i-web00001"]
    assert edge_b[("ec2:i-web00001", "iam-role:web-role", "has_role")] == 11.0
    assert edge_b[("internet", "s3:customer-data", "can_reach")] == 1.0


def test_decoy_candidate_removes_zero_paths_and_never_ranks():
    store, paths = _demo_store_and_paths()
    # orphan-role has s3:* on * but no way in: its edges touch only
    # decoy resources. Score a hand-built candidate for one of them.
    decoy = CandidateFix(
        id="edge:iam-role:orphan-role->s3:assets:can_admin",
        kind="edge",
        target_id="s3:assets",
        edge_key=("iam-role:orphan-role", "s3:assets", "can_admin"),
        title="Remove orphan-role's admin access to s3://assets",
        explanation="Decoy candidate for the test.",
        evidence=("s3:* on *",),
        what_could_break="Nothing on any attack path.",
    )
    scored = score_candidate(store, paths, decoy)
    assert scored.paths_removed == 0
    assert scored.removed_path_indexes == ()
    assert scored.crown_jewels_protected == ()
    ranking = rank_fixes(store, paths)
    assert all(fix.candidate.id != decoy.id for fix in ranking.top_fixes)
    assert all(
        fix.candidate.id != decoy.id for fix in ranking.disconnecting_set
    )


def test_ranking_is_deterministic():
    store, paths = _demo_store_and_paths()
    first = rank_fixes(store, paths)
    second = rank_fixes(store, paths)
    assert [f.candidate.id for f in first.top_fixes] == [
        f.candidate.id for f in second.top_fixes
    ]
    assert [f.paths_removed for f in first.top_fixes] == [
        f.paths_removed for f in second.top_fixes
    ]
    assert [f.candidate.id for f in first.disconnecting_set] == [
        f.candidate.id for f in second.disconnecting_set
    ]


def test_empty_paths_rank_nothing():
    store = InMemoryGraphStore()
    build_graph(load_demo_inventory(), store)
    assert find_paths(store) == []
    ranking = rank_fixes(store, [])
    assert ranking.total_paths == 0
    assert ranking.top_fixes == ()
    assert ranking.disconnecting_set == ()
    assert ranking.disconnects_all


def test_top_n_limits_output():
    store, paths = _demo_store_and_paths()
    ranking = rank_fixes(store, paths, top=2)
    assert len(ranking.top_fixes) == 2
    # The disconnecting set is computed over all candidates, not
    # just the shown top N.
    assert ranking.disconnects_all
    assert len(ranking.disconnecting_set) == 2


def test_every_fix_carries_explanation_evidence_and_break_note():
    store, paths = _demo_store_and_paths()
    ranking = rank_fixes(store, paths)
    for fix in ranking.top_fixes:
        cand = fix.candidate
        assert cand.explanation
        assert "not a validated Terraform change" in cand.explanation
        assert cand.evidence
        assert "Heuristic" in cand.what_could_break
        assert "human must review" in cand.what_could_break
