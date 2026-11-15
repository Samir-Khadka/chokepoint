"""Tests for the fix templates (Phase 4).

Per the plan's safety rules, templates are unit-tested like code,
with a golden-file test per pattern: each template's output on the
demo fixture is frozen in tests/golden/ and asserted exactly, so a
template change is a deliberate golden update, not a silent drift.
"""

import hcl2
import pytest

from chokepoint.fixes import generate_fix
from chokepoint.fixes.templates import (
    NoOpFix,
    UnsupportedFix,
    apply_template,
    select_template,
)
from chokepoint.ranking.candidates import CandidateFix


def _hcl_normalize(value):
    """Strip hcl2 8.x's literal quotes for structural assertions."""
    if isinstance(value, dict):
        return {
            (k[1:-1] if isinstance(k, str) and k.startswith('"') else k): (
                _hcl_normalize(v)
            )
            for k, v in value.items()
            if k != "__is_block__"
        }
    if isinstance(value, list):
        return [_hcl_normalize(v) for v in value]
    if isinstance(value, str) and len(value) >= 2 and value.startswith('"'):
        return value[1:-1]
    return value


def _resources_by_address(tf_text):
    """{address: resource body} from a .tf text, via hcl2."""
    parsed = _hcl_normalize(hcl2.loads(tf_text))
    out = {}
    for entry in parsed.get("resource", []):
        for rtype, named in entry.items():
            for name, body in named.items():
                out[f"{rtype}.{name}"] = body
    return out


def _ranked(demo_ranking, rank):
    return demo_ranking.top_fixes[rank - 1]


# -- template selection ---------------------------------------------------

@pytest.mark.parametrize(
    "rank,template",
    [
        (1, "detach_instance_profile"),
        (2, "narrow_policy_statement"),
        (3, "close_sg_ingress"),
        (4, "make_workload_private"),
        (5, "remove_trust_principal"),
        (6, "narrow_policy_statement"),
        (7, "remove_credential_object"),
        (13, "make_bucket_private"),
    ],
)
def test_select_template(demo_graph, demo_ranking, rank, template):
    scored = _ranked(demo_ranking, rank)
    assert select_template(scored.candidate, demo_graph["store"]) == template


def test_select_template_unknown_edge(demo_graph):
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
    # CAN_DELETE is not a kind any template implements.
    with pytest.raises(UnsupportedFix):
        select_template(candidate, demo_graph["store"])


# -- each template on the fixture ------------------------------------------

def test_detach_template(demo_graph, demo_ranking, demo_fixture):
    main_tf, state = demo_fixture
    scored = _ranked(demo_ranking, 1)
    application = apply_template(
        "detach_instance_profile", scored.candidate, main_tf, state,
        demo_graph["store"],
    )
    resources = _resources_by_address(application.new_tf_text)
    assert "iam_instance_profile" not in resources["aws_instance.web"]
    # The worker instance keeps its profile — the fix is surgical.
    assert "iam_instance_profile" in resources["aws_instance.worker"]
    assert application.changed_addresses == ("aws_instance.web",)
    assert application.exclude_edges == {
        ("ec2:i-web00001", "iam-role:web-role", "has_role")
    }
    hcl2.loads(application.new_tf_text)  # still parses


def test_scope_template_narrows_to_assets(demo_graph, demo_ranking, demo_fixture):
    main_tf, state = demo_fixture
    scored = _ranked(demo_ranking, 2)
    application = apply_template(
        "narrow_policy_statement", scored.candidate, main_tf, state,
        demo_graph["store"],
    )
    resources = _resources_by_address(application.new_tf_text)
    policy = resources["aws_iam_role_policy.web_policy"]["policy"]
    assert "arn:aws:s3:::assets/*" in str(policy)
    assert '"*"' not in str(policy)
    # The narrow write statement is untouched.
    assert application.changed_addresses == ("aws_iam_role_policy.web_policy",)
    assert ("iam-role:web-role", "s3:backups", "can_read") in application.exclude_edges
    assert ("iam-role:web-role", "s3:customer-data", "can_read") in application.exclude_edges
    hcl2.loads(application.new_tf_text)


def test_close_ingress_template(demo_graph, demo_ranking, demo_fixture):
    main_tf, state = demo_fixture
    scored = _ranked(demo_ranking, 3)
    application = apply_template(
        "close_sg_ingress", scored.candidate, main_tf, state,
        demo_graph["store"],
    )
    resources = _resources_by_address(application.new_tf_text)
    assert "ingress" not in resources["aws_security_group.web"]
    assert application.changed_addresses == ("aws_security_group.web",)
    hcl2.loads(application.new_tf_text)


def test_make_workload_private_template(demo_graph, demo_ranking, demo_fixture):
    main_tf, state = demo_fixture
    scored = _ranked(demo_ranking, 4)
    application = apply_template(
        "make_workload_private", scored.candidate, main_tf, state,
        demo_graph["store"],
    )
    resources = _resources_by_address(application.new_tf_text)
    assert "ingress" not in resources["aws_security_group.web"]
    assert resources["aws_instance.web"]["associate_public_ip_address"] is False
    hcl2.loads(application.new_tf_text)


def test_trust_template(demo_graph, demo_ranking, demo_fixture):
    main_tf, state = demo_fixture
    scored = _ranked(demo_ranking, 5)
    application = apply_template(
        "remove_trust_principal", scored.candidate, main_tf, state,
        demo_graph["store"],
    )
    resources = _resources_by_address(application.new_tf_text)
    trust = resources["aws_iam_role.admin_role"]["assume_role_policy"]
    assert "web-role" not in str(trust)
    assert application.changed_addresses == ("aws_iam_role.admin_role",)
    hcl2.loads(application.new_tf_text)


def test_bucket_private_template(demo_graph, demo_ranking, demo_fixture):
    main_tf, state = demo_fixture
    scored = _ranked(demo_ranking, 13)
    application = apply_template(
        "make_bucket_private", scored.candidate, main_tf, state,
        demo_graph["store"],
    )
    resources = _resources_by_address(application.new_tf_text)
    assert "aws_s3_bucket_policy.customer_data" not in resources
    pab = resources["aws_s3_bucket_public_access_block.customer_data"]
    assert pab["block_public_acls"] is True
    assert pab["block_public_policy"] is True
    assert pab["ignore_public_acls"] is True
    assert pab["restrict_public_buckets"] is True
    hcl2.loads(application.new_tf_text)


def test_credential_object_template(demo_graph, demo_ranking, demo_fixture):
    main_tf, state = demo_fixture
    scored = _ranked(demo_ranking, 7)
    application = apply_template(
        "remove_credential_object", scored.candidate, main_tf, state,
        demo_graph["store"],
    )
    resources = _resources_by_address(application.new_tf_text)
    assert "aws_s3_object.db_creds" not in resources
    assert application.exclude_nodes == {"secret:backups:db-creds.json"}
    hcl2.loads(application.new_tf_text)


def test_attached_policy_statement_removed(demo_graph, demo_ranking, demo_fixture):
    """Rank 8: the attached DatabaseConnect statement is removed —
    the role has no narrow grant, so there is nothing to narrow to."""
    main_tf, state = demo_fixture
    scored = _ranked(demo_ranking, 8)
    application = apply_template(
        "narrow_policy_statement", scored.candidate, main_tf, state,
        demo_graph["store"],
    )
    resources = _resources_by_address(application.new_tf_text)
    policy = resources["aws_iam_policy.database_connect"]["policy"]
    assert "rds-db:connect" not in str(policy)
    hcl2.loads(application.new_tf_text)


# -- no-op / unsupported ----------------------------------------------------

def test_already_scoped_role_is_noop(demo_graph, demo_ranking, demo_fixture):
    """Rank 9: admin-role's policies are already scoped — nothing to narrow."""
    main_tf, state = demo_fixture
    scored = _ranked(demo_ranking, 9)
    with pytest.raises(NoOpFix):
        apply_template(
            "narrow_policy_statement", scored.candidate, main_tf, state,
            demo_graph["store"],
        )


def test_already_private_bucket_is_noop(demo_graph, demo_ranking, demo_fixture):
    """Rank 10: the backups bucket is already private."""
    main_tf, state = demo_fixture
    scored = _ranked(demo_ranking, 10)
    with pytest.raises(NoOpFix):
        apply_template(
            "make_bucket_private", scored.candidate, main_tf, state,
            demo_graph["store"],
        )


# -- golden files -----------------------------------------------------------

GOLDEN = [
    (1, "fix-1-detach.tf"),
    (2, "fix-2-scope.tf"),
    (3, "fix-3-close-ingress.tf"),
    (4, "fix-4-make-private.tf"),
    (5, "fix-5-trust.tf"),
    (13, "fix-6-bucket-private.tf"),
]


@pytest.mark.parametrize("rank,filename", GOLDEN)
def test_golden_files(demo_graph, demo_ranking, demo_fixture, rank, filename):
    """A template change is a release: golden outputs must match exactly."""
    from pathlib import Path

    main_tf, state = demo_fixture
    scored = _ranked(demo_ranking, rank)
    generated = generate_fix(
        scored.candidate,
        demo_graph["store"],
        demo_graph["paths"],
        main_tf,
        state,
        scored=scored,
    )
    golden = Path(__file__).with_name("golden") / filename
    assert generated.new_tf_text == golden.read_text()
