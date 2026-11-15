"""Tests for the narrow IAM policy evaluator (graph/iam_eval.py).

The evaluator is the accuracy-critical piece: a wrong Allow invents
a path, a wrong Deny hides one. Every branch of the subset is
covered, including the unknown-confidence escapes.
"""

from chokepoint.graph.iam_eval import (
    EvalResult,
    policy_allows,
    role_can,
    trust_allows_assume,
)
from chokepoint.collectors.records import IAMRole
from chokepoint.graph.model import Confidence

WEB_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "OverBroadRead",
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*",
        },
        {
            "Sid": "NarrowWrite",
            "Effect": "Allow",
            "Action": "s3:PutObject",
            "Resource": "arn:aws:s3:::assets/*",
        },
    ],
}


def test_allow_wildcard_resource():
    r = policy_allows(WEB_POLICY, "s3:GetObject", "arn:aws:s3:::backups/db-creds.json")
    assert r.allowed is True
    assert r.confidence is Confidence.PROVEN
    assert "statement 0" in r.reason


def test_allow_wildcard_action_case_insensitive():
    r = policy_allows(WEB_POLICY, "S3:getobject", "arn:aws:s3:::x/y")
    assert r.allowed is True


def test_action_not_covered():
    r = policy_allows(WEB_POLICY, "s3:DeleteObject", "arn:aws:s3:::assets/x")
    assert r.allowed is False
    assert r.confidence is Confidence.PROVEN


def test_resource_not_covered():
    r = policy_allows(WEB_POLICY, "s3:PutObject", "arn:aws:s3:::backups/x")
    assert r.allowed is False


def test_explicit_deny_wins_over_allow():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "*"},
            {
                "Effect": "Deny",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::backups/*",
            },
        ],
    }
    r = policy_allows(policy, "s3:GetObject", "arn:aws:s3:::backups/db-creds.json")
    assert r.allowed is False
    assert "explicit Deny" in r.reason
    r2 = policy_allows(policy, "s3:PutObject", "arn:aws:s3:::backups/x")
    assert r2.allowed is True  # deny was scoped to GetObject only


def test_not_action_is_unknown():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
        ],
    }
    r = policy_allows(policy, "s3:GetObject", "arn:aws:s3:::x")
    assert r.confidence is Confidence.UNKNOWN
    assert r.allowed is False


def test_unsupported_condition_is_unknown():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
            },
        ],
    }
    r = policy_allows(policy, "s3:GetObject", "arn:aws:s3:::x")
    assert r.confidence is Confidence.UNKNOWN


def test_principal_arn_condition_matching():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalArn": "arn:aws:iam::123456789012:role/web-role"
                    }
                },
            },
        ],
    }
    ok = policy_allows(
        policy, "s3:GetObject", "arn:aws:s3:::x",
        principal_arn="arn:aws:iam::123456789012:role/web-role",
    )
    assert ok.allowed is True
    assert ok.confidence is Confidence.PROVEN
    no = policy_allows(
        policy, "s3:GetObject", "arn:aws:s3:::x",
        principal_arn="arn:aws:iam::123456789012:role/other-role",
    )
    assert no.allowed is False
    assert no.confidence is Confidence.PROVEN


def test_empty_policy_denies():
    assert policy_allows({}, "s3:GetObject", "arn:aws:s3:::x").allowed is False
    assert policy_allows(None, "s3:GetObject", "arn:aws:s3:::x").allowed is False


# --- trust policies ---------------------------------------------------------

TRUST_EC2 = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

TRUST_WEB_ROLE = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:role/web-role"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def test_trust_allows_role_principal():
    r = trust_allows_assume(
        TRUST_WEB_ROLE, "arn:aws:iam::123456789012:role/web-role"
    )
    assert r.allowed is True
    r2 = trust_allows_assume(
        TRUST_WEB_ROLE, "arn:aws:iam::123456789012:role/other-role"
    )
    assert r2.allowed is False


def test_service_principal_does_not_match_role_arn():
    # ec2.amazonaws.com lets the EC2 service assume the role, not an
    # IAM role ARN. A role-to-role edge must not be drawn from it.
    r = trust_allows_assume(
        TRUST_EC2, "arn:aws:iam::123456789012:role/web-role"
    )
    assert r.allowed is False


def test_trust_star_principal():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}
        ],
    }
    assert trust_allows_assume(
        policy, "arn:aws:iam::123456789012:role/anything"
    ).allowed is True


# --- role_can with permission boundaries -------------------------------------

def _role(policies, boundary=None):
    return IAMRole(
        name="test-role",
        arn="arn:aws:iam::123456789012:role/test-role",
        policies=tuple(policies),
        permission_boundary=boundary,
    )


def test_role_can_allow():
    role = _role([("inline:p", WEB_POLICY)])
    result, evidence = role_can(role, "s3:GetObject", "arn:aws:s3:::backups/x")
    assert result.allowed is True
    assert "inline:p" in evidence


def test_role_can_boundary_blocks():
    boundary = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject",
             "Resource": "arn:aws:s3:::assets/*"},
        ],
    }
    role = _role([("inline:p", WEB_POLICY)], boundary=boundary)
    result, _ = role_can(role, "s3:GetObject", "arn:aws:s3:::backups/x")
    assert result.allowed is False
    assert "boundary" in result.reason
    ok, _ = role_can(role, "s3:GetObject", "arn:aws:s3:::assets/x")
    assert ok.allowed is True


def test_role_can_boundary_unknown():
    boundary = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*",
             "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}},
        ],
    }
    role = _role([("inline:p", WEB_POLICY)], boundary=boundary)
    result, _ = role_can(role, "s3:GetObject", "arn:aws:s3:::backups/x")
    assert result.confidence is Confidence.UNKNOWN
    assert result.allowed is False


def test_role_can_explicit_deny_in_one_policy_wins():
    deny = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Deny", "Action": "s3:GetObject",
             "Resource": "arn:aws:s3:::backups/*"},
        ],
    }
    role = _role([("inline:allow", WEB_POLICY), ("inline:deny", deny)])
    result, _ = role_can(role, "s3:GetObject", "arn:aws:s3:::backups/x")
    assert result.allowed is False
