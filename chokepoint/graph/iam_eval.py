"""Narrow, heavily tested IAM policy evaluator (plan Section 6).

This is the deliberately small subset Phase 1 evaluates:

* identity policies (attached managed + inline) and resource policies
* trust policies (``sts:AssumeRole``)
* permission boundaries

Anything outside the subset is reported as ``confidence=unknown``,
never silently assumed allowed or denied. Unsupported constructs
that force an ``unknown`` verdict:

* ``NotAction`` / ``NotResource`` in a statement
* ``Condition`` blocks other than a bare ``StringEquals`` on
  ``aws:PrincipalArn`` matching the evaluated principal
* a permission boundary whose own evaluation is ``unknown``

Action matching is case-insensitive with ``*``/``?`` wildcards
(AWS semantics); resource matching is case-sensitive with the same
wildcards. An explicit ``Deny`` always wins over ``Allow``.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass

from .model import Confidence


@dataclass(frozen=True)
class EvalResult:
    allowed: bool
    confidence: Confidence
    reason: str


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def _action_matches(pattern: str, action: str) -> bool:
    return fnmatch.fnmatchcase(action.lower(), pattern.lower())


def _resource_matches(pattern: str, resource: str) -> bool:
    return fnmatch.fnmatchcase(resource, pattern)


def _statement_matches(
    stmt: dict, action: str, resource: str
) -> tuple[bool, Confidence, str]:
    """Does this statement apply to (action, resource)?

    Returns (matches, confidence, reason). ``matches`` is True only
    when the statement's Action and Resource both cover the request.
    """
    if "NotAction" in stmt or "NotResource" in stmt:
        return False, Confidence.UNKNOWN, "NotAction/NotResource not evaluated"
    actions = _as_list(stmt.get("Action"))
    resources = _as_list(stmt.get("Resource"))
    if not actions or not resources:
        return False, Confidence.UNKNOWN, "statement lacks Action or Resource"
    if not any(_action_matches(p, action) for p in actions):
        return False, Confidence.PROVEN, "action not in statement"
    if not any(_resource_matches(p, resource) for p in resources):
        return False, Confidence.PROVEN, "resource not in statement"
    return True, Confidence.PROVEN, "statement covers action and resource"


def _condition_supported(stmt: dict, principal_arn: str | None) -> tuple[bool, Confidence, str]:
    """Check a statement's Condition block.

    No Condition -> supported. A Condition containing only
    ``StringEquals`` on ``aws:PrincipalArn`` that matches the
    principal -> supported. Anything else -> unknown.
    """
    cond = stmt.get("Condition")
    if not cond:
        return True, Confidence.PROVEN, ""
    if set(cond.keys()) != {"StringEquals"}:
        return False, Confidence.UNKNOWN, f"unsupported Condition keys: {sorted(cond)}"
    equals = cond["StringEquals"]
    if set(equals.keys()) != {"aws:PrincipalArn"}:
        return False, Confidence.UNKNOWN, "unsupported StringEquals condition key"
    if principal_arn is None:
        return False, Confidence.UNKNOWN, "PrincipalArn condition needs a principal"
    values = _as_list(equals["aws:PrincipalArn"])
    if any(_resource_matches(v, principal_arn) for v in values):
        return True, Confidence.PROVEN, ""
    return False, Confidence.PROVEN, "PrincipalArn condition does not match"


def policy_allows(
    policy_doc: dict | None,
    action: str,
    resource: str,
    principal_arn: str | None = None,
) -> EvalResult:
    """Evaluate one policy document for (action, resource).

    Returns allowed=True only when an Allow statement covers the
    request and no matching Deny exists. If any relevant statement
    cannot be evaluated, confidence is ``unknown``.
    """
    if not policy_doc:
        return EvalResult(False, Confidence.PROVEN, "no policy document")
    statements = _as_list(policy_doc.get("Statement"))
    allowed = False
    allow_stmt: int | None = None
    unknown = False
    unknown_reason = ""
    for i, stmt in enumerate(statements):
        effect = str(stmt.get("Effect", "")).lower()
        matches, conf, reason = _statement_matches(stmt, action, resource)
        if conf is Confidence.UNKNOWN:
            # The statement might cover the request; we cannot tell.
            unknown = True
            unknown_reason = f"statement {i}: {reason}"
            continue
        if not matches:
            continue
        ok, _, cond_reason = _condition_supported(stmt, principal_arn)
        if not ok:
            if cond_reason.startswith("unsupported"):
                unknown = True
                unknown_reason = f"statement {i}: {cond_reason}"
            continue
        if effect == "deny":
            return EvalResult(False, Confidence.PROVEN, f"explicit Deny in statement {i}")
        if effect == "allow":
            allowed = True
            allow_stmt = i
    if allowed:
        return EvalResult(
            True,
            Confidence.PROVEN,
            f"Allow statement {allow_stmt} covers action and resource",
        )
    if unknown:
        return EvalResult(False, Confidence.UNKNOWN, unknown_reason)
    return EvalResult(False, Confidence.PROVEN, "no Allow statement covers action and resource")


def trust_allows_assume(trust_doc: dict | None, principal_arn: str) -> EvalResult:
    """Does a role trust policy let ``principal_arn`` assume the role?

    Evaluates ``sts:AssumeRole`` against the trust policy's Principal
    entries (ARN, service, or "*"). Conditions other than a bare
    ``StringEquals`` on ``aws:PrincipalArn`` yield ``unknown``.
    """
    if not trust_doc:
        return EvalResult(False, Confidence.PROVEN, "no trust policy")
    statements = _as_list(trust_doc.get("Statement"))
    allowed = False
    unknown = False
    unknown_reason = ""
    for i, stmt in enumerate(statements):
        if str(stmt.get("Effect", "")).lower() != "allow":
            continue
        actions = _as_list(stmt.get("Action"))
        if not actions or not any(
            _action_matches(a, "sts:AssumeRole") for a in actions
        ):
            continue
        principal = stmt.get("Principal", {})
        principals: list[str] = []
        if isinstance(principal, str):
            principals = [principal]
        elif isinstance(principal, dict):
            for key in ("AWS", "Service", "Federated"):
                principals.extend(_as_list(principal.get(key)))
        matched = False
        for p in principals:
            if p == "*":
                matched = True
            elif p.startswith("arn:"):
                matched = _resource_matches(p, principal_arn)
            else:
                # Service principal such as ec2.amazonaws.com: only
                # matches a service principal, never an IAM ARN.
                matched = False
        if not matched:
            continue
        ok, conf, cond_reason = _condition_supported(stmt, principal_arn)
        if not ok:
            if cond_reason.startswith("unsupported"):
                unknown = True
                unknown_reason = f"trust statement {i}: {cond_reason}"
            continue
        allowed = True
    if allowed:
        return EvalResult(True, Confidence.PROVEN, "trust policy allows assumption")
    if unknown:
        return EvalResult(False, Confidence.UNKNOWN, unknown_reason)
    return EvalResult(False, Confidence.PROVEN, "trust policy does not allow this principal")


def role_can(role, action: str, resource: str) -> tuple[EvalResult, str]:
    """Can an IAM role perform ``action`` on ``resource``?

    Evaluates every attached + inline policy document, then applies
    the permission boundary as an additional gate (a boundary that
    does not allow the action denies it). Returns ``(result,
    evidence)`` where evidence names the policy that decided it.
    """
    from ..collectors.records import IAMRole  # local import: no cycle

    assert isinstance(role, IAMRole)
    allowed = False
    allow_evidence = ""
    unknown = False
    unknown_reason = ""
    for policy_name, doc in role.policies:
        result = policy_allows(doc, action, resource, principal_arn=role.arn)
        if result.confidence is Confidence.UNKNOWN:
            unknown = True
            unknown_reason = f"{policy_name}: {result.reason}"
            continue
        if not result.allowed and "explicit Deny" in result.reason:
            return (
                EvalResult(False, Confidence.PROVEN, result.reason),
                f"{policy_name} {result.reason}",
            )
        if result.allowed:
            allowed = True
            allow_evidence = f"{policy_name} {result.reason}"
    if role.permission_boundary is not None:
        boundary = policy_allows(
            role.permission_boundary, action, resource, principal_arn=role.arn
        )
        if boundary.confidence is Confidence.UNKNOWN:
            return (
                EvalResult(False, Confidence.UNKNOWN, "permission boundary unevaluated"),
                "permission boundary could not be evaluated",
            )
        if not boundary.allowed:
            return (
                EvalResult(False, Confidence.PROVEN, "permission boundary does not allow"),
                "permission boundary does not allow this action",
            )
    if allowed:
        return EvalResult(True, Confidence.PROVEN, "allowed by role policies"), allow_evidence
    if unknown:
        return EvalResult(False, Confidence.UNKNOWN, unknown_reason), unknown_reason
    return (
        EvalResult(False, Confidence.PROVEN, "no role policy allows this action"),
        "no role policy allows this action",
    )
