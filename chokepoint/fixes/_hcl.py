"""HCL helpers for the fix templates (Phase 4, read-only analysis).

Two jobs, kept separate on purpose:

* **Locate** policy arguments in a ``.tf`` block (``jsonencode`` or
  heredoc) and splice new text back in — done with the same
  brace-matching scanner as :mod:`chokepoint.terraform.config`,
  so the templates never reformat a whole file.
* **Read** a policy document as data, via python-hcl2 — used only
  to decide *what* to change (which statements are over-broad,
  which buckets are legitimately used). hcl2 8.x returns keys and
  string values with their literal quotes attached, so everything
  is normalised here; the templates never write hcl2 output back
  into a file.

Nothing in this module writes infrastructure. It only reads text.
"""

from __future__ import annotations

import re

import hcl2

from ..terraform.config import _matching as _match_bracket


def matching_brace(text: str, open_pos: int) -> int:
    """Offset just past the ``}`` matching the ``{`` at ``open_pos``."""
    return _match_bracket(text, open_pos, "{", "}")


def policy_argument(block_text: str) -> tuple[str, int, int] | None:
    """The policy argument of a block: (text, start, end).

    Handles ``policy = jsonencode({...})`` /
    ``assume_role_policy = jsonencode({...})`` and heredoc
    policies (``policy = <<EOT ... EOT``). Offsets cover the JSON
    text itself, inside the parens / heredoc markers, relative to
    ``block_text``. Returns None when the block has no policy.
    """
    match = re.search(
        r"(?:policy|assume_role_policy)\s*=\s*jsonencode\s*\(",
        block_text,
    )
    if match:
        paren = match.end() - 1
        end = _match_bracket(block_text, paren, "(", ")")
        return block_text[paren + 1:end - 1], paren + 1, end - 1
    match = re.search(
        r"(?:policy|assume_role_policy)\s*=\s*<<-?\s*([A-Za-z_][A-Za-z0-9_]*)",
        block_text,
    )
    if match:
        marker = match.group(1)
        body_start = block_text.find("\n", match.end()) + 1
        j = body_start
        n = len(block_text)
        while j < n:
            line_end = block_text.find("\n", j)
            if line_end == -1:
                line_end = n
            if block_text[j:line_end].strip() == marker:
                return block_text[body_start:j], body_start, j
            j = line_end + 1
    return None


def policy_argument_text(block_text: str) -> str | None:
    """Just the policy argument text of a block, or None."""
    found = policy_argument(block_text)
    return found[0] if found else None


def _normalize(value):
    """Strip hcl2 8.x's literal quotes from keys and string values."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if isinstance(key, str) and len(key) >= 2 and key.startswith('"'):
                key = key[1:-1]
            out[key] = _normalize(item)
        return out
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, str) and len(value) >= 2 and value.startswith('"'):
        return value[1:-1]
    return value


def policy_document(block_text: str) -> dict | None:
    """The policy of a block as a dict, or None if unreadable.

    Parses the ``jsonencode`` argument (or heredoc body) with
    hcl2 and normalises the result. Returns None — never raises —
    when the block has no policy or the policy does not parse, so
    the caller can refuse the fix instead of guessing.
    """
    found = policy_argument(block_text)
    if found is None:
        return None
    arg_text = found[0]
    try:
        parsed = hcl2.loads(f"_policy = {arg_text}")
    except Exception:
        return None
    policy = _normalize(parsed).get("_policy")
    return policy if isinstance(policy, dict) else None


def statements(policy: dict) -> list[dict]:
    """The policy's Statement list as dicts (empty when absent)."""
    raw = policy.get("Statement", [])
    if isinstance(raw, dict):
        return [raw]
    return [s for s in raw if isinstance(s, dict)]


def replace_policy_argument(block_text: str, new_arg_text: str) -> str:
    """Splice new policy argument text into a block."""
    found = policy_argument(block_text)
    if found is None:
        raise ValueError("block has no policy argument to replace")
    _, start, end = found
    return block_text[:start] + new_arg_text + block_text[end:]
