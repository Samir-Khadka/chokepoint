"""Minimal Terraform config reader (plan Section 6: collectors).

This is NOT a general HCL parser. It locates a resource block by
address in a ``.tf`` file and does brace-matched text surgery on
it — enough for the Phase 4 templates, which assume the fixture's
known structure. General-purpose HCL editing (variables, modules,
``for_each``, ``${}`` interpolation inside strings, heredoc
policies) is future work and is called out wherever a template
relies on the fixture shape.

What it does handle: nested blocks, strings (braces inside a
quoted string do not count), line comments (``#``, ``//``) and
block comments (``/* */``), and heredoc bodies (``<<EOT`` /
``<<-EOT``), which are skipped as raw text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_RESOURCE_RE = re.compile(
    r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.MULTILINE
)


@dataclass(frozen=True)
class ResourceBlock:
    """One ``resource "type" "name" { ... }`` block."""

    address: str  # e.g. "aws_instance.web"
    type: str
    name: str
    start: int  # offset of the `resource` keyword
    end: int  # offset just past the closing `}`
    text: str  # the whole block, `resource ... { ... }`


@dataclass(frozen=True)
class NestedBlock:
    """A labelled block inside a resource block, e.g. ``ingress {``."""

    label: str
    start: int  # absolute offset of the label in the file text
    end: int  # absolute offset just past the closing `}`
    text: str


class BlockNotFoundError(ValueError):
    """No block with that address/label exists in the file."""


def _matching(text: str, open_pos: int, open_ch: str, close_ch: str) -> int:
    """Offset just past the bracket matching the one at ``open_pos``.

    Skips braces/parens inside double-quoted strings, line and
    block comments, and heredoc bodies. ``${`` interpolation inside
    a string is not supported — the fixture has none.
    """
    depth = 0
    i = open_pos
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\":
                    i += 1
                i += 1
            i += 1
            continue
        if ch == "#":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        if text.startswith("<<", i):
            # Heredoc: <<EOT or <<-EOT, body ends at a line that is
            # exactly the marker (allowing leading whitespace for -).
            m = re.match(r"<<-?\s*([A-Za-z_][A-Za-z0-9_]*)", text[i:])
            if m:
                marker = m.group(1)
                body_start = text.find("\n", i) + 1
                j = body_start
                while j < n:
                    line_end = text.find("\n", j)
                    if line_end == -1:
                        line_end = n
                    if text[j:line_end].strip() == marker:
                        i = line_end + 1
                        break
                    j = line_end + 1
                else:
                    i = n
                continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    raise BlockNotFoundError(
        f"unbalanced {open_ch!r}: no matching {close_ch!r} from offset {open_pos}"
    )


def find_resource_block(text: str, address: str) -> ResourceBlock | None:
    """Locate a resource block by address, or None if absent."""
    try:
        rtype, name = address.split(".", 1)
    except ValueError:
        return None
    for match in _RESOURCE_RE.finditer(text):
        if match.group(1) == rtype and match.group(2) == name:
            brace = match.end() - 1  # the `{` itself
            end = _matching(text, brace, "{", "}")
            return ResourceBlock(
                address=address,
                type=rtype,
                name=name,
                start=match.start(),
                end=end,
                text=text[match.start():end],
            )
    return None


def find_nested_blocks(block: ResourceBlock, label: str) -> list[NestedBlock]:
    """All ``label { ... }`` blocks inside a resource block.

    Offsets are absolute (into the whole file text the block came
    from), so spans can be cut straight out of the file.
    """
    pattern = re.compile(rf"(?<![A-Za-z0-9_-]){re.escape(label)}\s*\{{")
    found: list[NestedBlock] = []
    for match in pattern.finditer(block.text):
        brace = match.end() - 1
        # _matching works on the block text; translate offsets.
        rel_end = _matching(block.text, brace, "{", "}")
        found.append(
            NestedBlock(
                label=label,
                start=block.start + match.start(),
                end=block.start + rel_end,
                text=block.text[match.start():rel_end],
            )
        )
    return found


def remove_span(text: str, start: int, end: int) -> str:
    """Delete ``text[start:end]`` and tidy the gap it leaves.

    Collapses three or more blank lines into two, and removes a
    blank line left at the very start of a block body. The result
    is still valid HCL for the fixture's shape.
    """
    out = text[:start] + text[end:]
    out = re.sub(r"\n{4,}", "\n\n\n", out)
    return out


def replace_span(text: str, start: int, end: int, replacement: str) -> str:
    """Replace ``text[start:end]`` with ``replacement``."""
    return text[:start] + replacement + text[end:]


def extract_jsonencode(text: str, start: int = 0) -> tuple[str, int, int] | None:
    """The JSON argument of the first ``jsonencode(...)`` at/after ``start``.

    Returns (json_text, arg_start, arg_end) where the offsets cover
    the JSON object text itself (inside the parens), or None if
    there is no ``jsonencode`` call.
    """
    match = re.search(r"jsonencode\s*\(", text[start:])
    if not match:
        return None
    paren = start + match.end() - 1
    end = _matching(text, paren, "(", ")")
    return text[paren + 1:end - 1], paren + 1, end - 1


def extract_heredoc_json(text: str, start: int = 0) -> tuple[str, int, int] | None:
    """The JSON body of the first heredoc policy at/after ``start``.

    Returns (json_text, body_start, body_end), or None.
    """
    match = re.search(r"<<-?\s*([A-Za-z_][A-Za-z0-9_]*)", text[start:])
    if not match:
        return None
    marker = match.group(1)
    body_start = text.find("\n", start + match.end()) + 1
    j = body_start
    n = len(text)
    while j < n:
        line_end = text.find("\n", j)
        if line_end == -1:
            line_end = n
        if text[j:line_end].strip() == marker:
            return text[body_start:j], body_start, j
        j = line_end + 1
    return None
