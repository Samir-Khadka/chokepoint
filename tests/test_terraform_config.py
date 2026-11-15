"""Tests for the minimal .tf config reader (Phase 4).

The reader is fixture-scoped by design: it locates blocks and
does brace-matched surgery, it is not a general HCL parser. The
tests pin the behaviours the templates rely on.
"""

import pytest

from chokepoint.demo import load_demo_terraform
from chokepoint.terraform import (
    BlockNotFoundError,
    extract_heredoc_json,
    extract_jsonencode,
    find_nested_blocks,
    find_resource_block,
    remove_span,
    replace_span,
)
from chokepoint.fixes import _hcl as hcl


@pytest.fixture(scope="module")
def main_tf():
    text, _ = load_demo_terraform()
    return text


def test_find_resource_block(main_tf):
    block = find_resource_block(main_tf, "aws_instance.web")
    assert block is not None
    assert block.type == "aws_instance"
    assert block.name == "web"
    assert block.text.startswith('resource "aws_instance" "web" {')
    assert block.text.rstrip().endswith("}")
    assert "iam_instance_profile" in block.text


def test_find_missing_block_returns_none(main_tf):
    assert find_resource_block(main_tf, "aws_instance.nope") is None
    assert find_resource_block(main_tf, "not-an-address") is None


def test_find_nested_ingress_block(main_tf):
    block = find_resource_block(main_tf, "aws_security_group.web")
    nested = find_nested_blocks(block, "ingress")
    assert len(nested) == 1
    span = nested[0]
    assert "0.0.0.0/0" in span.text
    assert "443" in span.text
    # Spans are absolute: cutting them out of the file works.
    assert main_tf[span.start:span.end] == span.text


def test_find_nested_blocks_absent_label(main_tf):
    block = find_resource_block(main_tf, "aws_security_group.web")
    assert find_nested_blocks(block, "lifecycle") == []


def test_remove_span_tidies_blank_lines():
    text = "a {\n  x = 1\n\n  y = 2\n}\n"
    out = remove_span(text, text.index("  x = 1\n"), text.index("  x = 1\n") + 8)
    assert "x = 1" not in out
    assert "y = 2" in out
    assert "\n\n\n\n" not in out


def test_replace_span():
    text = 'resource "x" "y" {\n  a = 1\n}\n'
    assert replace_span(text, 9, 12, '"z"') == 'resource "z" "y" {\n  a = 1\n}\n'


def test_unbalanced_braces_raise():
    with pytest.raises(BlockNotFoundError):
        find_resource_block('resource "x" "y" {\n  a = 1\n', "x.y")


def test_extract_jsonencode(main_tf):
    block = find_resource_block(main_tf, "aws_iam_role_policy.web_policy")
    found = extract_jsonencode(block.text)
    assert found is not None
    arg_text, start, end = found
    assert '"OverBroadRead"' in arg_text or "OverBroadRead" in arg_text
    assert block.text[start:end] == arg_text


def test_extract_jsonencode_absent(main_tf):
    block = find_resource_block(main_tf, "aws_s3_bucket.backups")
    assert extract_jsonencode(block.text) is None


def test_extract_heredoc_json():
    text = 'policy = <<EOT\n{"Version": "2012-10-17"}\nEOT\n'
    found = extract_heredoc_json(text)
    assert found is not None
    assert '"Version"' in found[0]


def test_policy_document_reads_fixture(main_tf):
    block = find_resource_block(main_tf, "aws_iam_role_policy.web_policy")
    policy = hcl.policy_document(block.text)
    assert policy is not None
    assert policy["Version"] == "2012-10-17"
    statements = hcl.statements(policy)
    assert [s.get("Sid") for s in statements] == ["OverBroadRead", "NarrowWrite"]
    assert statements[0]["Resource"] == "*"


def test_policy_document_unreadable_returns_none():
    assert hcl.policy_document('resource "x" "y" {\n  a = 1\n}') is None


def test_replace_policy_argument_round_trip(main_tf):
    block = find_resource_block(main_tf, "aws_iam_role_policy.web_policy")
    arg_text, _, _ = hcl.policy_argument(block.text)
    new_arg = arg_text.replace('"*"', '"arn:aws:s3:::assets/*"')
    new_block = hcl.replace_policy_argument(block.text, new_arg)
    assert "arn:aws:s3:::assets/*" in new_block
    # The replacement is still parseable by hcl2.
    import hcl2

    hcl2.loads(new_block)
