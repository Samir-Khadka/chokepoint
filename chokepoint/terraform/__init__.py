"""Terraform support (Phase 4): state parsing and config reading.
"""

from .config import (
    BlockNotFoundError,
    NestedBlock,
    ResourceBlock,
    extract_heredoc_json,
    extract_jsonencode,
    find_nested_blocks,
    find_resource_block,
    remove_span,
    replace_span,
)
from .state import (
    StateParseError,
    TerraformResource,
    TerraformState,
    address_to_node_id,
    load_state,
    node_id_to_address,
    parse_state,
)

__all__ = [
    "BlockNotFoundError",
    "NestedBlock",
    "ResourceBlock",
    "StateParseError",
    "TerraformResource",
    "TerraformState",
    "address_to_node_id",
    "extract_heredoc_json",
    "extract_jsonencode",
    "find_nested_blocks",
    "find_resource_block",
    "load_state",
    "node_id_to_address",
    "parse_state",
    "remove_span",
    "replace_span",
]
