"""Fix generation (Phase 4): template-based Terraform fixes.

Templates first, no LLM anywhere in this phase. A ranked fix
becomes a modified ``.tf`` file, a PR body, and a validation
record — after the graph proves the fix removes paths and opens
none. Opening a real pull request against a repository is the
next step after this build, not part of it.
"""

from .generate import FixRejected, GeneratedFix, fix_id, generate_fix
from .prbody import render_pr_body
from .templates import NoOpFix, TemplateApplication, UnsupportedFix
from .validation import ValidationResult, validate_fix

__all__ = [
    "FixRejected",
    "GeneratedFix",
    "NoOpFix",
    "TemplateApplication",
    "UnsupportedFix",
    "ValidationResult",
    "fix_id",
    "generate_fix",
    "render_pr_body",
    "validate_fix",
]
