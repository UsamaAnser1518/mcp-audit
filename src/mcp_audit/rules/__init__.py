"""The active rule set.

A rule is registered by its module being imported, so this list *is* the
configuration. Explicit and greppable: to disable a check in a fork, delete
one line here rather than hunting for a decorator.
"""

from . import (  # noqa: F401 -- imported for the @register side effect
    mcp001_no_auth,
    mcp002_static_credentials,
    mcp003_ssrf,
    mcp004_dangerous_sink,
    mcp005_oauth_scopes,
)
from .base import Rule, ScanContext, all_rules, register

__all__ = ["Rule", "ScanContext", "all_rules", "register"]
