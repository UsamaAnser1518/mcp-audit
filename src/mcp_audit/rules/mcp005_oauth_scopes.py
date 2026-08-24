"""MCP005 -- OAuth configured, scopes not enforced.

This one only speaks up for servers that already did the hard part. If a
server verifies tokens but never looks at what the token is *for*, then
every scope is effectively `*`: a token minted for the read-only tool can
drive the one that writes.

At most one finding per file. The absence of per-tool scope checks is a
single design decision, and repeating it once per tool would bury the rest
of the report.
"""

from __future__ import annotations

import ast
import re

from ..finding import Finding, Severity
from .base import Rule, ScanContext, register

# Specific enough that a plain API-key check does not trip it -- MCP001
# already covers "is there any auth at all".
_OAUTH_MARKER = re.compile(
    r"oauth|token[_-]?verifier|auth[_-]?settings|auth[_-]?server[_-]?provider|bearer[_-]?auth"
    r"|issuer[_-]?url|introspect|resource[_-]?server|jwks|\bjwt\b|id[_-]?token",
    re.IGNORECASE,
)
_SCOPE_MARKER = re.compile(r"scope", re.IGNORECASE)


@register
class OAuthWithoutScopes(Rule):
    """Token verification without any per-tool authorization decision."""

    id = "MCP005"
    title = "OAuth configured but tools do not enforce scopes"
    severity = Severity.MEDIUM
    remediation = (
        "Give each tool the narrowest scope that lets it work and check it inside the tool "
        "before doing anything -- read-only tools should not accept a token that can write. "
        "Reject the call with an authorization error, not an empty result, so the caller can "
        "tell the difference between 'not allowed' and 'nothing there'."
    )

    def check(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.tools:
            return []
        try:
            marker = _first_match(ctx.tree, _OAUTH_MARKER)
            if marker is None:
                return []  # no OAuth here; MCP001 owns the "no auth at all" case
            oauth_line, _ = marker

            unscoped = [t for t in ctx.tools if not _mentions_scope(t.node)]
            if not unscoped:
                return []

            if _first_match(ctx.tree, _SCOPE_MARKER) is None:
                detail = (
                    "Token verification is configured but no scope appears anywhere in this "
                    f"file, so all {len(ctx.tools)} tool(s) accept any token the issuer will "
                    "sign. A token obtained for one tool works on every other."
                )
                return [self.finding(ctx, line=oauth_line, detail=detail)]

            names = ", ".join(f"`{t.name}`" for t in unscoped[:5])
            if len(unscoped) > 5:
                names += f" and {len(unscoped) - 5} more"
            detail = (
                f"Scopes are configured for this server, but {len(unscoped)} of "
                f"{len(ctx.tools)} tool(s) do not check one of their own ({names}). A "
                "server-wide scope is a single privilege level: whoever can call the safest "
                "tool can call the rest."
            )
            return [self.finding(ctx, line=unscoped[0].line, detail=detail)]
        except Exception:  # noqa: BLE001 -- a rule crash must not abort the scan
            return []


def _mentions_scope(node: object) -> bool:
    if not isinstance(node, ast.AST):
        return False
    return _first_match(node, _SCOPE_MARKER) is not None


def _first_match(tree: ast.AST, pattern: re.Pattern[str]) -> tuple[int, str] | None:
    """First (line, token) where an identifier or literal matches."""
    for node in ast.walk(tree):
        for token in _tokens(node):
            if token and pattern.search(token):
                return getattr(node, "lineno", 0), token
    return None


def _tokens(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Import):
        return [a.name for a in node.names]
    if isinstance(node, ast.ImportFrom):
        return [node.module or ""] + [a.name for a in node.names]
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        return [node.attr]
    if isinstance(node, ast.keyword):
        return [node.arg or ""]
    if isinstance(node, ast.arg):
        return [node.arg]
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        # Scope strings ("mcp:read", "tools.write") are short identifiers,
        # not sentences. Prose about scope is not enforcement of it.
        text = node.value
        return [text] if len(text) <= 40 and " " not in text.strip() else []
    return []
