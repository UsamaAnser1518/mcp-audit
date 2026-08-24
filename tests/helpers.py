"""Shared plumbing for the rule tests.

Rules are exercised through a ScanContext built from source text, which is
the same object the scanner hands them in production. Tests that build a
context by hand would drift from what rules actually receive.
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from mcp_audit.detect import find_tools
from mcp_audit.rules.base import Rule, ScanContext

FIXTURES = Path(__file__).parent / "fixtures"

_PREAMBLE = "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('t')\n"


def context(source: str, path: str = "<test>") -> ScanContext:
    tree = ast.parse(source)
    return ScanContext(path=path, tree=tree, source=source, tools=find_tools(tree, path))


def run(rule: Rule, source: str, path: str = "<test>") -> list:
    return rule.check(context(source, path))


def server(body: str, preamble: str = "") -> str:
    """A minimal MCP module wrapping `body`, so tests show only what matters."""
    return _PREAMBLE + textwrap.dedent(preamble) + textwrap.dedent(body)


def fixture_source(name: str) -> tuple[str, str]:
    path = FIXTURES / name
    return path.read_text(encoding="utf-8"), str(path)


def run_on_fixture(rule: Rule, name: str) -> list:
    source, path = fixture_source(name)
    return run(rule, source, path)


def tool_names(findings) -> list[str]:
    return sorted({f.tool_name for f in findings if f.tool_name})


def details(findings) -> str:
    return " ".join(f.detail for f in findings)
