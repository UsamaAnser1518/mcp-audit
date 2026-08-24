"""The negative control.

A scanner is only worth running if a clean report means something, and a
scanner that cries wolf gets muted within a week. Every assertion here is
that mcp-audit says nothing about code that is already correct.
"""

from helpers import FIXTURES, run, server

from mcp_audit.finding import Severity
from mcp_audit.rules import all_rules
from mcp_audit.scanner import scan_file

RULES = all_rules()


def _all_findings(source: str):
    return [f for rule in RULES for f in run(rule, source)]


def test_a_well_written_server_raises_nothing_serious():
    """The one finding is MCP003's deliberate 'you checked it, verify the
    check' advisory. Anything critical or high here is a false positive."""
    result = scan_file(FIXTURES / "secure_server.py", force=True)
    assert result.errors == []
    assert [f.rule_id for f in result.findings] == ["MCP003"]
    assert result.findings[0].severity is Severity.MEDIUM


def test_constants_and_config_are_left_alone():
    assert _all_findings('''
import os

from mcp.server.fastmcp import FastMCP

MAX_TOKENS = 4096
API_KEY_HEADER = "X-API-Key"
TIMEOUT_SECONDS = 30
USER_AGENT = "mcp-audit/0.1.0"
API_KEY = os.environ["MCP_API_KEY"]

mcp = FastMCP("t")

if __name__ == "__main__":
    mcp.run()
''') == []


def test_a_tool_that_only_shuffles_data_is_left_alone():
    findings = _all_findings(server('''
        @mcp.tool()
        def summarise(records: list[dict], limit: int) -> dict:
            top = sorted(records, key=lambda r: r["score"], reverse=True)[:limit]
            return {"count": len(top), "items": [r["name"] for r in top]}
        ''', preamble="mcp.run()\n"))
    assert findings == []


def test_stdlib_calls_that_merely_look_like_sinks():
    findings = _all_findings(server('''
        import json

        CONFIG = {"mode": "fast"}

        @mcp.tool()
        def settings(key: str, payload: str) -> str:
            value = CONFIG.get(key)
            parsed = json.loads(payload)
            compiled = REGISTRY.compile(parsed)
            return json.dumps({"value": value, "compiled": compiled})
        ''', preamble="mcp.run()\n"))
    assert findings == []


def test_author_metadata_is_not_authentication():
    """`author` must not read as `auth`, in either direction."""
    findings = _all_findings(server('''
        @mcp.tool()
        def commits(author: str) -> list:
            return [{"author": author, "authors": [author]}]
        ''', preamble="mcp.run()\n"))
    assert findings == []  # stdio transport, so MCP001 stays quiet too
