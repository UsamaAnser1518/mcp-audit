"""MCP005: OAuth configured, scopes not enforced.

This rule only speaks to servers that already verify tokens, so the first
assertion is that it stays out of everyone else's way.
"""

from helpers import run, run_on_fixture, server

from mcp_audit.finding import Severity
from mcp_audit.rules.mcp005_oauth_scopes import OAuthWithoutScopes

RULE = OAuthWithoutScopes()


def test_no_oauth_means_no_finding():
    """MCP001 owns "no auth at all". This rule has nothing to add."""
    assert run(RULE, server('''
        @mcp.tool()
        def t(a: str):
            return a
        ''')) == []


def test_oauth_without_any_scope_is_reported():
    findings = run_on_fixture(RULE, "oauth_no_scopes.py")
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert "no scope appears anywhere" in findings[0].detail
    assert "2 tool(s)" in findings[0].detail


def test_server_wide_scopes_still_flag_unscoped_tools():
    findings = run(RULE, server('''
        auth = AuthSettings(issuer_url="https://auth.example.com", required_scopes=["mcp:read"])

        @mcp.tool()
        def read_doc(doc_id: str):
            return doc_id

        @mcp.tool()
        def delete_doc(doc_id: str):
            require_scope("mcp:write")
            return True
        '''))
    assert len(findings) == 1
    assert "`read_doc`" in findings[0].detail
    assert "`delete_doc`" not in findings[0].detail
    assert "1 of 2 tool(s)" in findings[0].detail


def test_every_tool_scoped_means_no_finding():
    assert run(RULE, server('''
        auth = AuthSettings(issuer_url="https://auth.example.com")

        @mcp.tool()
        def read_doc(doc_id: str):
            require_scope("mcp:read")
            return doc_id

        @mcp.tool()
        def delete_doc(doc_id: str):
            require_scope("mcp:write")
            return True
        ''')) == []


def test_scope_enforced_by_decorator_counts():
    assert run(RULE, server('''
        verifier = TokenVerifier()

        @mcp.tool()
        @requires_scope("mcp:read")
        def read_doc(doc_id: str):
            return doc_id
        ''')) == []


def test_no_tools_means_no_finding():
    assert run(RULE, "verifier = TokenVerifier()\n") == []


def test_one_finding_per_file():
    findings = run(RULE, server('''
        verifier = TokenVerifier()

        @mcp.tool()
        def one(): pass

        @mcp.tool()
        def two(): pass

        @mcp.tool()
        def three(): pass
        '''))
    assert len(findings) == 1
