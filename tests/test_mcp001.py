"""MCP001: no authentication.

Most of the work in this rule is deciding when to stay quiet, so most of
these tests assert silence.
"""

from helpers import run, run_on_fixture, server

from mcp_audit.finding import Severity
from mcp_audit.rules.mcp001_no_auth import NoAuthentication, auth_evidence, infer_transport

RULE = NoAuthentication()


def _transport(source):
    import ast

    from mcp_audit.astutil import build_alias_map

    tree = ast.parse(source)
    return infer_transport(tree, build_alias_map(tree))


def test_network_server_without_auth_is_reported():
    findings = run_on_fixture(RULE, "network_no_auth.py")
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "`list_customers`" in findings[0].detail
    assert "network transport" in findings[0].detail


def test_stdio_server_is_not_reported():
    """A stdio server's caller is the process that spawned it."""
    assert run_on_fixture(RULE, "stdio_server.py") == []


def test_authenticated_server_is_not_reported():
    assert run_on_fixture(RULE, "authenticated_server.py") == []


def test_file_with_no_tools_is_not_reported():
    assert run(RULE, "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('t')\n") == []


def test_unknown_transport_is_treated_as_network():
    findings = run(RULE, server('''
        @mcp.tool()
        def t(a: str):
            return a
        '''))
    assert len(findings) == 1
    assert "No transport is configured" in findings[0].detail


def test_one_finding_per_file_not_per_tool():
    findings = run(RULE, server('''
        @mcp.tool()
        def one(): pass

        @mcp.tool()
        def two(): pass

        @mcp.tool()
        def three(): pass
        '''))
    assert len(findings) == 1
    assert "3 tool(s)" in findings[0].detail


def test_long_tool_lists_are_truncated():
    body = "".join(f"@mcp.tool()\ndef tool_{i}(): pass\n\n" for i in range(9))
    findings = run(RULE, server(body))
    assert "and 4 more" in findings[0].detail


def test_token_verifier_silences_the_rule():
    assert run(RULE, server('''
        verifier = build_token_verifier()

        @mcp.tool()
        def t(): pass
        ''')) == []


def test_bearer_header_check_silences_the_rule():
    assert run(RULE, server('''
        @mcp.tool()
        def t(headers: dict):
            return headers["Authorization"]
        ''')) == []


def test_prose_about_authentication_does_not_silence_the_rule():
    """A docstring is a sentence about the problem, not a solution to it."""
    findings = run(RULE, server('''
        @mcp.tool()
        def t():
            """This tool needs no authentication and is safe for anyone to call."""
            return 1
        '''))
    assert len(findings) == 1


def test_a_commit_author_is_not_authentication():
    findings = run(RULE, server('''
        @mcp.tool()
        def commits(author: str):
            return [author, "authors"]
        '''))
    assert len(findings) == 1


def test_defining_a_key_is_not_checking_one():
    """MCP002 reports the literal. Nothing here authenticates a caller."""
    findings = run(RULE, server('''
        API_KEY = "sk-live-not-used-anywhere"

        @mcp.tool()
        def t(): pass
        '''))
    assert len(findings) == 1


def test_using_a_key_does_silence_the_rule():
    assert run(RULE, server('''
        API_KEY = "sk-live-abcdefghijkl"

        @mcp.tool()
        def t(supplied: str):
            return supplied == API_KEY
        ''')) == []


def test_auth_evidence_reports_what_it_matched():
    import ast

    assert auth_evidence(ast.parse("import oauthlib")) == "oauthlib"
    assert auth_evidence(ast.parse("x = 1")) is None


def test_transport_inference():
    assert _transport("mcp.run()") == "stdio"
    assert _transport("mcp.run(transport='stdio')") == "stdio"
    assert _transport("mcp.run(transport='sse')") == "network"
    assert _transport("mcp.run('streamable-http')") == "network"
    assert _transport("app = mcp.streamable_http_app()") == "network"
    assert _transport("import uvicorn\nuvicorn.run(app)") == "network"
    assert _transport("mcp = FastMCP('t', host='0.0.0.0', port=8080)") == "network"
    assert _transport("x = 1") == "unknown"


def test_subprocess_run_is_not_a_transport():
    """`subprocess.run(...)` must never read as "this server is on stdio"."""
    assert _transport("import subprocess\nsubprocess.run(['ls'])") == "unknown"


def test_network_evidence_beats_stdio_evidence():
    assert _transport("mcp.run(transport='stdio')\nmcp.run(transport='sse')") == "network"
