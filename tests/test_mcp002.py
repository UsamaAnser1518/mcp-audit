"""MCP002: static credentials and timing-unsafe comparison.

The interesting assertions are the negatives. A rule that flags
`API_KEY_HEADER = "X-API-Key"` gets muted within a day.
"""

from helpers import run, run_on_fixture, server

from mcp_audit.finding import Severity
from mcp_audit.rules.mcp002_static_credentials import StaticCredentials

RULE = StaticCredentials()


def _details(source):
    return [f.detail for f in run(RULE, source)]


def test_hardcoded_key_is_reported():
    findings = run(RULE, 'API_KEY = "9f2c41d0e84a17b6c3"\n')
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "`API_KEY`" in findings[0].detail


def test_vendor_prefixed_literal_is_reported_whatever_it_is_called():
    findings = run(RULE, 'FALLBACK = "sk-live-6f2b9c41d0e84a17"\n')
    assert len(findings) == 1
    assert "credential format" in findings[0].detail


def test_header_name_is_not_a_credential():
    assert run(RULE, 'API_KEY_HEADER = "X-API-Key"\n') == []


def test_env_var_name_is_not_a_credential():
    assert run(RULE, 'API_KEY = "MCP_SERVER_API_KEY"\n') == []


def test_placeholder_is_not_a_credential():
    assert run(RULE, 'API_KEY = "changeme"\n') == []
    assert run(RULE, 'API_KEY = "<your-key-here>"\n') == []
    assert run(RULE, 'API_KEY = "${MCP_API_KEY}"\n') == []
    assert run(RULE, 'API_KEY = "xxxxxxxxxxxx"\n') == []


def test_protocol_mechanism_names_are_not_credentials():
    """Found against mcp-atlassian: an OAuth method name, not a secret."""
    assert run(RULE, 'x = Client(token_endpoint_auth_method="client_secret_post")\n') == []
    assert run(RULE, 'SIGNING_ALGORITHM = "HS256-with-rotation"\n') == []


def test_short_value_is_not_a_credential():
    assert run(RULE, 'TOKEN = "abc"\n') == []


def test_value_from_the_environment_is_not_a_finding():
    assert run(RULE, 'import os\nAPI_KEY = os.environ["MCP_API_KEY"]\n') == []


def test_credential_passed_as_a_keyword_argument():
    findings = run(RULE, 'client = Client(api_key="9f2c41d0e84a17b6c3")\n')
    assert len(findings) == 1
    assert "`api_key=`" in findings[0].detail


def test_credential_in_a_headers_dict():
    findings = run(RULE, 'HEADERS = {"Authorization": "Bearer 9f2c41d0e84a17b6c3"}\n')
    assert len(findings) == 1
    assert "Authorization" in findings[0].detail


def test_content_type_header_is_not_a_credential():
    assert run(RULE, 'HEADERS = {"Content-Type": "application/json"}\n') == []


def test_equality_comparison_of_a_secret():
    findings = run(RULE, server('''
        @mcp.tool()
        def t(supplied: str, expected: str):
            api_key = supplied
            return api_key == expected
        '''))
    assert len(findings) == 1
    assert "timing" in findings[0].detail or "timing" in findings[0].remediation
    assert "compare_digest" in findings[0].remediation


def test_inequality_comparison_of_a_secret():
    findings = _details("if request_token != stored_token:\n    pass\n")
    assert len(findings) == 1
    assert "!=" in findings[0]


def test_protocol_constant_comparison_is_not_reported():
    """`token_type == "bearer"` compares a protocol value, not a secret."""
    assert run(RULE, 'if token_type == "bearer":\n    pass\n') == []


def test_none_comparison_is_not_reported():
    assert run(RULE, "if api_key == None:\n    pass\n") == []


def test_compare_digest_is_not_reported():
    assert run(RULE, "import hmac\nif hmac.compare_digest(api_key, expected):\n    pass\n") == []


def test_non_secret_comparison_is_not_reported():
    assert run(RULE, 'if name == "alice":\n    pass\n') == []


def test_docstrings_are_not_scanned_for_credentials():
    assert run(RULE, '"""Set MCP_API_KEY before starting the server."""\n') == []


def test_fixture_reports_both_failures():
    findings = run_on_fixture(RULE, "authenticated_server.py")
    assert len(findings) == 2
    assert {"credential" in f.detail or "compared" in f.detail for f in findings} == {True}


def test_findings_are_deduplicated_per_location():
    findings = run(RULE, 'API_KEY = SECRET_KEY = "9f2c41d0e84a17b6c3"\n')
    assert len(findings) == 1
