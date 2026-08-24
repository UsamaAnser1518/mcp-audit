"""MCP003: caller-controlled URLs reaching the network."""

from helpers import run, run_on_fixture, server, tool_names

from mcp_audit.finding import Severity
from mcp_audit.rules.mcp003_ssrf import UnvalidatedUrlFetch

RULE = UnvalidatedUrlFetch()


def test_requests_get_with_a_tool_parameter():
    findings = run(RULE, server('''
        import requests

        @mcp.tool()
        def fetch(url: str) -> str:
            return requests.get(url, timeout=10).text
        '''))
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].tool_name == "fetch"
    assert "169.254.169.254" in findings[0].detail


def test_async_client_method():
    findings = run(RULE, server('''
        import httpx

        @mcp.tool()
        async def fetch(url: str) -> str:
            async with httpx.AsyncClient() as client:
                response = await client.get(url)
                return response.text
        '''))
    assert len(findings) == 1


def test_urlopen():
    findings = run(RULE, server('''
        from urllib.request import urlopen

        @mcp.tool()
        def fetch(url: str) -> str:
            return urlopen(url).read().decode()
        '''))
    assert len(findings) == 1


def test_constant_url_is_not_a_finding():
    assert run(RULE, server('''
        import requests

        @mcp.tool()
        def status() -> int:
            return requests.get("https://api.example.com/health", timeout=5).status_code
        ''')) == []


def test_fixed_origin_is_not_ssrf():
    """The caller picks the path; the host is a literal."""
    assert run(RULE, server('''
        import requests

        @mcp.tool()
        def fetch(path: str) -> str:
            return requests.get(f"https://api.example.com/{path}", timeout=5).text
        ''')) == []


def test_tool_input_in_the_request_body_is_not_ssrf():
    assert run(RULE, server('''
        import requests

        @mcp.tool()
        def report(body: str) -> int:
            return requests.post("https://api.example.com/r", data=body, timeout=5).status_code
        ''')) == []


def test_method_first_signature_finds_the_url():
    findings = run(RULE, server('''
        import requests

        @mcp.tool()
        def fetch(url: str) -> str:
            return requests.request("GET", url, timeout=5).text
        '''))
    assert len(findings) == 1


def test_url_passed_as_a_keyword():
    findings = run(RULE, server('''
        import requests

        @mcp.tool()
        def fetch(target: str) -> str:
            return requests.get(url=target, timeout=5).text
        '''))
    assert len(findings) == 1


def test_allowlisted_url_is_graded_down_not_silenced():
    findings = run(RULE, server('''
        import requests
        from urllib.parse import urlparse

        ALLOWED = {"api.example.com"}

        @mcp.tool()
        def fetch(url: str) -> str:
            if urlparse(url).hostname not in ALLOWED:
                raise ValueError("host not allowed")
            return requests.get(url, timeout=5).text
        '''))
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert "does check the value" in findings[0].detail


def test_validation_helper_also_grades_down():
    findings = run(RULE, server('''
        import requests

        @mcp.tool()
        def fetch(url: str) -> str:
            validate_url(url)
            return requests.get(url, timeout=5).text
        '''))
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM


def test_dict_get_is_not_a_network_call():
    assert run(RULE, server('''
        import requests

        CONFIG = {"a": 1}

        @mcp.tool()
        def lookup(key: str):
            return CONFIG.get(key)
        ''')) == []


def test_client_shaped_call_without_an_http_import_is_ignored():
    """`session.get(x)` on its own is a dict lookup as often as a request."""
    assert run(RULE, server('''
        @mcp.tool()
        def lookup(key: str):
            return session.get(key)
        ''')) == []


def test_database_connect_is_not_a_network_sink():
    assert run(RULE, server('''
        import sqlite3

        @mcp.tool()
        def query(name: str):
            return sqlite3.connect(name)
        ''')) == []


def test_url_built_from_a_local_still_reaches_the_sink():
    findings = run(RULE, server('''
        import requests

        @mcp.tool()
        def fetch(target: str) -> str:
            url = target
            return requests.get(url, timeout=5).text
        '''))
    assert len(findings) == 1


def test_helper_call_is_not_followed():
    """Intraprocedural, same as MCP004."""
    assert run(RULE, server('''
        import requests

        def get(url):
            return requests.get(url, timeout=5).text

        @mcp.tool()
        def fetch(url: str) -> str:
            return get(url)
        ''')) == []


def test_fixture_coverage():
    findings = run_on_fixture(RULE, "ssrf_fetcher.py")
    assert tool_names(findings) == ["fetch", "fetch_allowlisted", "fetch_async"]
    by_tool = {f.tool_name: f.severity for f in findings}
    assert by_tool["fetch"] is Severity.HIGH
    assert by_tool["fetch_async"] is Severity.HIGH
    assert by_tool["fetch_allowlisted"] is Severity.MEDIUM
