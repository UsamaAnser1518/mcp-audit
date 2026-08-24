"""The scanner: file selection, error containment, ordering."""

from pathlib import Path

from helpers import FIXTURES

from mcp_audit.finding import Severity
from mcp_audit.rules.base import Rule, ScanContext
from mcp_audit.rules.mcp004_dangerous_sink import DangerousSink
from mcp_audit.scanner import scan_file, scan_path, scan_source


class BrokenRule(Rule):
    """Deliberately misbehaving. Not registered -- tests pass it explicitly."""

    id = "TEST999"
    title = "Always explodes"
    severity = Severity.LOW

    def check(self, ctx: ScanContext) -> list:
        raise RuntimeError("boom")


def test_scan_file_finds_the_expected_rules():
    result = scan_file(FIXTURES / "vulnerable_basic.py", force=True)
    assert {f.rule_id for f in result.findings} == {"MCP001", "MCP002", "MCP003", "MCP004"}
    assert result.files_scanned == 1
    assert len(result.tools) == 4
    assert result.errors == []


def test_scan_path_walks_a_directory():
    result = scan_path(FIXTURES)
    assert result.files_scanned >= 7
    assert result.errors == []
    assert {f.rule_id for f in result.findings} >= {"MCP001", "MCP003", "MCP004", "MCP005"}


def test_findings_are_ordered_worst_first():
    result = scan_path(FIXTURES)
    ranks = [f.severity.rank for f in result.findings]
    assert ranks == sorted(ranks, reverse=True)


def test_non_mcp_file_is_skipped_in_a_directory_scan(tmp_path):
    (tmp_path / "ordinary.py").write_text("import subprocess\nsubprocess.run('ls', shell=True)\n")
    result = scan_path(tmp_path)
    assert result.files_seen == 1
    assert result.files_scanned == 0
    assert result.findings == []


def test_named_file_is_scanned_even_if_it_looks_unrelated(tmp_path):
    """Silently doing nothing to a file the user named is the wrong answer."""
    target = tmp_path / "ordinary.py"
    target.write_text('API_KEY = "9f2c41d0e84a17b6c3"\n')
    result = scan_path(target)
    assert result.files_scanned == 1
    assert [f.rule_id for f in result.findings] == ["MCP002"]


def test_a_file_with_tools_is_scanned_without_an_mcp_import(tmp_path):
    """Vendored or re-exported SDKs still register tools the same way."""
    target = tmp_path / "server.py"
    target.write_text("@app.tool()\ndef t(cmd: str):\n    __import__('os').system(cmd)\n")
    result = scan_path(tmp_path)
    assert result.files_scanned == 1


def test_syntax_error_is_skipped_quietly_in_a_directory(tmp_path):
    (tmp_path / "broken.py").write_text("def broken(:\n")
    result = scan_path(tmp_path)
    assert result.findings == []
    assert result.errors == []


def test_syntax_error_is_reported_when_the_file_was_named(tmp_path):
    target = tmp_path / "broken.py"
    target.write_text("def broken(:\n")
    result = scan_path(target)
    assert len(result.errors) == 1
    assert "broken.py" in result.errors[0]


def test_a_crashing_rule_does_not_abort_the_scan():
    result = scan_path(FIXTURES / "dangerous_sinks.py", rules=[BrokenRule(), DangerousSink()])
    assert len(result.errors) == 1
    assert "TEST999 failed" in result.errors[0]
    assert "RuntimeError" in result.errors[0]
    assert len(result.findings) == 8  # the working rule still reported everything


def test_scan_source_takes_text_directly():
    result = scan_source("import os\n@mcp.tool()\ndef t(c: str):\n    os.system(c)\n", "mem.py")
    assert [f.rule_id for f in result.findings if f.rule_id == "MCP004"]


def test_scan_source_records_a_syntax_error():
    result = scan_source("def broken(:", "mem.py")
    assert result.findings == []
    assert "could not parse" in result.errors[0]


def test_severity_threshold():
    result = scan_file(FIXTURES / "stdio_server.py", force=True)
    assert result.worst() is None
    assert not result.meets(Severity.LOW)

    result = scan_file(FIXTURES / "dangerous_sinks.py", force=True)
    assert result.worst() is Severity.CRITICAL
    assert result.meets(Severity.CRITICAL)
    assert result.meets(Severity.LOW)


def test_counts_by_severity():
    result = scan_file(FIXTURES / "ssrf_fetcher.py", force=True)
    counts = result.counts()
    assert counts[Severity.HIGH] == 3  # two SSRF plus the missing-auth finding
    assert counts[Severity.MEDIUM] == 1


def test_empty_directory(tmp_path):
    result = scan_path(tmp_path)
    assert result.files_seen == 0
    assert result.findings == []


def test_missing_rules_argument_uses_the_registry():
    result = scan_path(Path(FIXTURES / "oauth_no_scopes.py"))
    assert [f.rule_id for f in result.findings] == ["MCP005"]
