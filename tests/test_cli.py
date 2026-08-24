"""The command line: formats, exit codes, and the SARIF contract.

SARIF is asserted structurally rather than by golden file. GitHub rejects a
run with a missing region or an unknown level, and those are exactly the
fields a refactor breaks silently.
"""

import json

import pytest
from helpers import FIXTURES

from mcp_audit.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main

VULNERABLE = str(FIXTURES / "vulnerable_basic.py")
CLEAN = str(FIXTURES / "stdio_server.py")


def test_text_output(capsys):
    assert main([VULNERABLE]) == EXIT_OK
    out = capsys.readouterr().out
    assert "MCP004" in out
    assert "vulnerable_basic.py:27" in out
    assert "tool: run_command" in out
    assert "fix:" in out
    assert "4 findings" in out


def test_text_output_has_no_escape_codes_when_not_a_tty(capsys):
    main([VULNERABLE])
    assert "\033[" not in capsys.readouterr().out


def test_quiet_drops_the_summary_and_remediation(capsys):
    main([VULNERABLE, "--quiet"])
    out = capsys.readouterr().out
    assert "MCP004" in out
    assert "fix:" not in out
    assert "findings (" not in out


def test_clean_file_says_so(capsys):
    assert main([CLEAN]) == EXIT_OK
    assert "No findings." in capsys.readouterr().out


def test_directory_with_no_servers_explains_itself(capsys, tmp_path):
    (tmp_path / "notes.py").write_text("x = 1\n")
    assert main([str(tmp_path)]) == EXIT_OK
    assert "No MCP server was recognised" in capsys.readouterr().out


def test_json_output(capsys):
    main([VULNERABLE, "--format", "json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"] == "mcp-audit"
    assert payload["summary"]["findings"] == len(payload["findings"])
    assert payload["summary"]["tools"] == 4
    assert payload["summary"]["by_severity"]["critical"] == 1
    first = payload["findings"][0]
    assert set(first) == {
        "rule_id", "title", "severity", "path", "line", "column",
        "tool_name", "detail", "remediation",
    }
    assert first["severity"] == "critical"  # worst first


def test_sarif_output_shape(capsys):
    main([VULNERABLE, "--format", "sarif"])
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].endswith("sarif-schema-2.1.0.json")

    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "mcp-audit"
    assert [rule["id"] for rule in driver["rules"]] == [
        "MCP001", "MCP002", "MCP003", "MCP004", "MCP005",
    ]
    for rule in driver["rules"]:
        assert rule["defaultConfiguration"]["level"] in {"error", "warning", "note"}
        assert "security-severity" in rule["properties"]

    assert run["results"]
    for result in run["results"]:
        assert result["level"] in {"error", "warning", "note"}
        assert driver["rules"][result["ruleIndex"]]["id"] == result["ruleId"]
        region = result["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1
        assert region["startColumn"] >= 1


def test_sarif_uri_is_relative_and_posix(capsys):
    main([VULNERABLE, "--format", "sarif"])
    sarif = json.loads(capsys.readouterr().out)
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert uri["uri"] == "tests/fixtures/vulnerable_basic.py"


def test_sarif_message_names_the_tool(capsys):
    main([VULNERABLE, "--format", "sarif"])
    sarif = json.loads(capsys.readouterr().out)
    messages = [r["message"]["text"] for r in sarif["runs"][0]["results"]]
    assert any(m.startswith("[tool: run_command]") for m in messages)


@pytest.mark.parametrize(
    ("threshold", "expected"),
    [
        ("critical", EXIT_FINDINGS),
        ("high", EXIT_FINDINGS),
        ("medium", EXIT_FINDINGS),
        ("low", EXIT_FINDINGS),
    ],
)
def test_fail_on_thresholds_met(threshold, expected, capsys):
    assert main([VULNERABLE, "--fail-on", threshold]) == expected
    capsys.readouterr()


def test_fail_on_is_not_met_by_a_clean_file(capsys):
    assert main([CLEAN, "--fail-on", "low"]) == EXIT_OK
    capsys.readouterr()


def test_fail_on_above_the_worst_finding(capsys):
    """ssrf_fetcher tops out at high; nothing should fail a critical gate."""
    ssrf = str(FIXTURES / "ssrf_fetcher.py")
    assert main([ssrf, "--fail-on", "critical"]) == EXIT_OK
    assert main([ssrf, "--fail-on", "high"]) == EXIT_FINDINGS
    capsys.readouterr()


def test_findings_alone_do_not_fail_the_build(capsys):
    """--fail-on is opt-in: a report is not an error."""
    assert main([VULNERABLE]) == EXIT_OK
    capsys.readouterr()


def test_missing_path(capsys):
    assert main(["does/not/exist.py"]) == EXIT_USAGE
    assert "no such file or directory" in capsys.readouterr().err


def test_errors_go_to_stderr_so_stdout_stays_parseable(capsys, tmp_path):
    broken = tmp_path / "broken.py"
    broken.write_text("def broken(:\n")
    assert main([str(broken), "--format", "json"]) == EXIT_OK
    captured = capsys.readouterr()
    json.loads(captured.out)  # stdout is still valid JSON
    assert "could not parse" in captured.err


def test_version():
    from mcp_audit import __version__

    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert __version__


def test_bad_format_is_rejected():
    with pytest.raises(SystemExit) as exit_info:
        main([VULNERABLE, "--format", "xml"])
    assert exit_info.value.code == EXIT_USAGE
