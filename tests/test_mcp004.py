"""MCP004: does caller input actually reach a dangerous sink?

The two failure modes to guard against are opposite: missing a real flow
(silent false negative, the worst bug a scanner can have) and reporting a
constant command (noise, which gets the tool muted). Both directions are
asserted here.
"""

from helpers import run, run_on_fixture, server, tool_names

from mcp_audit.finding import Severity
from mcp_audit.rules.mcp004_dangerous_sink import DangerousSink

RULE = DangerousSink()


def test_shell_true_with_tool_parameter():
    findings = run(RULE, server('''
        import subprocess

        @mcp.tool()
        def run_command(cmd: str) -> str:
            return subprocess.check_output(cmd, shell=True).decode()
        '''))
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP004"
    assert findings[0].severity is Severity.CRITICAL
    assert findings[0].tool_name == "run_command"
    assert "`cmd`" in findings[0].detail
    assert "shell" in findings[0].detail


def test_constant_argument_vector_is_not_a_finding():
    findings = run(RULE, server('''
        import subprocess

        @mcp.tool()
        def list_files() -> str:
            return subprocess.run(["ls", "-la"], capture_output=True).stdout.decode()
        '''))
    assert findings == []


def test_parameter_assigned_to_local_first():
    findings = run(RULE, server('''
        import subprocess

        @mcp.tool()
        def run_command(cmd: str) -> str:
            command = cmd
            return subprocess.check_output(command, shell=True).decode()
        '''))
    assert len(findings) == 1
    assert "`cmd`" in findings[0].detail  # reported as the parameter, not the local


def test_parameter_through_a_chain_of_locals():
    findings = run(RULE, server('''
        import subprocess

        @mcp.tool()
        def run_command(cmd: str) -> str:
            first = cmd
            second = first
            third = second
            return subprocess.check_output(third, shell=True).decode()
        '''))
    assert len(findings) == 1


def test_parameter_in_an_fstring():
    findings = run(RULE, server('''
        import os

        @mcp.tool()
        def list_dir(path: str) -> str:
            return os.popen(f"ls -la {path}").read()
        '''))
    assert len(findings) == 1
    assert "`path`" in findings[0].detail


def test_eval_of_tool_input():
    findings = run(RULE, server('''
        @mcp.tool()
        def calculate(expression: str):
            return eval(expression)
        '''))
    assert len(findings) == 1
    assert "Python" in findings[0].detail


def test_tool_with_no_sinks():
    findings = run(RULE, server('''
        @mcp.tool()
        def echo(text: str) -> dict:
            return {"echo": text.upper()}
        '''))
    assert findings == []


def test_sink_outside_a_tool_is_ignored():
    """Only tool parameters are caller-controlled. A helper's are not."""
    findings = run(RULE, server('''
        import subprocess

        def helper(cmd: str):
            return subprocess.check_output(cmd, shell=True)

        @mcp.tool()
        def safe() -> str:
            return "ok"
        '''))
    assert findings == []


def test_from_import_still_resolves_to_the_sink():
    findings = run(RULE, server('''
        from subprocess import check_output

        @mcp.tool()
        def run_command(cmd: str) -> str:
            return check_output(cmd, shell=True).decode()
        '''))
    assert len(findings) == 1


def test_aliased_import_still_resolves_to_the_sink():
    findings = run(RULE, server('''
        import subprocess as sp

        @mcp.tool()
        def run_command(cmd: str) -> str:
            return sp.check_output(cmd, shell=True).decode()
        '''))
    assert len(findings) == 1


def test_argument_vector_without_shell_is_reported_differently():
    findings = run(RULE, server('''
        import subprocess

        @mcp.tool()
        def clone(repo: str) -> str:
            return subprocess.run(["git", "clone", repo], capture_output=True).stdout.decode()
        '''))
    assert len(findings) == 1
    assert "no shell to inject into" in findings[0].detail


def test_shlex_quote_neutralises_the_payload():
    findings = run(RULE, server('''
        import shlex
        import subprocess

        @mcp.tool()
        def list_dir(path: str) -> str:
            return subprocess.check_output(f"ls {shlex.quote(path)}", shell=True).decode()
        '''))
    assert findings == []


def test_int_coercion_neutralises_the_payload():
    findings = run(RULE, server('''
        import subprocess

        @mcp.tool()
        def tail(count: str) -> str:
            return subprocess.check_output(f"tail -n {int(count)} log.txt", shell=True).decode()
        '''))
    assert findings == []


def test_interpolated_sql_is_a_finding():
    findings = run(RULE, server('''
        import sqlite3

        db = sqlite3.connect(":memory:")

        @mcp.tool()
        def lookup(user_id: str):
            query = f"SELECT * FROM users WHERE id = '{user_id}'"
            return db.execute(query).fetchall()
        '''))
    assert len(findings) == 1
    assert "SQL" in findings[0].detail
    assert "parameterised" in findings[0].remediation


def test_parameterised_sql_is_not_a_finding():
    findings = run(RULE, server('''
        import sqlite3

        db = sqlite3.connect(":memory:")

        @mcp.tool()
        def lookup(user_id: str):
            return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall()
        '''))
    assert findings == []


def test_path_sink_reports_traversal():
    findings = run(RULE, server('''
        @mcp.tool()
        def read(name: str) -> str:
            return open(f"/srv/data/{name}").read()
        '''))
    assert len(findings) == 1
    assert "traverse" in findings[0].detail
    assert "base directory" in findings[0].remediation


def test_dict_get_is_not_a_sink():
    findings = run(RULE, server('''
        CONFIG = {"a": 1}

        @mcp.tool()
        def lookup(key: str):
            return CONFIG.get(key)
        '''))
    assert findings == []


def test_framework_injected_context_is_not_caller_input():
    """`ctx` comes from the framework, so nothing flows from it."""
    findings = run(RULE, server('''
        import subprocess

        @mcp.tool()
        def run_command(ctx) -> str:
            return subprocess.check_output(ctx, shell=True).decode()
        '''))
    assert findings == []


def test_tool_nested_in_a_factory_is_still_checked():
    findings = run(RULE, '''
import subprocess
from mcp.server.fastmcp import FastMCP


def build():
    mcp = FastMCP("t")

    @mcp.tool()
    def run_command(cmd: str) -> str:
        return subprocess.check_output(cmd, shell=True).decode()

    return mcp
''')
    assert len(findings) == 1


def test_helper_call_is_not_followed():
    """Intraprocedural by design. If this ever starts finding it, the
    README's Limitations section is wrong and must be updated."""
    findings = run(RULE, server('''
        import subprocess

        def execute(command: str):
            return subprocess.check_output(command, shell=True)

        @mcp.tool()
        def run_command(cmd: str):
            return execute(cmd)
        '''))
    assert findings == []


def test_one_finding_per_call_not_per_argument():
    findings = run(RULE, server('''
        import subprocess

        @mcp.tool()
        def run_command(cmd: str, flag: str) -> str:
            return subprocess.check_output(f"{cmd} {flag}", shell=True).decode()
        '''))
    assert len(findings) == 1
    assert "`cmd`, `flag`" in findings[0].detail


def test_path_segments_are_checked_in_every_position():
    """Path(base, user) is as dangerous as Path(user); only open() pins the mode."""
    findings = run(RULE, server('''
        from pathlib import Path

        BASE = Path("/srv/data")

        @mcp.tool()
        def read(name: str) -> str:
            return Path(BASE, name).read_text()
        '''))
    assert len(findings) == 1


def test_containment_check_silences_the_path_finding():
    """resolve() + relative_to() is the fix, not a sign that somebody tried."""
    assert run(RULE, server('''
        from pathlib import Path

        BASE = Path("/srv/data").resolve()

        @mcp.tool()
        def read(name: str) -> str:
            target = Path(BASE, name).resolve()
            target.relative_to(BASE)
            return target.read_text()
        ''')) == []


def test_named_validator_downgrades_a_path_finding():
    """Found against mcp-server-git, which validates the repo path it is
    handed. Reporting that as critical is a false alarm; saying nothing
    would miss a check we never actually read."""
    findings = run(RULE, server('''
        from pathlib import Path

        @mcp.tool()
        def read(repo_path: str) -> str:
            target = Path(repo_path)
            validate_repo_path(target)
            return target.read_text()
        '''))
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "does check the value first" in findings[0].detail


def test_named_validator_does_not_downgrade_a_shell_finding():
    """For a shell the fix is an argument list, not a validator."""
    findings = run(RULE, server('''
        import subprocess

        @mcp.tool()
        def run_command(cmd: str) -> str:
            validate_command(cmd)
            return subprocess.check_output(cmd, shell=True).decode()
        '''))
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL


def test_check_output_does_not_vouch_for_its_own_argument():
    """`check_` in subprocess means "raise on non-zero exit", not "validate"."""
    findings = run(RULE, server('''
        import subprocess

        @mcp.tool()
        def read(name: str) -> str:
            subprocess.check_output(["ls", name])
            return open(name).read()
        '''))
    path_findings = [f for f in findings if "filesystem path" in f.detail]
    assert len(path_findings) == 1
    assert path_findings[0].severity is Severity.CRITICAL


def test_containment_check_does_not_silence_a_shell_finding():
    """Validating a value is not the fix for handing it to a shell."""
    findings = run(RULE, server('''
        import subprocess
        from pathlib import Path

        BASE = Path("/srv/data").resolve()

        @mcp.tool()
        def read(name: str) -> str:
            target = Path(BASE, name).resolve()
            target.relative_to(BASE)
            return subprocess.check_output(f"cat {target}", shell=True).decode()
        '''))
    assert [f.detail for f in findings if "shell" in f.detail]


def test_nested_path_calls_report_once():
    """open(Path(base, name)) matches two sinks but is one mistake."""
    findings = run(RULE, server('''
        from pathlib import Path

        BASE = "/srv/data"

        @mcp.tool()
        def read(name: str) -> str:
            return open(Path(BASE, name)).read()
        '''))
    assert len(findings) == 1
    assert findings[0].column == 12  # anchored on the outer call


def test_two_kinds_of_sink_on_one_line_both_report():
    findings = run(RULE, server('''
        import subprocess

        @mcp.tool()
        def both(name: str, cmd: str):
            return subprocess.run(cmd, shell=True), open(name)
        '''))
    assert len(findings) == 2


def test_open_mode_argument_is_not_a_path():
    assert run(RULE, server('''
        @mcp.tool()
        def write(mode: str) -> None:
            open("/srv/data/fixed.txt", mode).close()
        ''')) == []


def test_malformed_tool_node_does_not_raise():
    """Rules must never raise, whatever the inventory hands them."""
    from helpers import context

    ctx = context(server('''
        @mcp.tool()
        def t(x: str):
            return x
        '''))
    ctx.tools[0].node = None
    assert RULE.check(ctx) == []
    ctx.tools[0].node = "not an ast node"
    assert RULE.check(ctx) == []


def test_fixture_coverage():
    findings = run_on_fixture(RULE, "dangerous_sinks.py")
    assert tool_names(findings) == [
        "async_shell",
        "delete_path",
        "evaluated",
        "read_file",
        "shell_true",
        "sql_interpolated",
        "via_fstring",
        "via_local",
    ]
    assert all(f.severity is Severity.CRITICAL for f in findings)
    assert all(f.remediation for f in findings)
