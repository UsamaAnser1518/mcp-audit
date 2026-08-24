import ast
from pathlib import Path

from mcp_audit.detect import find_tools, is_mcp_source, iter_python_files, parse_file

FIXTURES = Path(__file__).parent / "fixtures"


def _tools(source: str):
    tree = ast.parse(source)
    return find_tools(tree, "<test>")


def test_detects_mcp_import():
    assert is_mcp_source(ast.parse("from mcp.server.fastmcp import FastMCP"))
    assert is_mcp_source(ast.parse("import fastmcp"))
    assert not is_mcp_source(ast.parse("import requests"))


def test_fixture_tool_inventory():
    path = FIXTURES / "vulnerable_basic.py"
    tree = parse_file(path)
    assert tree is not None
    tools = find_tools(tree, str(path))
    names = [t.name for t in tools]
    assert names == [
        "fetch_url",
        "run_command",
        "lookup_user",
        "legacy_positional_name",
    ]


def test_undecorated_function_is_not_a_tool():
    tools = _tools("def helper(x): return x")
    assert tools == []


def test_bare_decorator_without_call():
    tools = _tools("@mcp.tool\ndef ping(): return 'pong'")
    assert len(tools) == 1
    assert tools[0].name == "ping"


def test_keyword_name_override():
    tools = _tools("@mcp.tool(name='exposed')\ndef internal(): pass")
    assert tools[0].name == "exposed"
    assert tools[0].function_name == "internal"


def test_positional_name_override():
    tools = _tools("@mcp.tool('exposed')\ndef internal(): pass")
    assert tools[0].name == "exposed"


def test_async_tool_is_detected():
    tools = _tools("@mcp.tool()\nasync def fetch(url: str): pass")
    assert len(tools) == 1
    assert tools[0].parameters == ["url"]


def test_framework_params_excluded():
    tools = _tools("@mcp.tool()\ndef t(self, ctx, real_arg: str): pass")
    assert tools[0].parameters == ["real_arg"]


def test_server_object_can_have_any_name():
    tools = _tools("@whatever_i_called_it.tool()\ndef t(): pass")
    assert len(tools) == 1


def test_low_level_call_tool_decorator():
    tools = _tools("@server.call_tool()\ndef handler(name: str): pass")
    assert len(tools) == 1


def test_tool_defined_inside_factory():
    source = """
def build_server():
    mcp = FastMCP("x")

    @mcp.tool()
    def nested(a: str): pass

    return mcp
"""
    tools = _tools(source)
    assert len(tools) == 1
    assert tools[0].name == "nested"


def test_keyword_only_params_included():
    tools = _tools("@mcp.tool()\ndef t(*, url: str): pass")
    assert tools[0].parameters == ["url"]


def test_parse_file_returns_none_on_syntax_error(tmp_path):
    bad = tmp_path / "bad.py"
    bad.write_text("def broken(:")
    assert parse_file(bad) is None


def test_iter_python_files_skips_noise(tmp_path):
    (tmp_path / "keep.py").write_text("x = 1")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "skip.py").write_text("x = 1")
    (tmp_path / "notes.txt").write_text("hi")
    found = [p.name for p in iter_python_files(tmp_path)]
    assert found == ["keep.py"]
