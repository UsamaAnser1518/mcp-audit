"""Call-target resolution. Every sink match in every rule depends on it."""

import ast

from mcp_audit.astutil import build_alias_map, dotted_path, matches, resolve, resolve_call


def _expression(source: str):
    return ast.parse(source, mode="eval").body


def test_dotted_path_shapes():
    assert dotted_path(_expression("tool")) == "tool"
    assert dotted_path(_expression("mcp.tool")) == "mcp.tool"
    assert dotted_path(_expression("mcp.tool(name='x')")) == "mcp.tool"
    assert dotted_path(_expression("httpx.Client().get")) == "httpx.Client.get"


def test_dotted_path_gives_up_cleanly():
    assert dotted_path(_expression("handlers[0]")) == ""
    assert dotted_path(_expression("'literal'")) == ""


def test_alias_map_covers_the_import_shapes():
    tree = ast.parse(
        "import subprocess\n"
        "import subprocess as sp\n"
        "from subprocess import check_output\n"
        "from os.path import join as j\n"
        "import os.path\n"
    )
    aliases = build_alias_map(tree)
    assert aliases["subprocess"] == "subprocess"
    assert aliases["sp"] == "subprocess"
    assert aliases["check_output"] == "subprocess.check_output"
    assert aliases["j"] == "os.path.join"
    assert aliases["os"] == "os"


def test_relative_imports_are_skipped():
    aliases = build_alias_map(ast.parse("from . import helpers\nfrom .util import run\n"))
    assert aliases == {}


def test_resolve_rewrites_only_the_head():
    aliases = {"sp": "subprocess"}
    assert resolve("sp.check_output", aliases) == "subprocess.check_output"
    assert resolve("other.check_output", aliases) == "other.check_output"
    assert resolve("", aliases) == ""


def test_resolve_call_end_to_end():
    tree = ast.parse("from subprocess import check_output\ncheck_output('ls')\n")
    call = tree.body[1].value
    assert resolve_call(call.func, build_alias_map(tree)) == "subprocess.check_output"


def test_bare_pattern_matches_only_a_bare_path():
    """Otherwise `model.compile(...)` would match the `compile` builtin."""
    assert matches("eval", ["eval"]) == "eval"
    assert matches("model.compile", ["compile"]) is None


def test_dotted_pattern_is_a_segment_aligned_suffix():
    assert matches("subprocess.run", ["subprocess.run"]) == "subprocess.run"
    assert matches("a.b.subprocess.run", ["subprocess.run"]) == "subprocess.run"
    assert matches("mysubprocess.run", ["subprocess.run"]) is None


def test_leading_dot_pattern_matches_any_receiver():
    assert matches("cursor.execute", [".execute"]) == ".execute"
    assert matches("db.conn.cursor.execute", [".execute"]) == ".execute"
    assert matches("execute_query", [".execute"]) is None


def test_empty_path_never_matches():
    assert matches("", ["eval", ".execute"]) is None
