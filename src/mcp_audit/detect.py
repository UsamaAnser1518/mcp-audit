"""Find MCP servers and inventory the tools they expose.

Everything downstream depends on this module being right: a rule can only
check tools we actually found. Missed tools are silent false negatives,
which are the worst kind of bug in a security scanner.
"""

from __future__ import annotations

import ast
from pathlib import Path

from .astutil import dotted_path, last_segment
from .finding import ToolDefinition

# Import roots that indicate this file is probably an MCP server.
MCP_IMPORT_ROOTS = {"mcp", "fastmcp"}

# Decorator *suffixes* that register a tool. We match on the last segment
# rather than the full path because the server object can be named anything:
# `@mcp.tool()`, `@app.tool()`, `@srv.tool()` are all the same pattern.
TOOL_DECORATOR_SUFFIXES = {"tool", "call_tool"}

# Registration is not always a decorator. FastMCP takes a plain function
# reference too -- `mcp.add_tool(search)`, `self.tool(find, name="q-find")`
# -- and mcp-server-qdrant among others registers every tool that way. A
# scanner that only reads decorator_list reports zero tools for those
# servers and then says nothing is wrong, which is the worst outcome this
# module can produce.
TOOL_REGISTRATION_SUFFIXES = {"tool", "add_tool"}

# Parameters that are injected by the framework, not supplied by the caller.
# Rules care about caller-controlled input, so these are excluded.
NON_INPUT_PARAMS = {"self", "cls", "ctx", "context"}


def _decorator_path(node: ast.expr) -> str:
    """Render a decorator expression as a dotted string.

    Handles the three shapes a decorator can take:
        @tool              -> ast.Name        -> "tool"
        @mcp.tool          -> ast.Attribute   -> "mcp.tool"
        @mcp.tool(name=..) -> ast.Call        -> unwrap .func, then as above

    Shares astutil.dotted_path with the rules rather than keeping a second
    copy: a decorator and a call target are the same expression shapes, and
    two implementations would eventually disagree about one of them.
    """
    return dotted_path(node)


def _is_tool_decorator(node: ast.expr) -> bool:
    path = _decorator_path(node)
    if not path:
        return False
    return path.rsplit(".", 1)[-1] in TOOL_DECORATOR_SUFFIXES


def _tool_name_from_decorator(node: ast.expr, fallback: str) -> str:
    """MCP lets you override the exposed name: @mcp.tool(name="search_docs").

    The exposed name is what an attacker sees and what a report should show,
    so prefer it over the Python function name.
    """
    if isinstance(node, ast.Call):
        for kw in node.keywords:
            if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                if isinstance(kw.value.value, str):
                    return kw.value.value
        # Some styles pass the name positionally: @mcp.tool("search_docs")
        if node.args and isinstance(node.args[0], ast.Constant):
            if isinstance(node.args[0].value, str):
                return node.args[0].value
    return fallback


def _caller_supplied_params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    args = func.args
    names: list[str] = []
    for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
        if arg.arg not in NON_INPUT_PARAMS:
            names.append(arg.arg)
    return names


def is_mcp_source(tree: ast.Module) -> bool:
    """Heuristic: does this file import the MCP SDK?

    Deliberately loose. A false positive costs one wasted scan; a false
    negative means we silently skip a real server.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in MCP_IMPORT_ROOTS:
                    return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] in MCP_IMPORT_ROOTS:
                return True
    return False


def find_tools(tree: ast.Module, path: str) -> list[ToolDefinition]:
    """Inventory every tool registered in this module.

    Uses ast.walk rather than only inspecting module-level statements, so
    tools defined inside a factory function or a class still get found.
    """
    tools: list[ToolDefinition] = []
    claimed: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            if not _is_tool_decorator(dec):
                continue
            claimed.add(id(node))
            tools.append(
                ToolDefinition(
                    name=_tool_name_from_decorator(dec, node.name),
                    function_name=node.name,
                    path=path,
                    line=node.lineno,
                    parameters=_caller_supplied_params(node),
                    decorator=_decorator_path(dec),
                    node=node,
                )
            )
            break  # one tool per function, even if stacked decorators match
    tools.extend(_registered_tools(tree, path, claimed))
    return tools


def _function_table(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    """Every function in the module, by name. Nested ones included -- the
    registered implementation is usually a closure over the server."""
    table: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            table.setdefault(node.name, node)
    return table


def _name_aliases(tree: ast.Module) -> dict[str, str]:
    """Follow `handler = find` so a registration through a local resolves.

    Only plain name-to-name bindings are recorded, so a rebind through a
    call -- `find = make_partial(find, ...)` -- leaves the original mapping
    intact rather than replacing it with something unresolvable.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, (ast.Name, ast.Attribute)):
            continue
        source = last_segment(dotted_path(node.value))
        for target in node.targets:
            if isinstance(target, ast.Name) and source:
                aliases.setdefault(target.id, source)
    return aliases


def _resolve_function(
    reference: ast.expr,
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    aliases: dict[str, str],
) -> tuple[str, ast.FunctionDef | ast.AsyncFunctionDef | None]:
    name = last_segment(dotted_path(reference))
    seen: set[str] = set()
    while name and name not in functions and name in aliases and name not in seen:
        seen.add(name)
        name = aliases[name]
    return name, functions.get(name)


def _registered_tools(tree: ast.Module, path: str, claimed: set[int]) -> list[ToolDefinition]:
    """Tools passed to a registration call rather than wearing a decorator."""
    functions = _function_table(tree)
    aliases = _name_aliases(tree)
    tools: list[ToolDefinition] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        if last_segment(_decorator_path(node.func)) not in TOOL_REGISTRATION_SUFFIXES:
            continue
        reference = node.args[0]
        # `@mcp.tool("search_docs")` passes a name, not a function. Only a
        # reference to something callable is a registration.
        if not isinstance(reference, (ast.Name, ast.Attribute)):
            continue
        function_name, func = _resolve_function(reference, functions, aliases)
        if func is not None and id(func) in claimed:
            continue
        if func is not None:
            claimed.add(id(func))
        tools.append(
            ToolDefinition(
                name=_tool_name_from_decorator(node, function_name),
                function_name=function_name,
                path=path,
                # Point at the implementation when we found it; the
                # registration call is only a stand-in.
                line=func.lineno if func is not None else node.lineno,
                parameters=_caller_supplied_params(func) if func is not None else [],
                decorator=_decorator_path(node.func),
                node=func,
            )
        )
    return tools


def parse_file(path: Path) -> ast.Module | None:
    """Parse a file, returning None if it isn't valid Python.

    A syntax error is not our problem to report -- the user's own tooling
    will catch it -- so we skip rather than crash the whole scan.
    """
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        return ast.parse(source, filename=str(path))
    except SyntaxError:
        return None


def iter_python_files(root: Path) -> list[Path]:
    """Walk a directory for .py files, skipping the usual noise."""
    skip_dirs = {
        ".git", ".venv", "venv", "__pycache__", "node_modules",
        ".tox", ".mypy_cache", ".pytest_cache", "build", "dist",
    }
    if root.is_file():
        return [root] if root.suffix == ".py" else []
    files: list[Path] = []
    for p in root.rglob("*.py"):
        if any(part in skip_dirs for part in p.parts):
            continue
        files.append(p)
    return sorted(files)
