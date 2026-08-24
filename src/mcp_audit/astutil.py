"""Small AST helpers shared by detection and the rules.

These live outside `detect` so a rule can resolve a call target without
importing the detector, and so every consumer agrees on what a dotted path
is. Getting this wrong in two places independently is how a scanner ends up
matching `subprocess.run` in one rule and missing it in another.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable


def dotted_path(node: ast.expr | None) -> str:
    """Render an expression as a dotted string.

        tool                 -> "tool"
        mcp.tool             -> "mcp.tool"
        mcp.tool(name=...)   -> unwrap the call, then as above
        httpx.Client().get   -> "httpx.Client.get"

    Anything else -- a subscript, a literal, a lambda -- renders as "",
    which callers read as "unresolvable, do not match it".
    """
    if isinstance(node, ast.Call):
        return dotted_path(node.func)
    if isinstance(node, ast.Attribute):
        prefix = dotted_path(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def last_segment(path: str) -> str:
    return path.rsplit(".", 1)[-1]


def build_alias_map(tree: ast.Module) -> dict[str, str]:
    """Map local names back to the fully qualified thing they refer to.

        import subprocess as sp        -> {"sp": "subprocess"}
        from subprocess import run     -> {"run": "subprocess.run"}
        from os.path import join as j  -> {"j": "os.path.join"}

    Sink patterns are written fully qualified. Without this map,
    `from subprocess import check_output` renders as a bare "check_output"
    and matches nothing -- a silent false negative, which is the failure
    mode this project cares most about avoiding.

    Relative imports are skipped: there is no package context to resolve
    them against, and a guess would be worse than an honest blank.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                # `import os.path` binds `os`; `import os.path as p` binds the full path.
                aliases[alias.asname or root] = alias.name if alias.asname else root
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                continue
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def resolve(path: str, aliases: dict[str, str]) -> str:
    """Rewrite the head of a dotted path through the alias map."""
    if not path:
        return path
    head, _, rest = path.partition(".")
    target = aliases.get(head)
    if not target:
        return path
    return f"{target}.{rest}" if rest else target


def resolve_call(node: ast.expr | None, aliases: dict[str, str]) -> str:
    """Fully qualified target of a call expression, as far as we can tell."""
    return resolve(dotted_path(node), aliases)


def matches(path: str, patterns: Iterable[str]) -> str | None:
    """Match a dotted path against patterns, returning the one that hit.

    Three pattern shapes, deliberately distinct so a rule author picks the
    precision they want:

        "subprocess.run"  dotted  -- segment-aligned suffix match, so it
                                     covers `subprocess.run(...)` without
                                     letting `mysubprocess.run(...)` in.
        "eval"            bare    -- exact match only. A bare name is a
                                     builtin; matching it as a suffix would
                                     flag `model.compile(...)` as `compile`.
        ".execute"        leading -- last segment only, for methods whose
                             dot    receiver we cannot resolve statically
                                     (`cur.execute`, `conn.execute`).
    """
    if not path:
        return None
    segs = path.split(".")
    for pattern in patterns:
        if pattern.startswith("."):
            if segs[-1] == pattern[1:]:
                return pattern
            continue
        psegs = pattern.split(".")
        if len(psegs) == 1:
            if path == pattern:
                return pattern
        elif len(psegs) <= len(segs) and segs[-len(psegs) :] == psegs:
            return pattern
    return None


def keyword_of(call: ast.Call, name: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def is_true(node: ast.expr | None) -> bool:
    """Literal `True`, as opposed to something merely truthy at runtime."""
    return isinstance(node, ast.Constant) and node.value is True


def string_constant(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def call_repr(call: ast.Call, aliases: dict[str, str] | None = None) -> str:
    """A short `name(...)` label for a call, for use in finding messages."""
    path = dotted_path(call.func)
    if aliases:
        path = resolve(path, aliases) or path
    return f"{path or '<call>'}()"
