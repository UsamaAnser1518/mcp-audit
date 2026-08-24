"""MCP004 -- tool input reaching a dangerous sink.

The shape every finding here has: a caller-controlled tool parameter, an
unbroken path through local assignments and string building, and a call
that interprets its argument as a command, as code, as a path, or as SQL.

Everything is intraprocedural. A parameter handed to a helper function
leaves our view and is not reported; see the README's Limitations.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from ..astutil import (
    build_alias_map,
    dotted_path,
    is_true,
    keyword_of,
    last_segment,
    matches,
    resolve,
)
from ..finding import Finding, Severity
from ..taint import TaintSet, analyse, is_dynamic_string, looks_guarded, taint_origins
from .base import Rule, ScanContext, register


@dataclass(frozen=True)
class _Sink:
    """One family of dangerous calls.

    `patterns` are matched by `astutil.matches`, so a bare name means a
    builtin (exact) and a leading dot means "any receiver, this method".
    """

    patterns: tuple[str, ...]
    kind: str
    # Which positional arguments carry the payload. Empty means all of them:
    # subprocess takes the command in argv[0] or as a list, os.system in
    # argv[0], and there is no harm in looking at the rest. A sink that
    # takes data in later positions (execute's parameter tuple) pins this
    # down so we do not report the safe half of a parameterised call.
    arg_indices: tuple[int, ...] = ()
    kwargs: frozenset[str] = frozenset()
    # SQL only: a constant query with bound parameters is the *fix*, not the
    # bug. Report only when the statement was built by string construction.
    requires_interpolation: bool = False


_SINKS: tuple[_Sink, ...] = (
    _Sink(
        patterns=(
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.Popen",
            "subprocess.getoutput",
            "subprocess.getstatusoutput",
            "asyncio.create_subprocess_shell",
            "asyncio.create_subprocess_exec",
            "os.system",
            "os.popen",
            "os.execv",
            "os.execvp",
            "os.spawnv",
        ),
        kind="shell",
        kwargs=frozenset({"args", "cmd"}),
    ),
    _Sink(patterns=("eval", "exec", "compile"), kind="code", arg_indices=(0,)),
    _Sink(
        patterns=("open", "os.remove", "os.unlink", "os.rmdir", "shutil.rmtree"),
        kind="path",
        arg_indices=(0,),  # argument 1 of open() is the mode, not a path
    ),
    _Sink(
        # Path(base, user) joins segments, so the caller's value is as
        # dangerous in position 1 as in position 0. os.path.join is
        # deliberately absent: it builds a path but never opens one, so
        # flagging it would report the same issue twice on
        # `open(os.path.join(base, name))`.
        patterns=("pathlib.Path", "pathlib.PurePath"),
        kind="path",
    ),
    _Sink(
        patterns=(".execute", ".executemany", ".executescript"),
        kind="sql",
        arg_indices=(0,),
        requires_interpolation=True,
    ),
)

# `(base / user).resolve().relative_to(base)` raises when the resolved path
# escapes the base. Unlike MCP003's allowlist guess, that is a complete check
# rather than a sign that somebody tried, so recognising it is reason enough
# to stay quiet.
_CONTAINMENT_CHECKS = frozenset({"relative_to", "is_relative_to", "commonpath", "commonprefix"})

_REMEDIATION = {
    "shell": (
        "Pass a fixed argument list with shell=False and keep caller input out of argv[0]. "
        "If a shell is genuinely required, wrap the value in shlex.quote()."
    ),
    "code": (
        "Do not evaluate caller input. Map the request onto a fixed set of operations, or "
        "parse it with ast.literal_eval() if you only need a literal."
    ),
    "path": (
        "Resolve the path against a fixed base directory and reject anything that escapes it: "
        "base = Path(BASE).resolve(); target = (base / user).resolve(); "
        "target.relative_to(base)."
    ),
    "sql": (
        "Use a parameterised query -- cursor.execute('... WHERE id = ?', (value,)). "
        "Never build SQL with f-strings, % or .format()."
    ),
}


@register
class DangerousSink(Rule):
    """Caller-controlled input reaching a shell, an interpreter, a path, or SQL."""

    id = "MCP004"
    title = "Tool input reaches a dangerous sink"
    severity = Severity.CRITICAL
    remediation = _REMEDIATION["shell"]

    def check(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.tools:
            return []
        aliases = build_alias_map(ctx.tree)
        findings: list[Finding] = []
        for tool in ctx.tools:
            func = tool.node
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue  # a malformed inventory entry costs one tool, not the scan
            try:
                findings.extend(self._check_tool(ctx, tool, func, aliases))
            except Exception:  # noqa: BLE001 -- one bad tool must not lose the others
                continue
        return findings

    def _check_tool(self, ctx, tool, func, aliases: dict[str, str]) -> list[Finding]:
        taints = analyse(func, tool.parameters, aliases)
        if not taints:
            return []
        findings: list[Finding] = []
        # One line, one finding per sink kind. `open(Path(base, name))` is a
        # single mistake even though two sinks match it.
        seen: set[tuple[int, str]] = set()
        # Both computed once, and only if a path sink actually turns up.
        contained = None
        guarded = None
        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue
            sink = _match_sink(node, aliases)
            if sink is None:
                continue
            origins = _tainted_arguments(node, sink, taints, aliases)
            if not origins:
                continue
            # A path is the one sink where validation, rather than a
            # different API, is the accepted fix -- so seeing a check here
            # means something. For a shell or a query it would not: the fix
            # there is an argument list or a bound parameter, and "they
            # validated it first" does not lower the risk much.
            downgrade = False
            if sink.kind == "path":
                if contained is None:
                    contained = _has_containment_check(func, taints, aliases)
                if contained:
                    continue  # resolve()/relative_to() is a complete check
                if guarded is None:
                    guarded = looks_guarded(func, taints, aliases)
                downgrade = guarded
            key = (node.lineno, sink.kind)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                self.finding(
                    ctx,
                    line=node.lineno,
                    column=node.col_offset + 1,
                    tool_name=tool.name,
                    detail=_detail(node, sink, origins, aliases, guarded=downgrade),
                    remediation=_REMEDIATION[sink.kind],
                    severity=Severity.HIGH if downgrade else None,
                )
            )
        return findings


def _match_sink(call: ast.Call, aliases: dict[str, str]) -> _Sink | None:
    path = resolve(dotted_path(call.func), aliases)
    if not path:
        return None
    for sink in _SINKS:
        if matches(path, sink.patterns):
            return sink
    return None


def _tainted_arguments(
    call: ast.Call, sink: _Sink, taints: TaintSet, aliases: dict[str, str]
) -> set[str]:
    """Tool parameters reaching the arguments this sink actually interprets."""
    origins: set[str] = set()
    for index, arg in enumerate(call.args):
        if sink.arg_indices and index not in sink.arg_indices:
            continue
        if isinstance(arg, ast.Starred):
            arg = arg.value
        if sink.requires_interpolation and not is_dynamic_string(arg, taints):
            continue
        origins |= taint_origins(arg, taints, aliases)
    for name in sink.kwargs:
        value = keyword_of(call, name)
        if value is None:
            continue
        if sink.requires_interpolation and not is_dynamic_string(value, taints):
            continue
        origins |= taint_origins(value, taints, aliases)
    return origins


def _short_label(path: str) -> str:
    """`sqlite3.connect.cursor.execute` reads better as `cursor.execute`."""
    segs = path.split(".")
    return ".".join(segs[-2:]) if len(segs) > 2 else path


def _detail(
    call: ast.Call,
    sink: _Sink,
    origins: set[str],
    aliases: dict[str, str],
    guarded: bool = False,
) -> str:
    params = ", ".join(f"`{name}`" for name in sorted(origins))
    many = len(origins) > 1
    subject = f"Tool parameter{'s' if many else ''} {params}"
    reach = "reach" if many else "reaches"
    are = "are" if many else "is"
    path = resolve(dotted_path(call.func), aliases)
    label = _short_label(path) + "()"
    if sink.kind == "shell":
        if is_true(keyword_of(call, "shell")) or _always_shell(path):
            return (
                f"{subject} {reach} {label}, which hands the value to a shell. A caller can "
                "chain arbitrary commands with ; && | or backticks."
            )
        return (
            f"{subject} {reach} {label} as part of the argument vector. There is no shell to "
            f"inject into, but the caller still chooses the arguments -- and if the value can "
            "land in argv[0], the executable itself."
        )
    if sink.kind == "code":
        return (
            f"{subject} {reach} {label}. Whatever the caller sends is executed as Python with "
            "the server's privileges."
        )
    if sink.kind == "path":
        if guarded:
            return (
                f"{subject} {are} used as a filesystem path in {label}. This tool does check "
                "the value first, so confirm the check runs before every use and that it "
                "compares resolved paths -- ../ and symlinks both survive a naive test."
            )
        return (
            f"{subject} {are} used as a filesystem path in {label}. A caller can traverse out "
            "of the intended directory with ../ or pass an absolute path."
        )
    return (
        f"{subject} {are} interpolated into the statement passed to {label}. The value becomes "
        "part of the SQL rather than data inside it."
    )


def _has_containment_check(func, taints: TaintSet, aliases: dict[str, str]) -> bool:
    """Does this function check that the resolved path stays under a base?"""
    for node in ast.walk(func):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if last_segment(dotted_path(node.func)) not in _CONTAINMENT_CHECKS:
            continue
        # The checked value is usually the receiver -- target.relative_to(BASE)
        # -- but os.path.commonpath([base, target]) puts it in the arguments.
        if taint_origins(node.func.value, taints, aliases):
            return True
        if any(taint_origins(arg, taints, aliases) for arg in node.args):
            return True
    return False


def _always_shell(path: str) -> bool:
    """Calls that run a shell whether or not shell= is passed."""
    return path.rsplit(".", 1)[-1] in {
        "system",
        "popen",
        "create_subprocess_shell",
        "getoutput",
        "getstatusoutput",
    }
