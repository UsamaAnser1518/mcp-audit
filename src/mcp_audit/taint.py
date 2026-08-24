"""Intraprocedural taint tracking, shared by the injection rules.

MCP003 (SSRF) and MCP004 (dangerous sinks) ask the same question with
different sink lists: can a caller-controlled tool parameter reach this
call? Keeping the propagation in one place means the two rules cannot
drift apart on what "reaches" means.

The analysis stops at the edge of the function body. Following a parameter
into a helper needs a call graph and an interprocedural fixpoint, which is
a different tool; the README's Limitations section says so and must keep
saying so.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterable, Iterator

from .astutil import dotted_path, last_segment, matches, resolve

# Calls that destroy an injection payload by construction: int("; rm -rf /")
# raises rather than returning something a shell would act on, and
# shlex.quote() hands the shell a single inert argument. A value that has
# been through one of these is no longer interesting.
#
# Matching goes through the alias map, so `from shlex import quote` still
# resolves to shlex.quote rather than reading as some unrelated `quote`.
NEUTRALISING_CALLS = frozenset({"int", "float", "bool", "len", "shlex.quote"})

# Methods that paste a value into the middle of a larger string. A tool
# parameter that arrives at a sink this way is a *structural* part of the
# command or query, which is precisely what parameterised APIs prevent.
STRING_BUILDING_METHODS = frozenset({"format", "format_map", "join"})

# Names that read as "the author tested this value before using it". Matched
# on the last segment of the call target, so `url_is_allowed(url)` and
# `target.relative_to(BASE)` both count.
GUARD_NAMES = re.compile(
    r"valid|allow|check|ensure|sanit|verify|assert|guard|require|permit"
    r"|relative_to|commonpath|commonprefix",
    re.IGNORECASE,
)

# ...except in subprocess, where "check" means "raise if the exit code is
# non-zero". Without this, check_output() would vouch for its own argument.
NOT_GUARDS = frozenset({"check_output", "check_call"})

# Convergence is guaranteed -- the name set only grows -- but a long alias
# chain in a pathological file should not cost quadratic time.
_MAX_ROUNDS = 32


class TaintSet:
    """Local names carrying caller-controlled data, and where it came from.

    Names may be dotted (`self.command`): an attribute write is tracked as
    its own path rather than by tainting the whole receiver, which would
    make every later `self.anything` look dangerous.
    """

    def __init__(self, parameters: Iterable[str] = ()) -> None:
        self._origins: dict[str, set[str]] = {p: {p} for p in parameters}
        self._interpolated: set[str] = set()

    def __contains__(self, name: object) -> bool:
        return name in self._origins

    def __bool__(self) -> bool:
        return bool(self._origins)

    def __repr__(self) -> str:
        return f"TaintSet({sorted(self._origins)})"

    def names(self) -> set[str]:
        return set(self._origins)

    def origins(self, name: str) -> set[str]:
        """Tool parameters whose value this name can hold."""
        return set(self._origins.get(name, ()))

    def is_interpolated(self, name: str) -> bool:
        """True if this name's taint arrived through string construction."""
        return name in self._interpolated

    def add(self, name: str, origins: set[str], interpolated: bool = False) -> bool:
        """Widen the set. Returns True if anything changed, for the fixpoint."""
        current = self._origins.setdefault(name, set())
        changed = not origins <= current
        current |= origins
        if interpolated and name not in self._interpolated:
            self._interpolated.add(name)
            changed = True
        return changed


def analyse(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    parameters: Iterable[str],
    aliases: dict[str, str] | None = None,
) -> TaintSet:
    """Propagate taint from the given parameters through local bindings.

    Flow-insensitive on purpose: the result is the union over the whole
    body rather than a per-statement state, so `c = cmd` taints `c`
    wherever it appears -- inside a loop, a branch, a `with`. The cost is
    that a name later rebound to a constant stays tainted. For a triage
    tool an extra lead beats a missed injection.
    """
    aliases = aliases or {}
    taints = TaintSet(parameters)
    if not taints:
        return taints
    bindings = list(_bindings(func))
    for _ in range(min(len(bindings) + 1, _MAX_ROUNDS)):
        changed = False
        for targets, value in bindings:
            origins = taint_origins(value, taints, aliases)
            if not origins:
                continue
            built = is_string_construction(value)
            for target in targets:
                for name in _bound_names(target):
                    changed |= taints.add(name, origins, built)
        if not changed:
            break
    return taints


def taint_origins(
    node: ast.AST | None, taints: TaintSet, aliases: dict[str, str] | None = None
) -> set[str]:
    """Which tool parameters, if any, this expression's value can carry."""
    found: set[str] = set()
    if node is not None:
        _collect(node, taints, aliases or {}, found)
    return found


def is_tainted(
    node: ast.AST | None, taints: TaintSet, aliases: dict[str, str] | None = None
) -> bool:
    return bool(taint_origins(node, taints, aliases))


def is_string_construction(node: ast.AST | None) -> bool:
    """Was this value built by pasting pieces of a string together?

    f-strings, %-formatting, `+` concatenation and `.format()` are the four
    shapes that turn a parameter into part of a command line or a SQL
    statement instead of a value inside one.
    """
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call):
        return last_segment(dotted_path(node.func)) in STRING_BUILDING_METHODS
    return False


def is_dynamic_string(node: ast.AST | None, taints: TaintSet) -> bool:
    """String construction at this expression, or at the name's binding.

        cur.execute(f"... {uid}")     -- construction is right here
        q = f"... {uid}"; cur.execute(q)  -- construction was upstream
    """
    if is_string_construction(node):
        return True
    if isinstance(node, (ast.Name, ast.Attribute)):
        return taints.is_interpolated(dotted_path(node))
    return False


def _collect(node: ast.AST, taints: TaintSet, aliases: dict[str, str], found: set[str]) -> None:
    if isinstance(node, ast.Call):
        target = resolve(dotted_path(node.func), aliases)
        if matches(target, NEUTRALISING_CALLS):
            return  # the payload does not survive the call; stop descending
    if isinstance(node, ast.Name):
        found |= taints.origins(node.id)
        return
    if isinstance(node, ast.Attribute):
        path = dotted_path(node)
        if path in taints:
            found |= taints.origins(path)
            return
    for child in ast.iter_child_nodes(node):
        _collect(child, taints, aliases, found)


def _bindings(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Iterator[tuple[list[ast.expr], ast.expr]]:
    """Every (targets, value) pair in the body that binds a name.

    ast.walk rather than body iteration: an assignment nested in a `try`,
    a loop, or a branch binds a name just as well as a top-level one.
    """
    for node in ast.walk(func):
        if isinstance(node, ast.Assign):
            yield node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            yield [node.target], node.value
        elif isinstance(node, ast.AugAssign):
            yield [node.target], node.value
        elif isinstance(node, ast.NamedExpr):
            yield [node.target], node.value
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            yield [node.target], node.iter
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    yield [item.optional_vars], item.context_expr
        elif isinstance(node, ast.comprehension):
            yield [node.target], node.iter


def _bound_names(target: ast.expr) -> list[str]:
    """Names an assignment target binds.

    Tuple unpacking taints every element: we cannot tell which slot the
    tainted value lands in, and guessing wrong loses a finding.
    """
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Starred):
        return _bound_names(target.value)
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for element in target.elts:
            names.extend(_bound_names(element))
        return names
    if isinstance(target, ast.Attribute):
        path = dotted_path(target)
        return [path] if path else []
    if isinstance(target, ast.Subscript):
        # `d["cmd"] = cmd` -- taint the container, since we do not model keys.
        base = dotted_path(target.value)
        return [base] if base else []
    return []


def looks_guarded(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    taints: TaintSet,
    aliases: dict[str, str] | None = None,
) -> bool:
    """Did the author test a tainted value before using it?

    Three shapes count: a branch on the value that raises or returns, an
    assert, and a call whose name reads like a check. Deliberately
    generous, because the answer only ever softens a finding -- so a wrong
    "yes" costs one report, while a rule that flags every server which
    wrote a check nobody recognised costs the whole audience.

    What it emphatically does not do is verify the check. Whether the
    allowlist covers 169.254.169.254 is beyond a parser.
    """
    aliases = aliases or {}
    names = taints.names()
    if not names:
        return False
    for node in ast.walk(func):
        if isinstance(node, ast.If) and _mentions(node.test, names) and _exits(node.body):
            return True
        if isinstance(node, ast.Assert) and _mentions(node.test, names):
            return True
        if isinstance(node, ast.Call) and _is_guard_call(node, names, aliases):
            return True
    return False


def _is_guard_call(node: ast.Call, names: set[str], aliases: dict[str, str]) -> bool:
    target = last_segment(resolve(dotted_path(node.func), aliases))
    if target in NOT_GUARDS or not GUARD_NAMES.search(target):
        return False
    # The value under test is the argument -- validate_path(p) -- or the
    # receiver -- target.relative_to(BASE).
    if any(_mentions(arg, names) for arg in node.args):
        return True
    return isinstance(node.func, ast.Attribute) and _mentions(node.func.value, names)


def _mentions(node: ast.AST, names: set[str]) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in names:
            return True
        if isinstance(child, ast.Attribute) and dotted_path(child) in names:
            return True
    return False


def _exits(body: list[ast.stmt]) -> bool:
    return any(
        isinstance(node, (ast.Raise, ast.Return))
        for statement in body
        for node in ast.walk(statement)
    )
