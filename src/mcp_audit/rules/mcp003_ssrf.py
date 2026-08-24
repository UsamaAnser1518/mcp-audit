"""MCP003 -- caller-controlled URL reaching a network call.

Same intraprocedural taint as MCP004, different sinks. The interesting
part of an SSRF check is not the sink list, it is knowing when to stay
quiet:

  * a guard on the URL that raises or returns grades the finding down to
    medium instead of leaving it at high. We cannot tell a correct
    allowlist from one that forgot 169.254.169.254, but we can tell that
    somebody tried, and a server that tried should not fail a
    `--fail-on high` build over a check we never read.
  * a URL whose scheme and host are fixed literals is not SSRF. The caller
    can only influence the path, which is a different bug in a different
    rule.
"""

from __future__ import annotations

import ast
import re

from ..astutil import build_alias_map, dotted_path, keyword_of, last_segment, resolve
from ..finding import Finding, Severity
from ..taint import TaintSet, analyse, looks_guarded, taint_origins
from .base import Rule, ScanContext, register

_HTTP_ROOTS = {"requests", "httpx", "aiohttp", "urllib", "urllib3", "http", "socket", "websockets"}
_HTTP_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "request",
                         "stream", "send", "fetch"})
_CONNECT_CALLS = frozenset({"urlopen", "urlretrieve", "create_connection", "Request",
                            "HTTPConnection", "HTTPSConnection", "connect"})

# Verbs whose URL is the *second* argument: requests.request("GET", url).
_METHOD_FIRST = frozenset({"request", "send", "stream", "open"})

# A receiver named like a client is how requests/httpx/aiohttp are actually
# used. Without this, `session.get(url)` is invisible; with it applied
# blindly, `config.get(key)` is a false positive -- so it only applies in a
# file that imports an HTTP library.
_CLIENT_RECEIVER = re.compile(r"client|session|http|aiohttp|requests|conn|api", re.IGNORECASE)

# scheme://host/ as a literal prefix: the caller cannot move the request to
# another origin from here.
_FIXED_ORIGIN = re.compile(r"^[a-z][a-z0-9+.\-]*://[^/\s{}]+/")


@register
class UnvalidatedUrlFetch(Rule):
    """A tool parameter reaching an HTTP client without an origin check."""

    id = "MCP003"
    title = "Caller-controlled URL reaches a network call"
    severity = Severity.HIGH
    remediation = (
        "Validate the URL before fetching it: parse it, require https, and match the host "
        "against an allowlist. Reject link-local and private ranges explicitly "
        "(169.254.169.254 is the cloud metadata service) and do not follow redirects, or the "
        "allowlist only covers the first hop."
    )

    def check(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.tools:
            return []
        aliases = build_alias_map(ctx.tree)
        http_imported = _imports_http_client(ctx.tree)
        findings: list[Finding] = []
        for tool in ctx.tools:
            func = tool.node
            if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            try:
                findings.extend(self._check_tool(ctx, tool, func, aliases, http_imported))
            except Exception:  # noqa: BLE001 -- one bad tool must not lose the others
                continue
        return findings

    def _check_tool(self, ctx, tool, func, aliases, http_imported) -> list[Finding]:
        taints = analyse(func, tool.parameters, aliases)
        if not taints:
            return []
        guarded = looks_guarded(func, taints, aliases)
        findings: list[Finding] = []
        seen: set[tuple[int, int]] = set()
        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue
            if not _is_network_sink(node, aliases, http_imported):
                continue
            for url in _url_arguments(node, aliases):
                if _has_fixed_origin(url, taints):
                    continue
                origins = taint_origins(url, taints, aliases)
                if not origins:
                    continue
                key = (node.lineno, node.col_offset)
                if key in seen:
                    continue
                seen.add(key)
                params = ", ".join(f"`{name}`" for name in sorted(origins))
                many = len(origins) > 1
                reach = "reach" if many else "reaches"
                label = last_segment(resolve(dotted_path(node.func), aliases))
                if guarded:
                    detail = (
                        f"Tool parameter{'s' if many else ''} {params} {reach} the URL of "
                        f"a {label}() call. This tool does check the value first, so confirm the "
                        "check covers redirects, private ranges and the cloud metadata address."
                    )
                else:
                    detail = (
                        f"Tool parameter{'s' if many else ''} {params} {reach} the URL of "
                        f"a {label}() call with no origin check. The caller chooses what the "
                        "server connects to, including 127.0.0.1 and 169.254.169.254, and gets "
                        "the response back."
                    )
                findings.append(
                    self.finding(
                        ctx,
                        line=node.lineno,
                        column=node.col_offset + 1,
                        tool_name=tool.name,
                        detail=detail,
                        severity=Severity.MEDIUM if guarded else None,
                    )
                )
        return findings


def _imports_http_client(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(a.name.split(".")[0] in _HTTP_ROOTS for a in node.names):
                return True
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] in _HTTP_ROOTS:
                return True
    return False


def _is_network_sink(call: ast.Call, aliases: dict[str, str], http_imported: bool) -> bool:
    path = resolve(dotted_path(call.func), aliases)
    if not path:
        return False
    segments = path.split(".")
    verb = segments[-1]
    root = segments[0]
    if root in _HTTP_ROOTS and (verb in _HTTP_VERBS or verb in _CONNECT_CALLS):
        return True
    if verb in _CONNECT_CALLS and root not in {"sqlite3", "psycopg2", "pymysql"}:
        return True
    if verb in _HTTP_VERBS and len(segments) >= 2 and http_imported:
        return bool(_CLIENT_RECEIVER.search(segments[-2]))
    return False


def _url_arguments(call: ast.Call, aliases: dict[str, str]) -> list[ast.expr]:
    """The arguments that name what to connect to, and only those.

    `requests.post(url, data=payload)` puts caller input in `data` all the
    time; that is not SSRF and reporting it would be a lie.
    """
    verb = last_segment(resolve(dotted_path(call.func), aliases))
    index = 1 if verb in _METHOD_FIRST else 0
    args = [call.args[index]] if len(call.args) > index else []
    for name in ("url", "uri", "endpoint", "host"):
        value = keyword_of(call, name)
        if value is not None:
            args.append(value)
    return args


def _has_fixed_origin(node: ast.expr, taints: TaintSet) -> bool:
    """Is the scheme and host of this URL a literal in the source?"""
    if isinstance(node, ast.JoinedStr):
        first = node.values[0] if node.values else None
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return bool(_FIXED_ORIGIN.match(first.value))
        return False
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        left = node.left
        if isinstance(left, ast.Constant) and isinstance(left.value, str):
            return bool(_FIXED_ORIGIN.match(left.value))
    return False
