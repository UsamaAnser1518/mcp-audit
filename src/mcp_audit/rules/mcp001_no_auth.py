"""MCP001 -- tools exposed with no authentication.

The most common finding in surveys of public MCP servers, and the one with
the least interesting root cause: the server was written for a local stdio
session and later put on a port.

Two decisions keep this rule from becoming noise people mute:

  * stdio servers are not reported. The MCP authorization spec covers
    HTTP transports; a stdio server's trust boundary is the process that
    spawned it, and credentials come from the environment. Flagging every
    local server would teach users to ignore the rule.
  * any credible sign of authentication anywhere in the file suppresses
    it. This rule claims only that a mechanism is *present*. Whether it is
    any good is MCP002's and MCP005's problem.
"""

from __future__ import annotations

import ast
import re

from ..astutil import (
    build_alias_map,
    dotted_path,
    keyword_of,
    last_segment,
    resolve,
    string_constant,
)
from ..finding import Finding, Severity
from .base import Rule, ScanContext, register

# Any identifier or short literal matching this counts as evidence that
# somebody thought about authentication.
#
# "auth" would swallow "author"/"authors" (a tool that lists commit authors
# is not authenticated), so those are carved out -- but "authorization"
# and "authorize" must still match, which is why the exclusion is anchored
# on the end of the word rather than a plain word boundary.
_AUTH_EVIDENCE = re.compile(
    r"auth(?!ors?(?![A-Za-z]))"
    r"|bearer|jwt|api[_-]?key|x-api-key|credential|token[_-]?verif"
    r"|verify[_-]?token|access[_-]?token|compare_digest|hmac",
    re.IGNORECASE,
)

# Transports that put the server on a network, where the spec expects
# OAuth 2.1 and where "no auth" means "anyone who can route to the port".
_NETWORK_TRANSPORTS = {"sse", "http", "streamable-http", "streamable_http", "ws", "websocket"}
_STDIO_TRANSPORTS = {"stdio"}

# ASGI plumbing only a network-facing server needs.
_NETWORK_CALLS = {
    "sse_app",
    "streamable_http_app",
    "run_sse_async",
    "run_streamable_http_async",
    "SseServerTransport",
    "StreamableHTTPSessionManager",
}
_NETWORK_IMPORTS = {"uvicorn", "starlette", "fastapi", "hypercorn", "gunicorn", "flask"}
_STDIO_CALLS = {"stdio_server", "run_stdio_async"}

# Modules whose `run` is not a server transport. `subprocess.run(...)` must
# never be read as "this server runs on stdio".
_NOT_TRANSPORT_ROOTS = {
    "subprocess", "asyncio", "os", "anyio", "trio", "uvicorn", "multiprocessing",
}

# Calls where host=/port= means "listen here" rather than "connect there".
_LISTENER_CALLS = {"run", "serve", "FastMCP", "Server", "start"}


@register
class NoAuthentication(Rule):
    """Tools reachable over a network transport with no authentication in sight."""

    id = "MCP001"
    title = "Tools exposed without authentication"
    severity = Severity.HIGH
    remediation = (
        "Put the server behind OAuth 2.1 as the MCP authorization spec describes (formalised "
        "in the 2025-11-25 revision), or at minimum require a bearer credential compared with "
        "hmac.compare_digest() before dispatching a tool call. If the server is only ever "
        "spawned over stdio, say so in the README so the next reader does not deploy it."
    )

    def check(self, ctx: ScanContext) -> list[Finding]:
        if not ctx.tools:
            return []
        try:
            aliases = build_alias_map(ctx.tree)
            transport = infer_transport(ctx.tree, aliases)
            if transport == "stdio":
                return []
            if auth_evidence(ctx.tree):
                return []
        except Exception:  # noqa: BLE001 -- a rule crash must not abort the scan
            return []

        names = [tool.name for tool in ctx.tools]
        shown = ", ".join(f"`{n}`" for n in names[:5])
        if len(names) > 5:
            shown += f" and {len(names) - 5} more"
        where = (
            "The server is configured for a network transport."
            if transport == "network"
            else "No transport is configured in this file, so the safe reading is a network one."
        )
        detail = (
            f"{len(names)} tool(s) are registered here ({shown}) and nothing in this file "
            f"authenticates the caller. {where} Every tool is callable by anyone who can reach "
            "the port."
        )
        return [self.finding(ctx, line=ctx.tools[0].line, detail=detail)]


def auth_evidence(tree: ast.Module) -> str | None:
    """The first identifier or literal suggesting authentication exists.

    Docstrings are excluded. "This tool requires no authentication" is a
    sentence about the problem, not a solution to it, and letting prose
    suppress the rule would gut it.
    """
    docstrings = _docstring_nodes(tree)
    for node in ast.walk(tree):
        for token in _tokens(node, docstrings):
            if token and _AUTH_EVIDENCE.search(token):
                return token
    return None


def infer_transport(tree: ast.Module, aliases: dict[str, str]) -> str:
    """"network", "stdio", or "unknown".

    Network evidence wins over stdio evidence: a file that can serve both
    is exposed either way, and the network case is the one worth reporting.
    """
    network = False
    stdio = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            network |= any(a.name.split(".")[0] in _NETWORK_IMPORTS for a in node.names)
            continue
        if isinstance(node, ast.ImportFrom):
            network |= bool(node.module) and node.module.split(".")[0] in _NETWORK_IMPORTS
            continue
        if not isinstance(node, ast.Call):
            continue
        path = resolve(dotted_path(node.func), aliases)
        segment = last_segment(path)
        root = path.split(".")[0]
        if segment in _NETWORK_CALLS or root == "uvicorn":
            network = True
        if segment in _STDIO_CALLS:
            stdio = True
        if segment in _LISTENER_CALLS and (
            keyword_of(node, "host") is not None or keyword_of(node, "port") is not None
        ):
            network = True
        if segment == "run" and root not in _NOT_TRANSPORT_ROOTS:
            named = string_constant(keyword_of(node, "transport"))
            positional = string_constant(node.args[0]) if node.args else None
            chosen = (named or positional or "").lower()
            if chosen in _NETWORK_TRANSPORTS:
                network = True
            elif chosen in _STDIO_TRANSPORTS:
                stdio = True
            elif not node.args and not node.keywords:
                stdio = True  # FastMCP.run() with no arguments defaults to stdio
    if network:
        return "network"
    return "stdio" if stdio else "unknown"


def _docstring_nodes(tree: ast.Module) -> set[int]:
    holders = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    found: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, holders) or not node.body:
            continue
        first = node.body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
            if isinstance(first.value.value, str):
                found.add(id(first.value))
    return found


def _tokens(node: ast.AST, docstrings: set[int]) -> list[str]:
    """Identifier-ish text attached to one node, for evidence matching."""
    if isinstance(node, ast.Import):
        return [a.name for a in node.names] + [a.asname or "" for a in node.names]
    if isinstance(node, ast.ImportFrom):
        return [node.module or ""] + [a.name for a in node.names]
    if isinstance(node, ast.Name):
        # Only a *use* counts. `API_KEY = "..."` at the top of a file with no
        # check anywhere is a credential nobody validates -- MCP002's problem,
        # and not a reason to believe this server authenticates callers.
        return [] if isinstance(node.ctx, (ast.Store, ast.Del)) else [node.id]
    if isinstance(node, ast.Attribute):
        return [node.attr]
    if isinstance(node, ast.keyword):
        return [node.arg or ""]
    if isinstance(node, ast.arg):
        return [node.arg]
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        # Header names and scheme literals, not prose: a value with spaces
        # or paragraph length is documentation, whatever words it contains.
        if id(node) in docstrings or len(node.value) > 40 or " " in node.value.strip():
            return []
        return [node.value]
    return []
