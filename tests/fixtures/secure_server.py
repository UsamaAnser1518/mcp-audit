"""Test fixture only -- parsed, never executed.

The negative control. This server does the right thing at every point the
other fixtures get wrong, so any finding here is a false positive and the
test that scans it should fail.
"""

from __future__ import annotations

import hmac
import os
import shlex
import sqlite3
import subprocess
from pathlib import Path
from urllib.parse import urlparse

import requests
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

ALLOWED_HOSTS = {"api.example.com"}
DATA_ROOT = Path("/srv/data").resolve()
API_KEY = os.environ["MCP_API_KEY"]
API_KEY_HEADER = "X-API-Key"

mcp = FastMCP(
    "secure",
    host="127.0.0.1",
    port=8443,
    auth=AuthSettings(issuer_url="https://auth.example.com", required_scopes=["mcp:read"]),
)
db = sqlite3.connect("/srv/data/app.db")


def check_api_key(supplied: str) -> bool:
    """Constant time, and the key comes from the environment."""
    return hmac.compare_digest(supplied, API_KEY)


@mcp.tool()
def read_note(name: str, scopes: list[str]) -> str:
    """Path resolved against a fixed root, then checked for containment."""
    require_scope(scopes, "mcp:read")
    target = Path(DATA_ROOT, name).resolve()
    target.relative_to(DATA_ROOT)
    return target.read_text()


@mcp.tool()
def git_log(count: str, scopes: list[str]) -> str:
    """Fixed argument vector, and the caller's value is coerced to an int."""
    require_scope(scopes, "mcp:read")
    return subprocess.run(
        ["git", "log", "-n", str(int(count))], capture_output=True, check=True
    ).stdout.decode()


@mcp.tool()
def grep_logs(pattern: str, scopes: list[str]) -> str:
    """A shell is unavoidable here, so the value is quoted for it."""
    require_scope(scopes, "mcp:write")
    return subprocess.check_output(f"grep {shlex.quote(pattern)} /var/log/app.log", shell=True)


@mcp.tool()
def lookup_user(user_id: str, scopes: list[str]) -> list:
    """Bound parameter, not string interpolation."""
    require_scope(scopes, "mcp:read")
    return db.execute("SELECT name FROM users WHERE id = ?", (user_id,)).fetchall()


@mcp.tool()
def fetch(url: str, scopes: list[str]) -> str:
    """Host checked against an allowlist before the request is made."""
    require_scope(scopes, "mcp:read")
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return requests.get(url, timeout=10, allow_redirects=False).text
