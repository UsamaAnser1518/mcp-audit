"""INTENTIONALLY VULNERABLE. Test fixture only -- parsed, never executed.

MCP001 stays quiet: this server does check a credential. MCP002 does not:
the fallback key is a literal and the check short-circuits on the first
wrong byte.
"""

import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("keyed", host="127.0.0.1", port=9000)

API_KEY_HEADER = "X-API-Key"
FALLBACK_KEY = "sk-live-6f2b9c41d0e84a17"


def authenticate(headers: dict) -> bool:
    api_key = headers.get(API_KEY_HEADER, "")
    return api_key == os.environ.get("MCP_API_KEY", FALLBACK_KEY)


@mcp.tool()
def whoami(headers: dict) -> str:
    """Authenticated, badly."""
    if not authenticate(headers):
        raise PermissionError("bad key")
    return "ok"
