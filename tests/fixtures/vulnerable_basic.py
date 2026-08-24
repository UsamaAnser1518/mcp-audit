"""INTENTIONALLY VULNERABLE. Test fixture only -- never deploy this.

Exercises the decorator shapes mcp-audit must recognise.
"""

import subprocess

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo-server")

API_KEY = "sk-hardcoded-secret-do-not-do-this"


@mcp.tool()
async def fetch_url(url: str, timeout: int = 10) -> str:
    """SSRF: caller-controlled URL reaches the network with no allowlist."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, timeout=timeout)
        return resp.text


@mcp.tool
def run_command(cmd: str) -> str:
    """Command injection: parameter flows straight into a shell."""
    return subprocess.check_output(cmd, shell=True).decode()


@mcp.tool(name="lookup_user")
def _lookup(user_id: str, ctx=None) -> dict:
    """Renamed tool. `ctx` is framework-injected, not caller input."""
    return {"id": user_id}


@mcp.tool("legacy_positional_name")
def legacy(query: str) -> str:
    """Name passed positionally rather than as a keyword."""
    return query


def not_a_tool(x: int) -> int:
    """No decorator -- must not appear in the inventory."""
    return x * 2
