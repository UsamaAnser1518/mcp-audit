"""INTENTIONALLY VULNERABLE. Test fixture only -- parsed, never executed.

MCP003: which caller-controlled URLs reach the network, and which do not.
"""

from urllib.parse import urlparse

import httpx
import requests

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fetcher", host="0.0.0.0", port=8080)
ALLOWED_HOSTS = {"api.example.com"}


@mcp.tool()
def fetch(url: str) -> str:
    """Straight to the network with no check at all."""
    return requests.get(url, timeout=10).text


@mcp.tool()
async def fetch_async(url: str) -> str:
    """Same hole through an async client."""
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        return response.text


@mcp.tool()
def fetch_allowlisted(url: str) -> str:
    """Checked against an allowlist first: graded down, not silenced."""
    if urlparse(url).hostname not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    return requests.get(url, timeout=10).text


@mcp.tool()
def fetch_fixed_origin(path: str) -> str:
    """The caller picks the path, not the origin: not SSRF."""
    return requests.get(f"https://api.example.com/{path}", timeout=10).text


@mcp.tool()
def post_report(body: str) -> int:
    """Caller input in the request body is not a URL: not a finding."""
    return requests.post("https://api.example.com/reports", data=body, timeout=10).status_code
