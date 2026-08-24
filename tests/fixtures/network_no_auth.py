"""INTENTIONALLY VULNERABLE. Test fixture only -- parsed, never executed.

MCP001: an HTTP-transport server with nothing checking who is calling.
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("public-server", host="0.0.0.0", port=8080)


@mcp.tool()
def list_customers() -> list[str]:
    """Reads the CRM. Reachable by anyone who can route to the port."""
    return ["acme", "globex"]


@mcp.tool()
def delete_customer(customer_id: str) -> bool:
    """Destructive, and just as open."""
    return bool(customer_id)


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
