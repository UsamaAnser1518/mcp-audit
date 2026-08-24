"""Test fixture only -- parsed, never executed.

MCP001 must stay quiet here. A stdio server's trust boundary is the process
that spawned it, so having no network authentication is the design, not a
defect.
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("local-notes")


@mcp.tool()
def read_note(name: str) -> str:
    """Returns a note by name."""
    return name.upper()


if __name__ == "__main__":
    mcp.run()
