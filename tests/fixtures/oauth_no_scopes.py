"""Test fixture only -- parsed, never executed.

MCP005: tokens are verified, but nothing asks what the token is allowed to
do, so the read tool and the delete tool take the same credential.
"""

from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP


class IntrospectingVerifier(TokenVerifier):
    async def verify_token(self, token: str):
        return {"active": True}


mcp = FastMCP(
    "documents",
    host="0.0.0.0",
    port=8443,
    token_verifier=IntrospectingVerifier(),
    auth=AuthSettings(issuer_url="https://auth.example.com"),
)


@mcp.tool()
def read_document(doc_id: str) -> str:
    """Read-only."""
    return f"contents of {doc_id}"


@mcp.tool()
def delete_document(doc_id: str) -> bool:
    """Destructive, and reachable with the same token."""
    return bool(doc_id)
