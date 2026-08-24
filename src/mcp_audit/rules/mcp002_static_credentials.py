"""MCP002 -- static credentials and timing-unsafe secret comparison.

Two failures that travel together. A server with a hardcoded key almost
always checks it with `==`, and both are visible without any dataflow: the
credential is a literal in the source, and the comparison is a Compare node
with an Eq operator.

The hard part is not finding them, it is not crying wolf. `API_KEY_HEADER =
"X-API-Key"` is a header name, `token_type == "bearer"` is a protocol
check, and `MAX_TOKENS = 4096` is not a credential at all. The filters
below exist to leave those alone.
"""

from __future__ import annotations

import ast
import re

from ..finding import Finding, Severity
from .base import Rule, ScanContext, register

_SECRET_NAME = re.compile(
    r"api[_-]?key|secret|token|password|passwd|passphrase|credential"
    r"|private[_-]?key|access[_-]?key|auth[_-]?key|bearer|signing[_-]?key",
    re.IGNORECASE,
)

# A name ending this way describes a credential rather than holding one.
_NOT_A_SECRET_SUFFIX = (
    "_header", "_headers", "_name", "_names", "_env", "_var", "_field", "_url", "_uri",
    "_path", "_file", "_prefix", "_suffix", "_pattern", "_regex", "_ttl", "_expiry",
    "_len", "_length", "_type", "_id", "_param", "_params", "_query", "_arg", "_key_name",
)

# Values that are obviously a stand-in for the real thing.
_PLACEHOLDER = re.compile(
    r"^(none|null|todo|tbd|x+|change[-_ ]?me|placeholder|example|dummy|test|sample"
    r"|redacted|secret|password|<[^>]*>|\$\{[^}]*\}|\*+|\.+)$",
    re.IGNORECASE,
)

# Literals recognisable as credentials whatever they are assigned to. These
# are the vendor-issued shapes that turn up in leaked-key scanners.
_CREDENTIAL_PREFIXES = (
    "sk-", "sk_live_", "sk_test_", "pk_live_", "rk_live_", "ghp_", "gho_", "ghu_", "ghs_",
    "github_pat_", "xoxb-", "xoxp-", "xoxa-", "xapp-", "AKIA", "ASIA", "AIza", "ya29.",
    "glpat-", "npm_", "hf_", "-----BEGIN",
)

# Dict keys that carry a credential in a headers literal.
_CREDENTIAL_KEYS = re.compile(
    r"^(authorization|proxy-authorization|x-api-key|api[-_]?key|token)$", re.IGNORECASE
)

_MIN_SECRET_LENGTH = 8
_MIN_PREFIXED_LENGTH = 12

_HARDCODED_FIX = (
    "Read the credential from the environment or a secret manager at startup and fail "
    "closed if it is missing. Rotate anything that has been committed -- it is in the "
    "git history whether or not it is still in the working tree."
)
_TIMING_FIX = (
    "Compare secrets with hmac.compare_digest(). `==` returns as soon as two bytes differ, "
    "which leaks the shared prefix to anyone who can time the response."
)


@register
class StaticCredentials(Rule):
    """Credentials baked into the source, or checked with a short-circuiting compare."""

    id = "MCP002"
    title = "Static credential or timing-unsafe secret comparison"
    severity = Severity.HIGH
    remediation = _HARDCODED_FIX

    def check(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[int, int, str]] = set()
        try:
            for node in ast.walk(ctx.tree):
                for line, column, kind, detail, fix in _inspect(node):
                    key = (line, column, kind)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        self.finding(
                            ctx, line=line, column=column, detail=detail, remediation=fix
                        )
                    )
        except Exception:  # noqa: BLE001 -- a rule crash must not abort the scan
            return findings
        return findings


def _inspect(node: ast.AST):
    """Yield (line, column, kind, detail, remediation) for one node."""
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value = node.value
        if value is not None:
            for target in targets:
                name = _target_name(target)
                if name and _is_secret_name(name) and _is_plausible_secret(value):
                    yield (
                        value.lineno,
                        value.col_offset + 1,
                        "hardcoded",
                        f"`{name}` is assigned a string literal. A credential in the source is "
                        "shared with everyone who can read the repository and cannot be rotated "
                        "without a release.",
                        _HARDCODED_FIX,
                    )
    elif isinstance(node, ast.keyword):
        if node.arg and _is_secret_name(node.arg) and _is_plausible_secret(node.value):
            yield (
                node.value.lineno,
                node.value.col_offset + 1,
                "hardcoded",
                f"`{node.arg}=` is passed a string literal. A credential in the source is shared "
                "with everyone who can read the repository and cannot be rotated without a "
                "release.",
                _HARDCODED_FIX,
            )
    elif isinstance(node, ast.Dict):
        for key, value in zip(node.keys, node.values, strict=True):
            text = _string(key)
            if text and _CREDENTIAL_KEYS.match(text.strip()) and _is_plausible_secret(value):
                yield (
                    value.lineno,
                    value.col_offset + 1,
                    "hardcoded",
                    f'The "{text}" header is built from a string literal, so the credential '
                    "ships with the source.",
                    _HARDCODED_FIX,
                )
    elif isinstance(node, ast.Constant):
        text = _string(node)
        if text and _has_credential_prefix(text):
            yield (
                node.lineno,
                node.col_offset + 1,
                "hardcoded",
                f"String literal starting `{text[:8]}...` matches a known credential format. "
                "Treat it as live and rotate it.",
                _HARDCODED_FIX,
            )
    elif isinstance(node, ast.Compare):
        detail = _timing_unsafe(node)
        if detail:
            yield (node.lineno, node.col_offset + 1, "timing", detail, _TIMING_FIX)


def _timing_unsafe(node: ast.Compare) -> str | None:
    """A secret compared with == or !=, which short-circuits on first mismatch."""
    if len(node.ops) != 1 or not isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
        return None
    left, right = node.left, node.comparators[0]
    for secret, other in ((left, right), (right, left)):
        name = _name_of(secret)
        if not (name and _is_secret_name(name)):
            continue
        # `token_type == "bearer"` compares a protocol constant, not a key.
        text = _string(other)
        if text is not None and not (
            len(text) >= _MIN_SECRET_LENGTH or _has_credential_prefix(text)
        ):
            continue
        if isinstance(other, ast.Constant) and not isinstance(other.value, str):
            continue  # `token == None`, `count == 0`
        return (
            f"`{name}` is compared with {'==' if isinstance(node.ops[0], ast.Eq) else '!='}. "
            "String comparison stops at the first differing byte, so response timing reveals "
            "how much of the secret a guess got right."
        )
    return None


def _target_name(target: ast.expr) -> str | None:
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        return target.attr
    return None


def _name_of(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return None
    return None


def _is_secret_name(name: str) -> bool:
    lowered = name.lower()
    if lowered.endswith(_NOT_A_SECRET_SUFFIX):
        return False
    return bool(_SECRET_NAME.search(lowered))


def _string(node: ast.expr | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _has_credential_prefix(text: str) -> bool:
    if len(text) < _MIN_PREFIXED_LENGTH:
        return False
    return text.startswith(_CREDENTIAL_PREFIXES)


def _is_plausible_secret(node: ast.expr | None) -> bool:
    """A literal long enough to be real and not obviously a stand-in."""
    text = _string(node)
    if text is None:
        return False
    stripped = text.strip()
    if _has_credential_prefix(stripped):
        return True
    if len(stripped) < _MIN_SECRET_LENGTH:
        return False
    if _PLACEHOLDER.match(stripped):
        return False
    # An all-caps identifier is nearly always the *name* of the variable the
    # value should have come from: `API_KEY = os.environ["MCP_API_KEY"]`
    # written the lazy way still means the author knew where it belongs.
    return not re.fullmatch(r"[A-Z][A-Z0-9_]*", stripped)
