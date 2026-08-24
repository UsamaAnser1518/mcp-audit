"""Core data types shared by every rule."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Ordered severity levels.

    Inherits from `str` so it serialises to JSON without a custom encoder,
    while still behaving like an enum in comparisons.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER[self]


_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class Finding:
    """A single reported issue.

    Frozen because a finding is a fact about a file at a point in time;
    nothing downstream should mutate one after a rule emits it.
    """

    rule_id: str
    title: str
    severity: Severity
    path: str
    line: int
    column: int = 0
    tool_name: str | None = None
    detail: str = ""
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "tool_name": self.tool_name,
            "detail": self.detail,
            "remediation": self.remediation,
        }


@dataclass
class ToolDefinition:
    """An MCP tool discovered in the source.

    This is the unit rules reason about: most checks are of the form
    "for each exposed tool, does X hold?"
    """

    name: str
    function_name: str
    path: str
    line: int
    parameters: list[str] = field(default_factory=list)
    decorator: str = ""
    node: object = None  # the ast.FunctionDef, for rules that walk the body

    def __repr__(self) -> str:  # keep the AST node out of test output
        return (
            f"ToolDefinition(name={self.name!r}, function_name={self.function_name!r}, "
            f"line={self.line}, parameters={self.parameters!r}, decorator={self.decorator!r})"
        )
