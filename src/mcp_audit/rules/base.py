"""The rule extension point.

Every check is a Rule subclass. Registration is explicit rather than
magic: a rule is active because it appears in the registry, not because
it happened to get imported. Easier to reason about, easier to test.
"""

from __future__ import annotations

import ast
from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..finding import Finding, Severity, ToolDefinition


@dataclass
class ScanContext:
    """Everything a rule is given about one file.

    Passing a context object rather than five positional arguments means
    adding new information later (config, resolved imports, call graph)
    doesn't break every existing rule signature.
    """

    path: str
    tree: ast.Module
    source: str
    tools: list[ToolDefinition]

    def line_of(self, node: ast.AST) -> int:
        return getattr(node, "lineno", 0)


class Rule(ABC):
    """Base class for all checks."""

    id: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM
    remediation: str = ""

    @abstractmethod
    def check(self, ctx: ScanContext) -> list[Finding]:
        """Return findings for this file. Must not raise."""
        raise NotImplementedError

    def finding(
        self,
        ctx: ScanContext,
        line: int,
        detail: str,
        tool_name: str | None = None,
        column: int = 0,
        remediation: str | None = None,
        severity: Severity | None = None,
    ) -> Finding:
        """Helper so subclasses don't repeat the boilerplate fields.

        Two overrides, both for rules that cover more than one mistake:
        `remediation`, because "use a parameterised query" is useless next
        to a command injection, and `severity`, so a rule can grade a
        weaker instance of its own pattern down instead of staying silent.
        The rule's declared `severity` remains its headline.
        """
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=self.severity if severity is None else severity,
            path=ctx.path,
            line=line,
            column=column,
            tool_name=tool_name,
            detail=detail,
            remediation=self.remediation if remediation is None else remediation,
        )


_REGISTRY: list[type[Rule]] = []


def register(cls: type[Rule]) -> type[Rule]:
    """Class decorator that adds a rule to the active set."""
    if not cls.id:
        raise ValueError(f"{cls.__name__} must define an id")
    if any(existing.id == cls.id for existing in _REGISTRY):
        raise ValueError(f"duplicate rule id: {cls.id}")
    _REGISTRY.append(cls)
    return cls


def all_rules() -> list[Rule]:
    return [cls() for cls in _REGISTRY]
