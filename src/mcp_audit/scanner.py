"""Run the rules over a path and collect what they find.

The scanner owns two things rules must not have to think about: which
files are worth analysing, and what happens when a rule misbehaves. A rule
is documented as never raising, but "documented" is not "enforced" -- one
bad regex must not cost the user the other four rules' findings, so every
call is wrapped and the failure is reported rather than swallowed.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .detect import find_tools, is_mcp_source, iter_python_files, parse_file
from .finding import Finding, Severity, ToolDefinition
from .rules import Rule, ScanContext, all_rules

_SEVERITY_SORT = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    tools: list[ToolDefinition] = field(default_factory=list)
    files_seen: int = 0  # Python files considered
    files_scanned: int = 0  # of those, the ones that looked like MCP servers
    errors: list[str] = field(default_factory=list)

    def extend(self, other: ScanResult) -> None:
        self.findings.extend(other.findings)
        self.tools.extend(other.tools)
        self.files_seen += other.files_seen
        self.files_scanned += other.files_scanned
        self.errors.extend(other.errors)

    def sort(self) -> None:
        """Worst first, then by location, so a truncated read is the useful half."""
        self.findings.sort(
            key=lambda f: (_SEVERITY_SORT.get(f.severity, 9), f.path, f.line, f.rule_id)
        )

    def counts(self) -> dict[Severity, int]:
        counts: dict[Severity, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def worst(self) -> Severity | None:
        return max((f.severity for f in self.findings), key=lambda s: s.rank, default=None)

    def meets(self, threshold: Severity) -> bool:
        return any(f.severity.rank >= threshold.rank for f in self.findings)


def scan_source(
    source: str, path: str, rules: Sequence[Rule] | None = None
) -> ScanResult:
    """Analyse already-loaded source. The unit tests drive this directly."""
    result = ScanResult(files_seen=1)
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        result.errors.append(f"{path}: could not parse ({exc.msg} at line {exc.lineno})")
        return result
    _run(tree, source, path, rules, result)
    result.sort()
    return result


def scan_file(
    path: Path, rules: Sequence[Rule] | None = None, *, force: bool = False
) -> ScanResult:
    """Analyse one file.

    `force` scans regardless of whether the file looks like an MCP server:
    if the user named the file explicitly, silently doing nothing would be
    the wrong answer.
    """
    result = ScanResult(files_seen=1)
    tree = parse_file(path)
    if tree is None:
        if not force:
            return result
        # parse_file drops the reason on purpose; a file the user named by
        # hand deserves to hear why nothing happened to it.
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            result.errors.append(f"{path}: {exc}")
            return result
        return scan_source(source, str(path), rules)

    tools = find_tools(tree, str(path))
    if not force and not tools and not is_mcp_source(tree):
        return result
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:  # parse_file just read it; a race is still possible
        result.errors.append(f"{path}: {exc}")
        return result
    return _run(tree, source, str(path), rules, result, tools=tools)


def scan_path(target: Path, rules: Sequence[Rule] | None = None) -> ScanResult:
    """Analyse a file or a directory tree."""
    rules = list(rules) if rules is not None else all_rules()
    result = ScanResult()
    if target.is_file():
        result.extend(scan_file(target, rules, force=True))
    else:
        for path in iter_python_files(target):
            result.extend(scan_file(path, rules))
    result.sort()
    return result


def _run(tree, source: str, path: str, rules, result: ScanResult, tools=None) -> ScanResult:
    tools = find_tools(tree, path) if tools is None else tools
    active: Iterable[Rule] = all_rules() if rules is None else rules
    ctx = ScanContext(path=path, tree=tree, source=source, tools=tools)
    result.files_scanned += 1
    result.tools.extend(tools)
    for rule in active:
        try:
            findings = rule.check(ctx)
        except Exception as exc:  # noqa: BLE001 -- a rule crash costs that rule only
            result.errors.append(f"{path}: rule {rule.id or type(rule).__name__} failed: {exc!r}")
            continue
        if findings:
            result.findings.extend(findings)
    return result
