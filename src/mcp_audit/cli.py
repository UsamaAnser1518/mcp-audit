"""Command line entry point.

Three output formats, and the third is the point: GitHub Code Scanning
ingests SARIF natively, so a scanner that emits it drops into an Actions
workflow and annotates the diff instead of hiding in a log.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .finding import Finding, Severity
from .rules import all_rules
from .scanner import ScanResult, scan_path

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
    "sarif-schema-2.1.0.json"
)
# GitHub renders "error" in the diff and "warning"/"note" in the sidebar.
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# GitHub sorts and filters alerts on this, so an unmapped severity would
# silently rank last. Numbers follow the CVSS bands GitHub documents.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}

_COLOURS = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-audit",
        description="Static security analysis for Model Context Protocol servers.",
        epilog=(
            "Findings are leads for human review, not a verdict. A clean report means these "
            "patterns were not found, not that the server is secure."
        ),
    )
    parser.add_argument(
        "path",
        type=Path,
        help="file or directory to scan (a directory is walked for MCP servers)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="output format (default: text; sarif uploads to GitHub Code Scanning)",
    )
    parser.add_argument(
        "--fail-on",
        choices=("low", "medium", "high", "critical"),
        default=None,
        metavar="SEVERITY",
        help="exit non-zero when a finding of this severity or worse is reported",
    )
    parser.add_argument(
        "--include-tests",
        action="store_true",
        help="also scan test files (skipped by default: a test double is not a server)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="text format: findings only, no summary or remediation",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable colour (also honours NO_COLOR)",
    )
    parser.add_argument("--version", action="version", version=f"mcp-audit {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if not args.path.exists():
        print(f"mcp-audit: {args.path}: no such file or directory", file=sys.stderr)
        return EXIT_USAGE

    result = scan_path(args.path, include_tests=args.include_tests)

    if args.format == "json":
        print(json.dumps(to_json(result, args.path), indent=2))
    elif args.format == "sarif":
        print(json.dumps(to_sarif(result), indent=2))
    else:
        colour = _use_colour(args.no_color)
        print(render_text(result, args.path, colour=colour, quiet=args.quiet), end="")

    # Errors go to stderr in every format so machine-readable output on
    # stdout stays parseable.
    for error in result.errors:
        print(f"mcp-audit: {error}", file=sys.stderr)

    if args.fail_on and result.meets(Severity(args.fail_on)):
        return EXIT_FINDINGS
    return EXIT_OK


def _use_colour(disabled: bool) -> bool:
    if disabled or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def render_text(result: ScanResult, target: Path, colour: bool = False, quiet: bool = False) -> str:
    lines: list[str] = []
    for finding in result.findings:
        location = f"{_display_path(finding.path)}:{finding.line}"
        if finding.column:
            location += f":{finding.column}"
        label = finding.severity.value.upper()
        if colour:
            label = f"{_COLOURS[finding.severity]}{label}{_RESET}"
        head = f"{location}  {label}  {finding.rule_id}  {finding.title}"
        lines.append(head)
        if finding.tool_name:
            lines.append(_indent(f"tool: {finding.tool_name}", colour))
        lines.append(_indent(finding.detail, colour))
        if not quiet and finding.remediation:
            lines.append(_indent(f"fix:  {finding.remediation}", colour))
        lines.append("")

    if quiet:
        return "\n".join(lines)

    counts = result.counts()
    if not result.findings:
        summary = "No findings."
    else:
        breakdown = ", ".join(
            f"{counts[s]} {s.value}"
            for s in sorted(Severity, key=lambda s: -s.rank)
            if counts.get(s)
        )
        plural = "s" if len(result.findings) != 1 else ""
        summary = f"{len(result.findings)} finding{plural} ({breakdown})"
    scope = (
        f"scanned {result.files_scanned} file(s) of {result.files_seen} seen, "
        f"{len(result.tools)} tool(s) in {_display_path(str(target))}"
    )
    if result.tests_skipped:
        scope += f" ({result.tests_skipped} test file(s) skipped, --include-tests to scan them)"
    lines.append(f"{summary} -- {scope}")
    if not result.findings and result.files_scanned == 0:
        lines.append(
            "No MCP server was recognised here. mcp-audit looks for an mcp/fastmcp import "
            "or a @<server>.tool() decorator."
        )
    lines.append("")
    return "\n".join(lines)


def _indent(text: str, colour: bool) -> str:
    body = "\n".join("    " + line for line in _wrap(text, 92))
    return f"{_DIM}{body}{_RESET}" if colour else body


def _wrap(text: str, width: int) -> list[str]:
    words, lines, current = text.split(), [], ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines or [""]


def _display_path(path: str) -> str:
    """Relative to the working directory when possible -- shorter, and clickable."""
    try:
        return os.path.relpath(path, os.getcwd())
    except ValueError:  # different drive on Windows
        return path


def to_json(result: ScanResult, target: Path) -> dict:
    return {
        "tool": "mcp-audit",
        "version": __version__,
        "target": str(target),
        "summary": {
            "findings": len(result.findings),
            "by_severity": {s.value: n for s, n in sorted(
                result.counts().items(), key=lambda kv: -kv[0].rank
            )},
            "files_seen": result.files_seen,
            "files_scanned": result.files_scanned,
            "tests_skipped": result.tests_skipped,
            "tools": len(result.tools),
        },
        "findings": [f.to_dict() for f in result.findings],
        "errors": result.errors,
    }


def to_sarif(result: ScanResult) -> dict:
    rules = all_rules()
    index_of = {rule.id: i for i, rule in enumerate(rules)}
    return {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-audit",
                        "version": __version__,
                        # informationUri is optional and deliberately absent:
                        # a link to a repository that does not exist yet is
                        # worse than no link in every report the tool emits.
                        "rules": [_sarif_rule(rule) for rule in rules],
                    }
                },
                "results": [_sarif_result(f, index_of) for f in result.findings],
            }
        ],
    }


def _sarif_rule(rule) -> dict:
    summary = rule.__doc__.strip().splitlines()[0] if rule.__doc__ else rule.title
    return {
        "id": rule.id,
        "name": _pascal_case(rule.title),
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": summary},
        "help": {"text": rule.remediation or rule.title},
        "defaultConfiguration": {"level": _SARIF_LEVEL[rule.severity]},
        "properties": {
            "tags": ["security", "mcp"],
            "security-severity": _SECURITY_SEVERITY[rule.severity],
        },
    }


def _sarif_result(finding: Finding, index_of: dict[str, int]) -> dict:
    message = finding.detail or finding.title
    if finding.tool_name:
        message = f"[tool: {finding.tool_name}] {message}"
    result = {
        "ruleId": finding.rule_id,
        "level": _SARIF_LEVEL[finding.severity],
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _sarif_uri(finding.path)},
                    # SARIF regions are 1-based; a Finding carries 0 for
                    # "column unknown", which must not become column 0.
                    "region": {
                        "startLine": max(1, finding.line),
                        "startColumn": max(1, finding.column),
                    },
                }
            }
        ],
    }
    if finding.rule_id in index_of:
        result["ruleIndex"] = index_of[finding.rule_id]
    return result


def _sarif_uri(path: str) -> str:
    """Repo-relative POSIX path: what Code Scanning needs to match a file."""
    relative = _display_path(path)
    return Path(relative).as_posix()


def _pascal_case(title: str) -> str:
    return "".join(word.capitalize() for word in title.replace("-", " ").split() if word.isalnum())


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
