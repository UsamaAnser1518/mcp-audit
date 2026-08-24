# mcp-audit

Static security analysis for Model Context Protocol (MCP) servers written in Python.

Point it at a repository, get a report of the security issues that show up most often in
public MCP servers: tools exposed without authentication, static-key auth, caller-controlled
URLs reaching the network, and untrusted input reaching dangerous sinks.

```console
$ mcp-audit server.py
server.py:11:12  CRITICAL  MCP004  Tool input reaches a dangerous sink
    tool: git_log
    Tool parameters `count`, `repo` reach subprocess.check_output(), which hands the value to a
    shell. A caller can chain arbitrary commands with ; && | or backticks.
    fix: Pass a fixed argument list with shell=False and keep caller input out of argv[0]. If a
    shell is genuinely required, wrap the value in shlex.quote().

server.py:9  HIGH  MCP001  Tools exposed without authentication
    1 tool(s) are registered here (`git_log`) and nothing in this file authenticates the caller.
    The server is configured for a network transport. Every tool is callable by anyone who can
    reach the port.
    fix: Put the server behind OAuth 2.1 as the MCP authorization spec describes (formalised in
    the 2025-11-25 revision), or at minimum require a bearer credential compared with
    hmac.compare_digest() before dispatching a tool call. If the server is only ever spawned
    over stdio, say so in the README so the next reader does not deploy it.

2 findings (1 critical, 1 high) -- scanned 1 file(s) of 1 seen, 1 tool(s) in server.py
```

## Why

Independent analyses of public MCP servers in 2026 found a large share shipping with no
authentication at all, a majority of authenticated servers relying on static API keys, and a
significant fraction carrying SSRF-prone URL handling. The MCP spec has since formalised
OAuth 2.1, but the long tail of community servers predates it.

`mcp-audit` is a first-pass triage tool for that gap.

## Install

```bash
pip install -e ".[dev]"
```

No runtime dependencies. The analysis is standard-library `ast` only.

## Usage

```bash
mcp-audit path/to/server.py
mcp-audit path/to/repo/                    # walks the tree for MCP servers
mcp-audit path/to/repo/ --format json
mcp-audit path/to/repo/ --format sarif     # GitHub Code Scanning
mcp-audit path/to/repo/ --fail-on high     # non-zero exit for CI
mcp-audit path/to/repo/ --quiet            # findings only, no summary or fixes
mcp-audit path/to/repo/ --include-tests    # test files are skipped by default
```

Exit codes: `0` nothing to report (or findings below the `--fail-on` threshold), `1` a finding
met the threshold, `2` the path does not exist or the arguments were wrong. Without
`--fail-on`, findings alone never fail the build -- a report is not an error.

A directory scan analyses files that import `mcp`/`fastmcp` or register a tool, and skips the
rest. Test files are skipped too -- a test that builds a fake server is not a deployed server,
and its hardcoded key is a fixture. The count is always printed rather than hidden, and
`--include-tests` turns it off. Pointing the scanner straight at a test directory scans it
regardless, and a file named explicitly on the command line is always analysed: silently doing
nothing to a file the user asked about is the wrong answer.

## Rules

| ID | Check | Severity |
|----|-------|----------|
| MCP001 | Tools exposed with no authentication configured | High |
| MCP002 | Static credentials or non-constant-time key comparison | High |
| MCP003 | Caller-controlled URL reaches a network call without validation (SSRF) | High |
| MCP004 | Tool input reaches a dangerous sink (shell, eval, file path, raw SQL) | Critical |
| MCP005 | OAuth configured but tools do not enforce scopes | Medium |

**MCP001** reports once per file, not once per tool: authentication is a server-level property.
It stays quiet for stdio servers, whose trust boundary is the process that spawned them, and
for any file showing a credible sign of authentication. Whether that authentication is any
good is MCP002's and MCP005's question.

**MCP002** covers credentials that are literals in the source (by variable name, by keyword
argument, by header dict entry, and by vendor key format such as `sk-`, `ghp_`, `AKIA`) and
secrets compared with `==` or `!=` instead of `hmac.compare_digest`.

**MCP003** follows a tool parameter into `requests`, `httpx`, `aiohttp`, `urllib` and
socket-level calls. A URL whose scheme and host are literals is not reported -- the caller
controls only the path. A URL the tool checks first is graded down to Medium rather than
silenced: `mcp-audit` can see that somebody tried, but not whether the check is correct.

**MCP004** covers `subprocess`, `os.system`/`os.popen`, `asyncio.create_subprocess_*`,
`eval`/`exec`/`compile`, filesystem paths through `open`/`pathlib.Path`/`os.remove`, and SQL
built by interpolation into `execute()`. A parameterised query is not a finding, and neither
is a value that has been through `shlex.quote()` or `int()`. A path the tool validates first
is graded down to High, and one checked with the `resolve()`/`relative_to()` containment idiom
is not reported at all -- for a path, validation is the accepted fix. That reasoning does not
extend to the other sinks, where the fix is an argument list or a bound parameter rather than
a check, so those stay Critical however carefully the input was inspected.

**MCP005** only speaks to servers that already verify tokens. It reports either "no scope check
anywhere" or "scopes exist server-wide but these tools do not check one of their own".

## In CI

SARIF output uploads straight into GitHub Code Scanning, which annotates the pull request diff
instead of hiding findings in a log:

```yaml
- name: Audit MCP servers
  run: |
    pip install git+https://github.com/UsamaAnser1518/mcp-audit
    mcp-audit src/ --format sarif > mcp-audit.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: mcp-audit.sarif
```

Add `mcp-audit src/ --fail-on critical` as a separate step to block a merge on the worst class
of finding while the rest stay advisory.

## How it works

```
detect.py   find MCP servers, inventory the tools they expose
taint.py    intraprocedural taint: which locals carry caller input
rules/      one class per check, each given a ScanContext
scanner.py  walk the tree, run the rules, contain their failures
cli.py      text, JSON, SARIF
```

Tools are found with `ast.walk` rather than by iterating module-level statements, so a tool
defined inside a factory function is still found -- a missed tool is a silent false negative,
the worst bug class for a scanner. Decorators are matched on the last dotted segment, so
`@mcp.tool()`, `@app.tool()` and `@srv.tool()` are one pattern rather than three. Registration
without a decorator counts too: `mcp.add_tool(search)` and `self.tool(handler, name="find")`
are how several real servers register everything they expose, including through a local alias.

MCP003 and MCP004 share one taint engine, so the two rules cannot drift apart on what "reaches"
means. It propagates a tool parameter through local assignments, tuple unpacking, loop and
`with` bindings, f-strings, `%`, `.format()` and concatenation, and drops taint at calls that
destroy an injection payload by construction (`int`, `float`, `bool`, `len`, `shlex.quote`).

Rules are documented as never raising, and the scanner does not take their word for it: each
`check()` runs inside a guard, and a rule that fails is reported on stderr while the other four
finish the file.

## Limitations

Read this before trusting a clean report.

- **Intraprocedural only.** Taint is tracked within a single tool function. If a parameter is
  passed to a helper that performs the shell call or the network call, `mcp-audit` will not
  follow it and will not report it.
- **Flow-insensitive within that function.** Taint is the union over the whole body, so a name
  assigned from a parameter stays tainted even if it is later reassigned to a constant. This
  direction is deliberate: an extra lead beats a missed injection.
- **Heuristics decide when to stay quiet.** MCP001 is silenced by any auth-shaped identifier in
  the file, even one that never runs. MCP003 grades a finding down when it sees a guard, without
  reading the guard -- an allowlist that forgets `169.254.169.254` still counts as trying.
  MCP002 matches names and known key formats, so a high-entropy literal that is neither named
  like a secret nor shaped like a vendor key is missed. MCP004 goes quiet about a path sink
  when the function contains the `resolve()` / `relative_to()` containment idiom, without
  checking that the resolved path is the one that gets opened.
- **stdio servers are not checked for authentication** at all. That is the spec's position, not
  an oversight, but it means a stdio server later exposed through an HTTP proxy gets no warning.
- **Python only.** TypeScript MCP servers are not analysed.
- **Static analysis.** Dynamically constructed tool registrations, decorators resolved at
  runtime, and configuration loaded from external sources are invisible.
- **Not a proof of absence.** A clean report means these specific patterns were not found. It
  does not mean the server is secure.

Treat findings as leads for human review, not as a verdict.

## Responsible use

`mcp-audit` reads source code. It does not send traffic to running servers, and it should not
be extended to do so -- probing someone else's deployed server without written authorisation is
unauthorised security testing.

If you use this tool to find a real issue in a project you do not own, report it privately to
the maintainer and give them time to fix it before publishing.

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
```

Test fixtures under `tests/fixtures/` are intentionally vulnerable sample servers, one concern
per file. They are never executed -- they exist to be parsed, and they are excluded from
linting for the same reason.

## License

MIT
