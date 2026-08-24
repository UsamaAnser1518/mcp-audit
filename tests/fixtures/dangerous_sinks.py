"""INTENTIONALLY VULNERABLE. Test fixture only -- parsed, never executed.

MCP004's sink coverage. Every tool is named for the case it exercises, so a
failing assertion names the behaviour that broke.
"""

import asyncio
import os
import shlex
import sqlite3
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("sinks")
DB = sqlite3.connect(":memory:")


@mcp.tool()
def shell_true(cmd: str) -> str:
    """Parameter straight into a shell."""
    return subprocess.check_output(cmd, shell=True).decode()


@mcp.tool()
def fixed_argv() -> str:
    """No caller input anywhere: not a finding."""
    return subprocess.run(["ls", "-la"], capture_output=True).stdout.decode()


@mcp.tool()
def via_local(cmd: str) -> str:
    """Parameter assigned to a local first."""
    command = cmd
    return subprocess.check_output(command, shell=True).decode()


@mcp.tool()
def via_fstring(path: str) -> str:
    """Parameter interpolated into an f-string."""
    command = f"ls -la {path}"
    return os.popen(command).read()


@mcp.tool()
def evaluated(expression: str):
    """Arbitrary Python from the caller."""
    return eval(expression)


@mcp.tool()
def read_file(name: str) -> str:
    """Path traversal: ../../etc/passwd escapes the intended directory."""
    return open(f"/srv/data/{name}").read()


@mcp.tool()
def delete_path(name: str) -> None:
    """pathlib is a sink too."""
    Path(name).unlink()


@mcp.tool()
def sql_interpolated(user_id: str):
    """Query built by interpolation."""
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return DB.execute(query).fetchall()


@mcp.tool()
def sql_parameterised(user_id: str):
    """Same input, bound as a parameter: not a finding."""
    return DB.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall()


@mcp.tool()
def quoted(name: str) -> str:
    """shlex.quote neutralises the payload: not a finding."""
    return subprocess.check_output(f"ls {shlex.quote(name)}", shell=True).decode()


@mcp.tool()
def coerced(count: str) -> str:
    """int() cannot return anything a shell would act on: not a finding."""
    return subprocess.check_output(f"head -n {int(count)} /var/log/app.log", shell=True).decode()


@mcp.tool()
async def async_shell(cmd: str):
    """Async servers reach the same shell by a different name."""
    process = await asyncio.create_subprocess_shell(cmd)
    return await process.wait()


@mcp.tool()
def no_sinks(text: str) -> dict:
    """Nothing dangerous happens here."""
    return {"echo": text.upper()}
