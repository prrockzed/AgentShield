import subprocess
from contextvars import ContextVar

from langchain_core.tools import tool

from app.interceptors import intercept_tool_call

_run_id_ctx: ContextVar[str] = ContextVar("_run_id_ctx", default="")

_TRUNCATE = 8000


@tool
def shell_exec(command: str) -> str:
    """Execute a shell command and return its output."""
    run_id = _run_id_ctx.get()
    result = intercept_tool_call(run_id, "shell_exec", command)
    if result.decision != "ALLOWED":
        return f"Error: command blocked by security policy — {result.reason}"
    try:
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = proc.stdout + proc.stderr
        return output[:_TRUNCATE]
    except subprocess.TimeoutExpired:
        return "Error: command timed out after 30 seconds"
    except Exception as exc:
        return f"Error: {exc}"
