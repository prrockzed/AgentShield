import subprocess
from contextvars import ContextVar
from langchain_core.tools import tool

_run_id_ctx: ContextVar[str] = ContextVar("_run_id_ctx", default="")

_TRUNCATE = 8000


@tool
def shell_exec(command: str) -> str:
    """Execute a shell command and return its output."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout + result.stderr
        return output[:_TRUNCATE]
    except subprocess.TimeoutExpired:
        return "Error: command timed out after 30 seconds"
    except Exception as exc:
        return f"Error: {exc}"
