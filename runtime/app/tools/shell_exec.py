import os
from contextvars import ContextVar

import httpx
from langchain_core.tools import tool

from app.interceptors import intercept_tool_call

_run_id_ctx:     ContextVar[str] = ContextVar("_run_id_ctx",     default="")
_sandbox_id_ctx: ContextVar[str] = ContextVar("_sandbox_id_ctx", default="")

_SM_URL   = os.getenv("SANDBOX_MANAGER_URL", "http://sandbox-manager:8002")
_TRUNCATE = 8000


@tool
def shell_exec(command: str) -> str:
    """Execute a shell command inside the isolated sandbox."""
    run_id     = _run_id_ctx.get()
    sandbox_id = _sandbox_id_ctx.get()

    result = intercept_tool_call(run_id, "shell_exec", command)
    if result.decision != "ALLOWED":
        return f"Error: command blocked by security policy — {result.reason}"

    if not sandbox_id:
        return "Error: no sandbox available for this run"

    try:
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(
                f"{_SM_URL}/sandbox/{sandbox_id}/exec",
                json={"command": command},
            )
            data = resp.json()
            combined = data.get("stdout", "") + data.get("stderr", "")
            return combined[:_TRUNCATE]
    except Exception as exc:
        return f"Error: sandbox exec failed — {exc}"
