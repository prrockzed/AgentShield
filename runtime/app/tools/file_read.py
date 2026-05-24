from langchain_core.tools import tool

from app.interceptors import intercept_filesystem, intercept_output
from app.tools.shell_exec import _run_id_ctx

_TRUNCATE = 8000


@tool
def file_read(path: str) -> str:
    """Read a file from disk and return its contents."""
    run_id = _run_id_ctx.get()

    # Pre-read: block or flag sensitive paths before opening the file
    fs_result = intercept_filesystem(run_id, path, "READ")
    if fs_result.decision == "BLOCKED":
        return f"Error: access to '{path}' blocked by filesystem security policy — {fs_result.reason}"

    try:
        with open(path) as fh:
            content = fh.read()[:_TRUNCATE]
    except FileNotFoundError:
        return f"Error: file not found: {path}"
    except Exception as exc:
        return f"Error: {exc}"

    # Post-read: DLP scan — redact secrets/PII before returning content to the agent
    out_result = intercept_output(run_id, content)
    if out_result.decision == "REDACTED":
        return out_result.redacted_content
    return content
