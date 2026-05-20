import httpx
from langchain_core.tools import tool

from app.interceptors import intercept_prompt
from app.tools.shell_exec import _run_id_ctx

_TRUNCATE = 8000


@tool
def http_fetch(url: str) -> str:
    """Fetch a URL via HTTP GET and return the response body."""
    run_id = _run_id_ctx.get()
    try:
        with httpx.Client(timeout=15) as client:
            response = client.get(url)
            content = response.text[:_TRUNCATE]
    except Exception as exc:
        return f"Error: {exc}"
    result = intercept_prompt(run_id, content, "FETCHED_CONTENT")
    if result.decision == "BLOCKED":
        return f"Error: fetched content blocked by security policy — {result.reason}"
    return content
