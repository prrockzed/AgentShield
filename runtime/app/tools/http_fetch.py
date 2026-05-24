import httpx
from langchain_core.tools import tool

from app.interceptors import intercept_prompt, intercept_network, intercept_browser
from app.tools.shell_exec import _run_id_ctx

_TRUNCATE = 8000


@tool
def http_fetch(url: str) -> str:
    """Fetch a URL via HTTP GET and return the response body."""
    run_id = _run_id_ctx.get()

    # Pre-request: block malicious URLs before any connection is made
    net_result = intercept_network(run_id, url, "GET")
    if net_result.decision != "ALLOWED":
        return f"Error: request blocked by network security policy — {net_result.reason}"

    try:
        with httpx.Client(timeout=15) as client:
            response = client.get(url)
            content = response.text[:_TRUNCATE]
    except Exception as exc:
        return f"Error: {exc}"

    # Browser security scan — only on HTML responses
    content_type = response.headers.get("content-type", "")
    if "text/html" in content_type:
        browser_result = intercept_browser(run_id, url, content)
        if browser_result.decision == "BLOCKED":
            return f"Error: web content blocked by browser security policy — {browser_result.reason}"
    # FLAGGED: event is logged but content passes through to prompt scan

    result = intercept_prompt(run_id, content, "FETCHED_CONTENT")
    if result.decision == "BLOCKED":
        return f"Error: fetched content blocked by security policy — {result.reason}"
    return content
