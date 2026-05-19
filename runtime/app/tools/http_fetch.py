import httpx
from langchain_core.tools import tool

_TRUNCATE = 8000


@tool
def http_fetch(url: str) -> str:
    """Fetch a URL via HTTP GET and return the response body."""
    try:
        with httpx.Client(timeout=15) as client:
            response = client.get(url)
            return response.text[:_TRUNCATE]
    except Exception as exc:
        return f"Error: {exc}"
