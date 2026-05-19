from langchain_core.tools import tool

_TRUNCATE = 8000


@tool
def file_read(path: str) -> str:
    """Read a file from disk and return its contents."""
    try:
        with open(path) as fh:
            return fh.read()[:_TRUNCATE]
    except FileNotFoundError:
        return f"Error: file not found: {path}"
    except Exception as exc:
        return f"Error: {exc}"
