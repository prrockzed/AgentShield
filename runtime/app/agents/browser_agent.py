from app.tools import http_fetch

DESCRIPTION = "Fetches web pages and APIs to answer questions from the internet."

TOOLS = [http_fetch]

SYSTEM_PROMPT = (
    "You are a web browsing assistant. You can fetch web pages and APIs "
    "to retrieve information from the internet. "
    "Summarize the content you retrieve and answer the user's question."
)
