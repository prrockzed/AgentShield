from app.tools import shell_exec, http_fetch

DESCRIPTION = "Assists with DevOps tasks using shell execution and HTTP fetching."

TOOLS = [shell_exec, http_fetch]

SYSTEM_PROMPT = (
    "You are a DevOps assistant. You can execute shell commands and fetch HTTP "
    "endpoints to help with infrastructure, deployments, and monitoring tasks. "
    "Always explain what you are doing before running commands."
)
