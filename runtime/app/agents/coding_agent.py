from app.tools import shell_exec, file_read

DESCRIPTION = "Assists with coding tasks using shell execution and file reading."

TOOLS = [shell_exec, file_read]

SYSTEM_PROMPT = (
    "You are a coding assistant. You can execute shell commands and read files "
    "to help with programming tasks, debugging, and code analysis. "
    "Always explain what you are doing before running commands."
)
