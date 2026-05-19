from dataclasses import dataclass


@dataclass
class InterceptResult:
    decision: str  # "ALLOWED" | "BLOCKED"
    reason: str = ""


def intercept_input(run_id: str, agent_type: str, task: str) -> InterceptResult:
    return InterceptResult(decision="ALLOWED")


def intercept_tool_call(run_id: str, tool_name: str, tool_input: str) -> InterceptResult:
    return InterceptResult(decision="ALLOWED")


def intercept_output(run_id: str, output: str) -> InterceptResult:
    return InterceptResult(decision="ALLOWED")
