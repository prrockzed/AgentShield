from dataclasses import dataclass

from app.events import publish_event


@dataclass
class InterceptResult:
    decision: str  # "ALLOWED" | "BLOCKED" | "FLAGGED" | "REDACTED"
    reason: str = ""


def intercept_input(run_id: str, agent_type: str, task: str) -> InterceptResult:
    result = InterceptResult(decision="ALLOWED")
    publish_event({
        "run_id":     run_id,
        "event_type": "PROMPT_SCAN",
        "source":     "prompt_interceptor_stub",
        "payload":    {"agent_type": agent_type, "task_length": len(task)},
        "decision":   result.decision,
        "reason":     result.reason or None,
        "severity":   "INFO",
    })
    return result


def intercept_tool_call(run_id: str, tool_name: str, tool_input: str) -> InterceptResult:
    result = InterceptResult(decision="ALLOWED")
    publish_event({
        "run_id":     run_id,
        "event_type": "TOOL_INTERCEPT",
        "source":     "tool_interceptor_stub",
        "payload":    {"tool_name": tool_name, "input_length": len(tool_input)},
        "decision":   result.decision,
        "reason":     result.reason or None,
        "severity":   "INFO",
    })
    return result


def intercept_output(run_id: str, output: str) -> InterceptResult:
    result = InterceptResult(decision="ALLOWED")
    publish_event({
        "run_id":     run_id,
        "event_type": "OUTPUT_SCAN",
        "source":     "output_interceptor_stub",
        "payload":    {"output_length": len(output)},
        "decision":   result.decision,
        "reason":     result.reason or None,
        "severity":   "INFO",
    })
    return result
