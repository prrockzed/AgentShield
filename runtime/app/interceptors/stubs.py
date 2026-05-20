import logging
import os
from dataclasses import dataclass

import httpx

from app.events import publish_event

logger = logging.getLogger(__name__)

_SE_URL = os.getenv("SECURITY_ENGINE_URL", "http://security-engine:8001")


@dataclass
class InterceptResult:
    decision: str  # "ALLOWED" | "BLOCKED" | "FLAGGED" | "REDACTED"
    reason: str = ""
    redacted_content: str = ""


def intercept_prompt(run_id: str, content: str, source: str) -> InterceptResult:
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(
                f"{_SE_URL}/intercept/prompt",
                json={"run_id": run_id, "content": content, "source": source},
            )
            data = resp.json()
            result = InterceptResult(decision=data["decision"], reason=data.get("reason", ""))
    except Exception as exc:
        logger.warning("intercept_prompt: security-engine unreachable: %s", exc)
        result = InterceptResult(decision="ALLOWED", reason="")

    severity = {"BLOCKED": "CRITICAL", "FLAGGED": "HIGH"}.get(result.decision, "INFO")
    publish_event({
        "run_id":     run_id,
        "event_type": "PROMPT_SCAN",
        "source":     "prompt_interceptor",
        "payload":    {"content_length": len(content), "source": source},
        "decision":   result.decision,
        "reason":     result.reason or None,
        "severity":   severity,
    })
    return result


def intercept_input(run_id: str, agent_type: str, task: str) -> InterceptResult:
    return intercept_prompt(run_id, task, "USER_INPUT")


def intercept_tool_call(run_id: str, tool_name: str, tool_input: str) -> InterceptResult:
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(
                f"{_SE_URL}/intercept/tool",
                json={"run_id": run_id, "tool_name": tool_name, "args": {"command": tool_input}},
            )
            data = resp.json()
            result = InterceptResult(decision=data["decision"], reason=data.get("reason", ""))
    except Exception as exc:
        logger.warning("intercept_tool_call: security-engine unreachable: %s", exc)
        result = InterceptResult(decision="ALLOWED", reason="")

    severity = "HIGH" if result.decision == "BLOCKED" else "INFO"
    publish_event({
        "run_id":     run_id,
        "event_type": "TOOL_INTERCEPT",
        "source":     "tool_interceptor",
        "payload":    {"tool_name": tool_name, "command": tool_input},
        "decision":   result.decision,
        "reason":     result.reason or None,
        "severity":   severity,
    })
    return result


def intercept_output(run_id: str, output: str) -> InterceptResult:
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(
                f"{_SE_URL}/intercept/output",
                json={"run_id": run_id, "content": output},
            )
            data = resp.json()
            result = InterceptResult(
                decision=data["decision"],
                redacted_content=data.get("redacted_content", output),
            )
            detections = data.get("detections", [])
    except Exception as exc:
        logger.warning("intercept_output: security-engine unreachable: %s", exc)
        result = InterceptResult(decision="ALLOWED", redacted_content=output)
        detections = []

    severity = "HIGH" if result.decision == "REDACTED" else "INFO"
    publish_event({
        "run_id":     run_id,
        "event_type": "OUTPUT_SCAN",
        "source":     "output_interceptor",
        "payload":    {"output_length": len(output), "detections": detections},
        "decision":   result.decision,
        "reason":     f"{len(detections)} detection(s)" if detections else None,
        "severity":   severity,
    })
    return result
