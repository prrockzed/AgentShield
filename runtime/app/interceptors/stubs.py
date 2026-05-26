import logging
import os
from contextvars import ContextVar
from dataclasses import dataclass

import httpx

from app.events import publish_event

logger = logging.getLogger(__name__)

_SE_URL = os.getenv("SECURITY_ENGINE_URL", "http://security-engine:8001")

_terminated_runs: set[str] = set()

# Per-request context variable holding the set of enabled check names.
# None (default) means all checks are enabled.
_enabled_checks_ctx: ContextVar[frozenset[str] | None] = ContextVar(
    "enabled_checks", default=None
)


def _check_enabled(name: str) -> bool:
    """Return True if the named check should run. None context means all enabled."""
    enabled = _enabled_checks_ctx.get()
    return enabled is None or name in enabled


def is_terminated(run_id: str) -> bool:
    return run_id in _terminated_runs


def cleanup_run(run_id: str) -> None:
    _terminated_runs.discard(run_id)


def analyze_behavior(run_id: str, tool_name: str, command: str | None = None) -> str:
    """
    POST /analyze/behavior on the security-engine.
    Publishes a BEHAVIORAL_ALERT event for each newly-fired rule.
    Returns 'OK' | 'WARN' | 'TERMINATE'. Never raises.
    """
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.post(
                f"{_SE_URL}/analyze/behavior",
                json={"run_id": run_id, "tool_name": tool_name, "command": command},
            )
            data = resp.json()
    except Exception as exc:
        logger.warning("analyze_behavior: security-engine unreachable: %s", exc)
        return "OK"

    for alert in data.get("alerts", []):
        publish_event({
            "run_id":     run_id,
            "event_type": "BEHAVIORAL_ALERT",
            "source":     "behavioral_analyzer",
            "payload":    {
                "rule":     alert["rule"],
                "message":  alert["message"],
                "counters": data.get("counters", {}),
            },
            "decision":   "BLOCKED" if alert["verdict"] == "TERMINATE" else "FLAGGED",
            "reason":     alert["rule"],
            "severity":   alert["severity"],
        })

    return data.get("verdict", "OK")


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
            matched_signature_id = data.get("matched_signature_id")
            result = InterceptResult(decision=data["decision"], reason=data.get("reason", ""))
    except Exception as exc:
        logger.warning("intercept_prompt: security-engine unreachable: %s", exc)
        matched_signature_id = None
        result = InterceptResult(decision="ALLOWED", reason="")

    severity = {"BLOCKED": "CRITICAL", "FLAGGED": "HIGH"}.get(result.decision, "INFO")
    publish_event({
        "run_id":                run_id,
        "event_type":            "PROMPT_SCAN",
        "source":                "prompt_interceptor",
        "payload":               {"content_length": len(content), "source": source},
        "decision":              result.decision,
        "reason":                result.reason or None,
        "severity":              severity,
        "matched_signature_id":  matched_signature_id,
    })
    return result


def intercept_input(run_id: str, agent_type: str, task: str) -> InterceptResult:
    if not _check_enabled("PROMPT_SCAN"):
        return InterceptResult(decision="ALLOWED", reason="check disabled")
    return intercept_prompt(run_id, task, "USER_INPUT")


def intercept_tool_call(run_id: str, tool_name: str, tool_input: str) -> InterceptResult:
    # Fast-path: run already terminated by a prior behavioral verdict
    if is_terminated(run_id):
        return InterceptResult(decision="BLOCKED", reason="Run terminated by behavioral policy")

    tool_enabled = _check_enabled("TOOL_INTERCEPT")
    behavioral_enabled = _check_enabled("BEHAVIORAL_ALERT")

    result = InterceptResult(decision="ALLOWED", reason="")

    # ── Security-engine tool intercept ──────────────────────────────────
    if tool_enabled:
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

    # ── Behavioral analysis ──────────────────────────────────────────────
    if behavioral_enabled:
        shell_tools = {"shell", "bash", "run_shell", "execute_command", "exec", "shell_exec"}
        cmd = tool_input if tool_name.lower() in shell_tools else None
        b_verdict = analyze_behavior(run_id, tool_name, cmd)
        if b_verdict == "TERMINATE":
            _terminated_runs.add(run_id)
            result = InterceptResult(decision="BLOCKED", reason="Run terminated by behavioral policy")

    return result


def intercept_network(run_id: str, url: str, method: str = "GET") -> InterceptResult:
    """
    POST /intercept/network on the security-engine.
    Publishes a NETWORK_INTERCEPT event.
    Returns ALLOWED on any network error (fail-open).
    """
    if not _check_enabled("NETWORK_INTERCEPT"):
        return InterceptResult(decision="ALLOWED", reason="check disabled")
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(
                f"{_SE_URL}/intercept/network",
                json={"run_id": run_id, "url": url, "method": method},
            )
            data = resp.json()
            result = InterceptResult(decision=data["decision"], reason=data.get("reason", ""))
    except Exception as exc:
        logger.warning("intercept_network: security-engine unreachable: %s", exc)
        result = InterceptResult(decision="ALLOWED", reason="")

    severity = "HIGH" if result.decision == "BLOCKED" else "INFO"
    publish_event({
        "run_id":     run_id,
        "event_type": "NETWORK_INTERCEPT",
        "source":     "network_interceptor",
        "payload":    {"url": url, "method": method},
        "decision":   result.decision,
        "reason":     result.reason or None,
        "severity":   severity,
    })

    return result


def intercept_filesystem(run_id: str, path: str, operation: str = "READ") -> InterceptResult:
    """
    POST /intercept/filesystem on the security-engine.
    Publishes a FILESYSTEM_INTERCEPT event.
    Returns ALLOWED on any network error (fail-open).
    """
    if not _check_enabled("FILESYSTEM_INTERCEPT"):
        return InterceptResult(decision="ALLOWED", reason="check disabled")
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(
                f"{_SE_URL}/intercept/filesystem",
                json={"run_id": run_id, "path": path, "operation": operation},
            )
            data     = resp.json()
            result   = InterceptResult(decision=data["decision"], reason=data.get("reason", ""))
            severity = data.get("severity", "HIGH") if data["decision"] != "ALLOWED" else "INFO"
    except Exception as exc:
        logger.warning("intercept_filesystem: security-engine unreachable: %s", exc)
        result   = InterceptResult(decision="ALLOWED", reason="")
        severity = "INFO"

    publish_event({
        "run_id":     run_id,
        "event_type": "FILESYSTEM_INTERCEPT",
        "source":     "filesystem_interceptor",
        "payload":    {"path": path, "operation": operation},
        "decision":   result.decision,
        "reason":     result.reason or None,
        "severity":   severity,
    })

    return result


def intercept_browser(run_id: str, url: str, html_content: str) -> InterceptResult:
    """
    POST /intercept/browser on the security-engine.
    Always publishes a BROWSER_INTERCEPT event (even ALLOWED — full audit trail).
    Returns ALLOWED on any error (fail-open).
    """
    if not _check_enabled("BROWSER_INTERCEPT"):
        return InterceptResult(decision="ALLOWED", reason="check disabled")
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(
                f"{_SE_URL}/intercept/browser",
                json={"run_id": run_id, "url": url, "html_content": html_content},
            )
            data     = resp.json()
            result   = InterceptResult(decision=data["decision"], reason=data.get("reason", ""))
            severity = data.get("severity", "INFO") if data["decision"] != "ALLOWED" else "INFO"
            findings = data.get("findings", [])
            score    = data.get("score", 0.0)
    except Exception as exc:
        logger.warning("intercept_browser: security-engine unreachable: %s", exc)
        result   = InterceptResult(decision="ALLOWED", reason="")
        severity = "INFO"
        findings = []
        score    = 0.0

    publish_event({
        "run_id":     run_id,
        "event_type": "BROWSER_INTERCEPT",
        "source":     "browser_interceptor",
        "payload":    {"url": url, "score": score, "findings": findings},
        "decision":   result.decision,
        "reason":     result.reason or None,
        "severity":   severity,
    })
    return result


def scan_code(run_id: str, content: str, content_type: str = "SHELL_SCRIPT") -> InterceptResult:
    """
    POST /scan/code on the security-engine.
    Always publishes a CODE_SCAN event (full audit trail).
    Returns ALLOWED on any error (fail-open).
    """
    if not _check_enabled("CODE_SCAN"):
        return InterceptResult(decision="ALLOWED", reason="check disabled")
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(
                f"{_SE_URL}/scan/code",
                json={"run_id": run_id, "content": content, "content_type": content_type},
            )
            data      = resp.json()
            result    = InterceptResult(decision=data["decision"], reason=data.get("reason", ""))
            severity  = "CRITICAL" if data["decision"] == "BLOCKED" else "INFO"
            matches   = data.get("matches", [])
            rule_name = data.get("rule_name")
    except Exception as exc:
        logger.warning("scan_code: security-engine unreachable: %s", exc)
        result    = InterceptResult(decision="ALLOWED", reason="")
        severity  = "INFO"
        matches   = []
        rule_name = None

    publish_event({
        "run_id":     run_id,
        "event_type": "CODE_SCAN",
        "source":     "antivirus_interceptor",
        "payload":    {"content_type": content_type, "matches": matches, "rule_name": rule_name},
        "decision":   result.decision,
        "reason":     result.reason or None,
        "severity":   severity,
    })
    return result


def analyze_hallucination(run_id: str, output: str, tool_results: list[dict]) -> dict:
    """
    POST /analyze/hallucination on the security-engine.
    Publishes a HALLUCINATION_DETECTION event when score > 0.
    Returns {"score": 0.0, "status": "OK", "flags": []} on any error (fail-safe).
    """
    if not _check_enabled("HALLUCINATION_DETECTION"):
        return {"score": 0.0, "status": "OK", "flags": []}
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                f"{_SE_URL}/analyze/hallucination",
                json={"run_id": run_id, "output": output, "tool_results": tool_results},
            )
            data = resp.json()
    except Exception as exc:
        logger.warning("analyze_hallucination: security-engine unreachable: %s", exc)
        data = {"score": 0.0, "status": "OK", "flags": []}

    score  = data.get("score", 0.0)
    status = data.get("status", "OK")

    if score > 0.0:
        severity = "CRITICAL" if status == "UNRELIABLE" else "HIGH" if status == "WARN" else "INFO"
        publish_event({
            "run_id":     run_id,
            "event_type": "HALLUCINATION_DETECTION",
            "source":     "hallucination_analyzer",
            "payload":    {"score": score, "flags": data.get("flags", [])},
            "decision":   status,
            "reason":     f"hallucination_score={score}",
            "severity":   severity,
        })

    return data


def intercept_output(run_id: str, output: str) -> InterceptResult:
    if not _check_enabled("OUTPUT_SCAN"):
        return InterceptResult(decision="ALLOWED", reason="check disabled")
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
