"""
Hallucination detection analyzer.
Cross-references the agent's final output text against actual tool return values.
analyze_hallucination() never raises.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

_SUCCESS_PHRASES = [
    "successfully", "success", "completed", "done", "finished",
    "created", "wrote", "written", "modified", "updated", "changed",
    "read", "found", "retrieved", "fetched", "executed", "ran",
    "processed", "deleted", "removed",
]


def analyze_hallucination(output: str, tool_results: list[dict[str, Any]]) -> dict:
    """
    Evaluate the agent's output against tool results for hallucination signals.
    Returns {"score": float, "status": str, "flags": list[dict]}.
    Never raises.
    """
    try:
        score = 0.0
        flags: list[dict] = []
        output_lower = output.lower()
        has_success_claim = any(phrase in output_lower for phrase in _SUCCESS_PHRASES)

        for tr in tool_results:
            tool_name = tr.get("tool_name", "")
            result = tr.get("result", "")
            if not isinstance(result, str):
                result = str(result)

            # Rule 1: success claim in output but the tool returned an error
            if has_success_claim and result.startswith("Error:"):
                score += 0.4
                flags.append({
                    "rule":     "SUCCESS_CLAIM_ON_ERROR",
                    "tool":     tool_name,
                    "evidence": result[:120],
                    "severity": "HIGH",
                })

            # Rule 2: success claim but action was blocked by a security policy
            if has_success_claim and "blocked by" in result and "policy" in result:
                score += 0.6
                flags.append({
                    "rule":     "BLOCKED_ACTION_CLAIMED",
                    "tool":     tool_name,
                    "evidence": result[:120],
                    "severity": "CRITICAL",
                })

            # Rule 3: file_read returned "file not found" — agent may fabricate content
            if tool_name == "file_read" and result.startswith("Error: file not found"):
                score += 0.3
                flags.append({
                    "rule":     "NONEXISTENT_FILE_REFERENCE",
                    "tool":     tool_name,
                    "evidence": result[:120],
                    "severity": "HIGH",
                })

        score = min(round(score, 3), 1.0)
        if score > 0.7:
            status = "UNRELIABLE"
        elif score > 0.3:
            status = "WARN"
        else:
            status = "OK"

        return {"score": score, "status": status, "flags": flags}

    except Exception as exc:
        logger.warning("hallucination_analyzer: unexpected error: %s", exc)
        return {"score": 0.0, "status": "OK", "flags": []}
