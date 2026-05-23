"""
Runtime behavioral analyzer.
Maintains per-run Redis counters and evaluates anomaly rules.
analyze() never raises — returns {"verdict":"OK","alerts":[],"counters":{}} on failure.
"""
from __future__ import annotations

import logging
import os
import time

import redis as redis_lib

logger = logging.getLogger(__name__)

_TTL = 86400  # 24 h — keys expire after one day


def _redis() -> redis_lib.Redis:
    url = os.getenv("REDIS_URL", "redis://redis:6379/0")
    return redis_lib.Redis.from_url(url, decode_responses=True, socket_timeout=2)


def analyze(run_id: str, tool_name: str, command: str | None = None) -> dict:
    """
    Increment per-run counters, evaluate rules, return verdict.

    Returns:
        {
          "verdict": "OK" | "WARN" | "TERMINATE",
          "alerts":  [{"rule":…, "severity":…, "verdict":…, "message":…}],
          "counters": {"tool_call_count":…, "shell_call_count":…, "elapsed_ms":…}
        }
    """
    try:
        r = _redis()
        key      = f"agentshield:behavior:{run_id}"
        cmds_key = f"{key}:cmds"
        fired_key = f"{key}:fired"

        # ── Increment counters ──────────────────────────────────────────────
        pipe = r.pipeline()
        pipe.hsetnx(key, "start_time_ms", int(time.time() * 1000))
        pipe.hincrby(key, "tool_call_count", 1)
        is_shell = tool_name.lower() in ("shell", "bash", "run_shell", "execute_command", "exec", "shell_exec")
        if is_shell:
            pipe.hincrby(key, "shell_call_count", 1)
        pipe.expire(key, _TTL)
        pipe.execute()

        # Track unique command repetitions
        if command:
            r.zincrby(cmds_key, 1, command[:200])   # cap key length
            r.expire(cmds_key, _TTL)
        r.expire(fired_key, _TTL)

        # ── Read current state ──────────────────────────────────────────────
        data        = r.hgetall(key)
        tool_calls  = int(data.get("tool_call_count",  0))
        shell_calls = int(data.get("shell_call_count", 0))
        start_ms    = int(data.get("start_time_ms",    0))
        elapsed_ms  = int(time.time() * 1000) - start_ms if start_ms else 0

        alerts: list[dict] = []

        # ── Rule: RUNAWAY_AGENT ─────────────────────────────────────────────
        if tool_calls > 50 and not r.sismember(fired_key, "RUNAWAY_AGENT"):
            r.sadd(fired_key, "RUNAWAY_AGENT")
            alerts.append({
                "rule":     "RUNAWAY_AGENT",
                "severity": "CRITICAL",
                "verdict":  "TERMINATE",
                "message":  f"tool_call_count={tool_calls} exceeds limit of 50",
            })

        # ── Rule: REPETITIVE_EXECUTION ──────────────────────────────────────
        if command:
            cmd_count = int(r.zscore(cmds_key, command[:200]) or 0)
            dedup_key = f"REPETITIVE_EXECUTION:{command[:100]}"
            if cmd_count > 5 and not r.sismember(fired_key, dedup_key):
                r.sadd(fired_key, dedup_key)
                alerts.append({
                    "rule":     "REPETITIVE_EXECUTION",
                    "severity": "HIGH",
                    "verdict":  "WARN",
                    "message":  f"command repeated {cmd_count} times: {command[:80]}",
                })

        # ── Rule: TIMEOUT_APPROACHING ───────────────────────────────────────
        if elapsed_ms > 5 * 60 * 1000 and not r.sismember(fired_key, "TIMEOUT_APPROACHING"):
            r.sadd(fired_key, "TIMEOUT_APPROACHING")
            alerts.append({
                "rule":     "TIMEOUT_APPROACHING",
                "severity": "MEDIUM",
                "verdict":  "WARN",
                "message":  f"run elapsed {elapsed_ms // 1000}s exceeds 5-minute threshold",
            })

        # ── Rule: SHELL_HEAVY ───────────────────────────────────────────────
        if (tool_calls >= 5
                and shell_calls / tool_calls > 0.8
                and not r.sismember(fired_key, "SHELL_HEAVY")):
            r.sadd(fired_key, "SHELL_HEAVY")
            alerts.append({
                "rule":     "SHELL_HEAVY",
                "severity": "MEDIUM",
                "verdict":  "WARN",
                "message":  f"shell_ratio={shell_calls/tool_calls:.2f} ({shell_calls}/{tool_calls} calls)",
            })

        # ── Overall verdict ─────────────────────────────────────────────────
        verdict = "OK"
        if any(a["verdict"] == "TERMINATE" for a in alerts):
            verdict = "TERMINATE"
        elif alerts:
            verdict = "WARN"

        return {
            "verdict":  verdict,
            "alerts":   alerts,
            "counters": {
                "tool_call_count":  tool_calls,
                "shell_call_count": shell_calls,
                "elapsed_ms":       elapsed_ms,
            },
        }

    except Exception as exc:
        logger.error("behavioral.analyze: %s", exc)
        return {"verdict": "OK", "alerts": [], "counters": {}}
