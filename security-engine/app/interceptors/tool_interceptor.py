import json
import logging
import os
import re
import time

import redis

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hardcoded baseline rules — always active, evaluated in-process
# ---------------------------------------------------------------------------

_SHELL_RULES: list[tuple[str, str]] = [
    # destructive
    (r"\brm\b\s+.*-[^\s]*[rR][^\s]*.*-[^\s]*[fF]", "destructive_command"),
    (r"\brm\b\s+.*-[^\s]*[fF][^\s]*.*-[^\s]*[rR]", "destructive_command"),
    (r"\brm\b\s+-[rRfF]{2,}",                        "destructive_command"),
    (r"\bmkfs\b",                                     "destructive_command"),
    (r"\bdd\s+if=",                                   "destructive_command"),
    (r"\bshred\b",                                    "destructive_command"),
    # privilege escalation
    (r"\bsudo\b",                                     "privilege_escalation"),
    (r"\bsu\s+-\b",                                   "privilege_escalation"),
    (r"\bsu\s+root\b",                                "privilege_escalation"),
    (r"\bchmod\s+[0-9]*7[0-9][0-9]\b",               "privilege_escalation"),
    (r"\bchmod\s+[augo]*\+[rwx]*s\b",                "privilege_escalation"),
    (r"\bchown\s+root[:\s]",                          "privilege_escalation"),
    (r"\bchown\s+0[:\s]",                             "privilege_escalation"),
    # remote code execution
    (r"curl\b.*\|\s*(ba)?sh\b",                       "remote_code_execution"),
    (r"wget\b.*\|\s*(ba)?sh\b",                       "remote_code_execution"),
    (r"curl\b.*\|\s*python[23]?\b",                   "remote_code_execution"),
    (r"wget\b.*\|\s*python[23]?\b",                   "remote_code_execution"),
    (r"\beval\s*\(\s*[`$]\(?curl\b",                  "remote_code_execution"),
    (r"\beval\s*\(\s*[`$]\(?wget\b",                  "remote_code_execution"),
    (r"\bbash\s*<\s*\(\s*curl\b",                     "remote_code_execution"),
    (r"\bbash\s*<\s*\(\s*wget\b",                     "remote_code_execution"),
    # backdoor / reverse shell
    (r"\bnc\b.*-l\b",                                 "backdoor"),
    (r"\bnetcat\b.*-l\b",                             "backdoor"),
    (r"\bncat\b.*-l\b",                               "backdoor"),
    (r"/dev/tcp/",                                    "backdoor"),
    (r"/dev/udp/",                                    "backdoor"),
    (r"\bbash\s+-i\b",                                "backdoor"),
    (r"\bmkfifo\b.*\bnc\b",                           "backdoor"),
    (r"0>&1",                                         "backdoor"),
    # crypto miners
    (r"\bxmrig\b",                                    "crypto_miner"),
    (r"\bminerd\b",                                   "crypto_miner"),
    (r"\bccminer\b",                                  "crypto_miner"),
    (r"\bsgminer\b",                                  "crypto_miner"),
    (r"\bcgminer\b",                                  "crypto_miner"),
    (r"\bbfgminer\b",                                 "crypto_miner"),
    (r"stratum\+(tcp|ssl)://",                        "crypto_miner"),
    (r"--pool\s+\S+\.\S+:\d{2,5}",                   "crypto_miner"),
]

_COMPILED_BASE: list[tuple[re.Pattern, str]] = [
    (re.compile(p, re.IGNORECASE), r) for p, r in _SHELL_RULES
]

# ---------------------------------------------------------------------------
# Redis — custom rules cache
# ---------------------------------------------------------------------------

_REDIS_KEY = "agentshield:policy:shell_rules"
_CACHE_TTL = 300  # seconds

_custom_compiled: list[tuple[re.Pattern, str]] = []
_last_refresh: float = 0.0


def _redis_client() -> redis.Redis:
    url = os.getenv("REDIS_URL", "redis://redis:6379/0")
    return redis.Redis.from_url(url, decode_responses=True, socket_timeout=2)


def _refresh_custom_rules() -> None:
    global _custom_compiled, _last_refresh
    try:
        raw = _redis_client().get(_REDIS_KEY)
        if raw:
            entries = json.loads(raw)
            _custom_compiled = [
                (re.compile(e["pattern"], re.IGNORECASE), e["reason"])
                for e in entries
                if "pattern" in e and "reason" in e
            ]
        else:
            _custom_compiled = []
    except Exception as exc:
        logger.warning("tool_interceptor: redis refresh failed: %s", exc)
    _last_refresh = time.monotonic()


def _custom_rules() -> list[tuple[re.Pattern, str]]:
    if time.monotonic() - _last_refresh > _CACHE_TTL:
        _refresh_custom_rules()
    return _custom_compiled


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def evaluate_shell_command(command: str) -> dict:
    for pattern, reason in _COMPILED_BASE:
        if pattern.search(command):
            return {"decision": "BLOCKED", "reason": reason}
    for pattern, reason in _custom_rules():
        if pattern.search(command):
            return {"decision": "BLOCKED", "reason": reason}
    return {"decision": "ALLOWED", "reason": ""}
