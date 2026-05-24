"""
antivirus_interceptor.py — YARA-based code scanner.

scan_code() never raises (fail-open).
3-tier rule loading: in-process cache → Redis → PostgreSQL.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 10 hardcoded fallback rules (used when DB is unreachable)
# Names match exactly the names seeded in the DB — no duplication.
# ---------------------------------------------------------------------------
_FALLBACK_RULE_SOURCES: dict[str, str] = {
    "CryptoMiner_XMRig": """
rule CryptoMiner_XMRig {
    strings:
        $a = "xmrig" nocase
        $b = "--donate-level" nocase
        $c = "cryptonight" nocase
    condition:
        any of them
}
""",
    "CryptoMiner_Stratum": """
rule CryptoMiner_Stratum {
    strings:
        $a = "stratum+tcp://" nocase
        $b = "stratum+ssl://" nocase
    condition:
        any of them
}
""",
    "ReverseShell_BashDevTcp": """
rule ReverseShell_BashDevTcp {
    strings:
        $a = "/dev/tcp/" nocase
        $b = "bash -i" nocase
    condition:
        all of them
}
""",
    "ReverseShell_NcExec": """
rule ReverseShell_NcExec {
    strings:
        $a = "nc " nocase
        $b = "-e /bin/sh" nocase
        $c = "-e /bin/bash" nocase
    condition:
        $a and ($b or $c)
}
""",
    "Persistence_Crontab": """
rule Persistence_Crontab {
    strings:
        $a = "crontab" nocase
        $b = "@reboot" nocase
    condition:
        any of them
}
""",
    "Persistence_Systemctl": """
rule Persistence_Systemctl {
    strings:
        $a = "systemctl enable" nocase
        $b = "systemctl start" nocase
    condition:
        any of them
}
""",
    "Obfuscation_Base64Pipe": """
rule Obfuscation_Base64Pipe {
    strings:
        $a = "base64 -d" nocase
        $b = "base64 --decode" nocase
    condition:
        any of them
}
""",
    "Obfuscation_EvalDecode": """
rule Obfuscation_EvalDecode {
    strings:
        $a = "eval(base64_decode" nocase
        $b = "eval(decode" nocase
    condition:
        any of them
}
""",
    "Exfiltration_CurlPost": """
rule Exfiltration_CurlPost {
    strings:
        $a = "curl" nocase
        $b = "--data" nocase
        $c = "-d " nocase
        $d = "/etc/passwd" nocase
        $e = "/etc/shadow" nocase
    condition:
        $a and ($b or $c) and ($d or $e)
}
""",
    "Exfiltration_WgetPost": """
rule Exfiltration_WgetPost {
    strings:
        $a = "wget" nocase
        $b = "--post-data" nocase
        $c = "--post-file" nocase
    condition:
        $a and ($b or $c)
}
""",
}

# ---------------------------------------------------------------------------
# In-process compiled-rules cache (5-min TTL)
# ---------------------------------------------------------------------------
try:
    import yara  # type: ignore
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False
    logger.warning("antivirus_interceptor: yara-python not installed — scanner disabled (fail-open)")

_compiled_rules: Any = None
_last_refresh: float = 0.0
_CACHE_TTL = 300.0  # 5 minutes

# ---------------------------------------------------------------------------
# External connections
# ---------------------------------------------------------------------------
import psycopg2  # type: ignore

_DB_DSN = (
    f"host={os.getenv('POSTGRES_HOST', 'postgres')} "
    f"port={os.getenv('POSTGRES_PORT', '5432')} "
    f"dbname={os.getenv('POSTGRES_DB', 'agentshield')} "
    f"user={os.getenv('POSTGRES_USER', 'agentshield')} "
    f"password={os.getenv('POSTGRES_PASSWORD', 'agentshield')} "
    f"sslmode=disable"
)

try:
    import redis as _redis  # type: ignore
    _redis_client = _redis.Redis.from_url(os.getenv("REDIS_URL", "redis://redis:6379/0"))
    _REDIS_AVAILABLE = True
except Exception:
    _redis_client = None
    _REDIS_AVAILABLE = False

_REDIS_KEY = "av:yara_rules"
_REDIS_TTL = 300


# ---------------------------------------------------------------------------
# Rule loading helpers
# ---------------------------------------------------------------------------

def _compile_from_sources(sources: dict[str, str]) -> Any:
    """Compile a dict of {name: rule_text} into a yara.Rules object."""
    return yara.compile(sources=sources)  # type: ignore[name-defined]


def _load_rules_from_db() -> dict[str, str] | None:
    """Return {name: rule_text} from DB, or None on error."""
    try:
        conn = psycopg2.connect(_DB_DSN)
        cur = conn.cursor()
        cur.execute("SELECT name, rule_text FROM yara_rules WHERE active = TRUE")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return {row[0]: row[1] for row in rows} if rows else None
    except Exception as exc:
        logger.warning("antivirus_interceptor: DB load failed: %s", exc)
        return None


def _get_rules() -> Any:
    """Return compiled yara.Rules using 3-tier cache; fall back to hardcoded rules."""
    global _compiled_rules, _last_refresh

    if not _YARA_AVAILABLE:
        return None

    now = time.monotonic()
    if _compiled_rules is not None and (now - _last_refresh) < _CACHE_TTL:
        return _compiled_rules

    sources: dict[str, str] | None = None

    # Tier 1: Redis
    if _REDIS_AVAILABLE and _redis_client is not None:
        try:
            cached = _redis_client.get(_REDIS_KEY)
            if cached:
                items = json.loads(cached)
                sources = {item["name"]: item["rule_text"] for item in items}
        except Exception as exc:
            logger.debug("antivirus_interceptor: Redis miss: %s", exc)

    # Tier 2: PostgreSQL
    if sources is None:
        db_sources = _load_rules_from_db()
        if db_sources:
            sources = db_sources
            # Populate Redis cache
            if _REDIS_AVAILABLE and _redis_client is not None:
                try:
                    payload = [{"name": k, "rule_text": v} for k, v in sources.items()]
                    _redis_client.setex(_REDIS_KEY, _REDIS_TTL, json.dumps(payload))
                except Exception:
                    pass

    # Tier 3: Hardcoded fallback
    if not sources:
        sources = _FALLBACK_RULE_SOURCES

    try:
        _compiled_rules = _compile_from_sources(sources)
        _last_refresh = now
    except Exception as exc:
        logger.warning("antivirus_interceptor: rule compilation failed: %s", exc)
        # Try compiling fallback only
        try:
            _compiled_rules = _compile_from_sources(_FALLBACK_RULE_SOURCES)
            _last_refresh = now
        except Exception as exc2:
            logger.error("antivirus_interceptor: fallback compilation failed: %s", exc2)
            _compiled_rules = None

    return _compiled_rules


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_code(content: str, content_type: str = "SHELL_SCRIPT") -> dict:
    """
    Scan *content* for known malware signatures using YARA.

    Returns:
        {"decision": str, "reason": str, "severity": str,
         "matches": list[dict], "rule_name": str | None}

    Never raises — fail-open on any error.
    """
    try:
        rules = _get_rules()
        if rules is None:
            return {"decision": "ALLOWED", "reason": "", "severity": "INFO",
                    "matches": [], "rule_name": None}

        matches = rules.match(data=content.encode("utf-8", errors="replace"))
        if matches:
            first = matches[0]
            return {
                "decision":  "BLOCKED",
                "reason":    first.rule,
                "severity":  "CRITICAL",
                "matches":   [{"rule": m.rule, "tags": list(m.tags)} for m in matches],
                "rule_name": first.rule,
            }
        return {"decision": "ALLOWED", "reason": "", "severity": "INFO",
                "matches": [], "rule_name": None}
    except Exception as exc:
        logger.warning("scan_code: unexpected error: %s", exc)
        return {"decision": "ALLOWED", "reason": "", "severity": "INFO",
                "matches": [], "rule_name": None}
