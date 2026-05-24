"""
Filesystem access interceptor.
Evaluates file paths against hardcoded baseline rules and a DB-backed policy table.
evaluate_filesystem_request() never raises — fail-open on all exceptions.
"""
from __future__ import annotations

import fnmatch
import json
import logging
import os
import time
from typing import TypedDict

import psycopg2
import psycopg2.extras
import redis as redis_lib

logger = logging.getLogger(__name__)

_CACHE_TTL = 300  # 5 minutes
_REDIS_KEY = "agentshield:policy:filesystem_policies"

# (path_pattern, frozenset of operations, decision, severity, reason)
# Evaluated top-to-bottom; first match wins — most-specific rules listed first.
_BASELINE: list[tuple[str, frozenset, str, str, str]] = [
    # SSH private keys — CRITICAL
    ("*/.ssh/id_rsa",      frozenset({"read","write","delete","all"}), "BLOCKED", "CRITICAL", "ssh_private_key"),
    ("*/.ssh/id_ed25519",  frozenset({"read","write","delete","all"}), "BLOCKED", "CRITICAL", "ssh_private_key"),
    ("*/.ssh/id_dsa",      frozenset({"read","write","delete","all"}), "BLOCKED", "CRITICAL", "ssh_private_key"),
    ("*/.ssh/id_ecdsa",    frozenset({"read","write","delete","all"}), "BLOCKED", "CRITICAL", "ssh_private_key"),
    # SSH dir catch-all
    ("*/.ssh/*",           frozenset({"read"}),                        "FLAGGED", "HIGH",     "ssh_config_read"),
    ("*/.ssh/*",           frozenset({"write","delete","all"}),        "BLOCKED", "CRITICAL", "ssh_dir_write"),
    # System auth
    ("/etc/shadow",        frozenset({"read","write","delete","all"}), "BLOCKED", "CRITICAL", "shadow_file_access"),
    ("/etc/sudoers",       frozenset({"read","write","delete","all"}), "BLOCKED", "CRITICAL", "sudoers_access"),
    ("/etc/sudoers.d/*",   frozenset({"read","write","delete","all"}), "BLOCKED", "CRITICAL", "sudoers_access"),
    ("/etc/passwd",        frozenset({"read"}),                        "FLAGGED", "MEDIUM",   "system_user_database"),
    # Cloud credentials
    ("*/.aws/credentials", frozenset({"read","write","delete","all"}), "BLOCKED", "CRITICAL", "aws_credentials"),
    ("*/.aws/*",           frozenset({"read"}),                        "FLAGGED", "HIGH",     "aws_config_read"),
    ("*/.config/gcloud/credentials.db",
                           frozenset({"read","write","delete","all"}), "BLOCKED", "CRITICAL", "gcloud_credentials"),
    ("*/.config/gcloud/application_default_credentials.json",
                           frozenset({"read","write","delete","all"}), "BLOCKED", "CRITICAL", "gcloud_credentials"),
    # Cert / key files
    ("*.pem",              frozenset({"read","write","delete","all"}), "BLOCKED", "HIGH",     "certificate_or_private_key"),
    ("*.p12",              frozenset({"read","write","delete","all"}), "BLOCKED", "HIGH",     "pkcs12_certificate"),
    ("*.pfx",              frozenset({"read","write","delete","all"}), "BLOCKED", "HIGH",     "pkcs12_certificate"),
    # Environment / secret files
    ("*.env",              frozenset({"read"}),                        "FLAGGED", "HIGH",     "env_file_read"),
    (".env.*",             frozenset({"read"}),                        "FLAGGED", "HIGH",     "env_file_read"),
    ("*/.env",             frozenset({"read"}),                        "FLAGGED", "HIGH",     "env_file_read"),
    # System binary dirs — write only
    ("/usr/bin/*",         frozenset({"write","delete","all"}),        "BLOCKED", "HIGH",     "system_binary_write"),
    ("/bin/*",             frozenset({"write","delete","all"}),        "BLOCKED", "HIGH",     "system_binary_write"),
    ("/sbin/*",            frozenset({"write","delete","all"}),        "BLOCKED", "HIGH",     "system_binary_write"),
]


class PolicyRecord(TypedDict):
    id:           str
    path_pattern: str
    operation:    str
    decision:     str
    severity:     str
    category:     str
    reason:       str


_cached_policies: list[PolicyRecord] = []
_last_refresh:    float = 0.0

_DB_QUERY = """
    SELECT id::text, path_pattern, operation, decision, severity,
           category, COALESCE(reason, '') AS reason
    FROM   filesystem_policies
    WHERE  active = TRUE
    ORDER  BY category, path_pattern
"""


def _redis_client() -> redis_lib.Redis:
    url = os.getenv("REDIS_URL", "redis://redis:6379/0")
    return redis_lib.Redis.from_url(url, decode_responses=True, socket_timeout=2)


def _pg_conn():
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "postgres"),
        port=int(os.getenv("POSTGRES_PORT", "5432")),
        dbname=os.getenv("POSTGRES_DB", "agentshield"),
        user=os.getenv("POSTGRES_USER", "agentshield"),
        password=os.getenv("POSTGRES_PASSWORD", "agentshield"),
        connect_timeout=5,
    )


def _load_policies_from_db() -> list[PolicyRecord]:
    try:
        conn = _pg_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute(_DB_QUERY)
                rows = cur.fetchall()
        finally:
            conn.close()
        entries: list[PolicyRecord] = [
            {"id": r["id"], "path_pattern": r["path_pattern"],
             "operation": r["operation"],  "decision": r["decision"],
             "severity":  r["severity"],   "category": r["category"],
             "reason":    r["reason"]}
            for r in rows
        ]
        try:
            _redis_client().setex(_REDIS_KEY, _CACHE_TTL, json.dumps(entries))
        except Exception as exc:
            logger.warning("filesystem_interceptor: redis write failed: %s", exc)
        logger.info("filesystem_interceptor: loaded %d policies from DB", len(entries))
        return entries
    except Exception as exc:
        logger.error("filesystem_interceptor: DB load failed: %s", exc)
        return []


def _get_db_policies() -> list[PolicyRecord]:
    """3-tier cache: in-process (5 min) → Redis → PostgreSQL. Never raises."""
    global _cached_policies, _last_refresh
    now = time.monotonic()
    if now - _last_refresh < _CACHE_TTL and _cached_policies:
        return _cached_policies
    try:
        raw = _redis_client().get(_REDIS_KEY)
        if raw:
            _cached_policies = json.loads(raw)
            _last_refresh = now
            return _cached_policies
    except Exception as exc:
        logger.warning("filesystem_interceptor: redis read failed: %s", exc)
    _cached_policies = _load_policies_from_db()
    _last_refresh = now
    return _cached_policies


def _normalize(path: str) -> str:
    return os.path.normpath(os.path.expanduser(path))


def evaluate_filesystem_request(path: str, operation: str = "READ") -> dict:
    """
    Evaluate a filesystem access request.
    Checks hardcoded baseline first (ordered, first-match wins), then DB policies.
    Returns {"decision": "ALLOWED"|"FLAGGED"|"BLOCKED", "reason": str, "severity": str}.
    Never raises.
    """
    try:
        norm   = _normalize(path)
        op_low = operation.lower()

        # 1. Hardcoded baseline — most-specific rules first
        for pattern, ops, decision, severity, reason in _BASELINE:
            if (op_low in ops or "all" in ops) and fnmatch.fnmatch(norm, pattern):
                return {"decision": decision, "reason": reason, "severity": severity}

        # 2. DB-backed policies — ordered by category/path_pattern
        for policy in _get_db_policies():
            pol_op = policy["operation"].lower()
            op_match = (pol_op == "all") or (pol_op == op_low)
            if op_match and fnmatch.fnmatch(norm, policy["path_pattern"]):
                return {
                    "decision": policy["decision"],
                    "reason":   policy["reason"] or f"policy:{policy['category']}",
                    "severity": policy["severity"],
                }

        return {"decision": "ALLOWED", "reason": "", "severity": "INFO"}

    except Exception as exc:
        logger.warning("filesystem_interceptor: unexpected error, failing open: %s", exc)
        return {"decision": "ALLOWED", "reason": "", "severity": "INFO"}
