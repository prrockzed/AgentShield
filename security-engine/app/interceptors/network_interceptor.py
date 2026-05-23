"""
Network request interceptor.
Enforces SSRF/private-IP protection, protocol allow-listing, and domain blocklist.
evaluate_network_request() never raises — fail-open on all exceptions.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import time
from urllib.parse import urlparse
from typing import TypedDict

import psycopg2
import psycopg2.extras
import redis as redis_lib

logger = logging.getLogger(__name__)

_ALLOWED_SCHEMES = {"http", "https"}

_PRIVATE_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),         # link-local / AWS IMDS
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::/128"),
]


def _is_private_ip(host: str) -> bool:
    """Resolve host to IPs and check all against private ranges. Fail-open."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            for net in _PRIVATE_NETWORKS:
                if ip in net:
                    return True
        return False
    except Exception as exc:
        logger.debug("network_interceptor: ip resolution failed for %s: %s", host, exc)
        return False


_REDIS_KEY = "agentshield:policy:network_blocklist"
_CACHE_TTL = 300  # 5 minutes


class BlocklistRecord(TypedDict):
    id:       str
    domain:   str
    category: str
    reason:   str


_cached_blocklist: list[BlocklistRecord] = []
_last_refresh: float = 0.0

_DB_QUERY = """
    SELECT id::text, domain, category, COALESCE(reason, '') AS reason
    FROM   network_policies
    WHERE  active = TRUE AND type = 'BLOCKLIST'
    ORDER  BY category, domain
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


def _load_blocklist_from_db() -> list[BlocklistRecord]:
    try:
        conn = _pg_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute(_DB_QUERY)
                rows = cur.fetchall()
        finally:
            conn.close()
        entries: list[BlocklistRecord] = [
            {"id": row["id"], "domain": row["domain"],
             "category": row["category"], "reason": row["reason"]}
            for row in rows
        ]
        try:
            _redis_client().setex(_REDIS_KEY, _CACHE_TTL, json.dumps(entries))
        except Exception as exc:
            logger.warning("network_interceptor: redis write failed: %s", exc)
        logger.info("network_interceptor: loaded %d blocklist entries from DB", len(entries))
        return entries
    except Exception as exc:
        logger.error("network_interceptor: DB load failed: %s", exc)
        return []


def _get_blocklist() -> list[BlocklistRecord]:
    """3-tier cache: in-process (5 min) → Redis → PostgreSQL. Never raises."""
    global _cached_blocklist, _last_refresh
    now = time.monotonic()
    if now - _last_refresh < _CACHE_TTL and _cached_blocklist:
        return _cached_blocklist
    try:
        raw = _redis_client().get(_REDIS_KEY)
        if raw:
            _cached_blocklist = json.loads(raw)
            _last_refresh = now
            return _cached_blocklist
    except Exception as exc:
        logger.warning("network_interceptor: redis read failed: %s", exc)
    _cached_blocklist = _load_blocklist_from_db()
    _last_refresh = now
    return _cached_blocklist


def _is_domain_blocked(host: str) -> tuple[bool, str, str]:
    """Exact + subdomain-suffix match. 'sub.evil.com' is blocked by 'evil.com'."""
    host_lower = host.lower().rstrip(".")
    for entry in _get_blocklist():
        blocked = entry["domain"].lower().rstrip(".")
        if host_lower == blocked or host_lower.endswith("." + blocked):
            return True, entry["reason"] or f"blocked domain ({entry['category']})", entry["category"]
    return False, "", ""


def evaluate_network_request(url: str, method: str = "GET") -> dict:
    """
    Evaluate a network request before execution.
    Checks in order: protocol → SSRF → domain blocklist.
    Returns {"decision": "ALLOWED"|"BLOCKED", "reason": str}.
    Never raises.
    """
    try:
        try:
            parsed = urlparse(url)
        except Exception:
            return {"decision": "BLOCKED", "reason": "invalid_url"}

        scheme = parsed.scheme.lower()
        host   = parsed.hostname or ""

        # 1. Protocol check
        if scheme not in _ALLOWED_SCHEMES:
            return {"decision": "BLOCKED", "reason": f"blocked_protocol:{scheme}"}

        if not host:
            return {"decision": "BLOCKED", "reason": "missing_host"}

        # 2. SSRF: literal IP fast-path (no DNS round-trip needed)
        try:
            ip = ipaddress.ip_address(host)
            for net in _PRIVATE_NETWORKS:
                if ip in net:
                    return {"decision": "BLOCKED", "reason": "ssrf_private_ip"}
        except ValueError:
            # Not a literal IP — resolve and check all returned addresses
            if _is_private_ip(host):
                return {"decision": "BLOCKED", "reason": "ssrf_private_ip"}

        # 3. Domain blocklist
        blocked, reason, _ = _is_domain_blocked(host)
        if blocked:
            return {"decision": "BLOCKED", "reason": reason}

        return {"decision": "ALLOWED", "reason": ""}

    except Exception as exc:
        logger.warning("network_interceptor: unexpected error, failing open: %s", exc)
        return {"decision": "ALLOWED", "reason": ""}
