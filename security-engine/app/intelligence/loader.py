"""
Threat signature loader: DB → Redis → in-process cache.
get_signatures() never raises — returns [] on any failure.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import TypedDict

import psycopg2
import psycopg2.extras
import redis as redis_lib

logger = logging.getLogger(__name__)

_REDIS_KEY = "agentshield:threat_signatures"
_CACHE_TTL = 300  # 5 minutes

_DB_QUERY = """
    SELECT id::text, category, pattern, pattern_type, severity,
           COALESCE(description, '') AS description
    FROM   threat_signatures
    WHERE  active = TRUE
    ORDER  BY category, severity DESC
"""


class SignatureRecord(TypedDict):
    id:           str
    category:     str
    pattern:      str
    pattern_type: str   # REGEX | SUBSTRING | SEMANTIC
    severity:     str
    description:  str


_cached: list[SignatureRecord] = []
_last_refresh: float = 0.0


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


def _load_from_db() -> list[SignatureRecord]:
    """Query DB, write to Redis. Returns [] on any failure."""
    try:
        conn = _pg_conn()
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
                cur.execute(_DB_QUERY)
                rows = cur.fetchall()
        finally:
            conn.close()

        sigs: list[SignatureRecord] = [
            {
                "id":           row["id"],
                "category":     row["category"],
                "pattern":      row["pattern"],
                "pattern_type": row["pattern_type"],
                "severity":     row["severity"],
                "description":  row["description"],
            }
            for row in rows
        ]

        try:
            _redis_client().setex(_REDIS_KEY, _CACHE_TTL, json.dumps(sigs))
        except Exception as exc:
            logger.warning("loader: redis write failed: %s", exc)

        logger.info("loader: loaded %d signatures from DB", len(sigs))
        return sigs

    except Exception as exc:
        logger.error("loader: DB load failed: %s", exc)
        return []


def get_signatures() -> list[SignatureRecord]:
    """
    Return active threat signatures.
    Cache hierarchy: in-process TTL (5 min) → Redis → PostgreSQL.
    Never raises.
    """
    global _cached, _last_refresh

    now = time.monotonic()
    if now - _last_refresh < _CACHE_TTL and _cached:
        return _cached

    try:
        raw = _redis_client().get(_REDIS_KEY)
        if raw:
            _cached = json.loads(raw)
            _last_refresh = now
            logger.debug("loader: %d signatures from Redis", len(_cached))
            return _cached
    except Exception as exc:
        logger.warning("loader: redis read failed: %s", exc)

    _cached = _load_from_db()
    _last_refresh = now
    return _cached


def prewarm() -> None:
    """Call at startup to pre-populate Redis and in-process cache."""
    global _cached, _last_refresh
    logger.info("loader: pre-warming signature cache")
    _cached = _load_from_db()
    _last_refresh = time.monotonic()
