"""
store.py — Persist and retrieve red-team run results via psycopg2.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

import psycopg2  # type: ignore
import psycopg2.extras  # type: ignore

from app.redteam.runner import RunResult

logger = logging.getLogger(__name__)

_DB_DSN = (
    f"host={os.getenv('POSTGRES_HOST', 'postgres')} "
    f"port={os.getenv('POSTGRES_PORT', '5432')} "
    f"dbname={os.getenv('POSTGRES_DB', 'agentshield')} "
    f"user={os.getenv('POSTGRES_USER', 'agentshield')} "
    f"password={os.getenv('POSTGRES_PASSWORD', 'agentshield')} "
    f"sslmode=disable"
)


def save_run(result: RunResult) -> None:
    """Persist a RunResult to redteam_runs + redteam_results."""
    conn = psycopg2.connect(_DB_DSN)
    try:
        with conn:
            cur = conn.cursor()

            cur.execute(
                """
                INSERT INTO redteam_runs (id, started_at, finished_at, total, passed, failed, pass_rate)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    result.id,
                    result.started_at,
                    result.finished_at,
                    result.total,
                    result.passed,
                    result.failed,
                    result.pass_rate,
                ),
            )

            for r in result.results:
                cur.execute(
                    """
                    INSERT INTO redteam_results
                        (id, run_id, case_id, category, description, expected,
                         actual, passed, actual_response, error, duration_ms)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        r.id,
                        r.run_id,
                        r.case_id,
                        r.category,
                        r.description,
                        r.expected,
                        r.actual,
                        r.passed,
                        json.dumps(r.actual_response),
                        r.error,
                        r.duration_ms,
                    ),
                )

            cur.close()
    finally:
        conn.close()


def list_runs(limit: int = 50) -> list[dict]:
    """Return the most recent *limit* redteam_runs rows."""
    conn = psycopg2.connect(_DB_DSN)
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            """
            SELECT id, started_at, finished_at, total, passed, failed, pass_rate, created_at
            FROM   redteam_runs
            ORDER  BY created_at DESC
            LIMIT  %s
            """,
            (limit,),
        )
        rows = cur.fetchall()
        cur.close()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_run(run_id: str) -> dict | None:
    """Return one run with all its case results, or None if not found."""
    conn = psycopg2.connect(_DB_DSN)
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        cur.execute(
            """
            SELECT id, started_at, finished_at, total, passed, failed, pass_rate, created_at
            FROM   redteam_runs
            WHERE  id = %s
            """,
            (run_id,),
        )
        run_row = cur.fetchone()
        if run_row is None:
            return None

        run = dict(run_row)

        cur.execute(
            """
            SELECT id, run_id, case_id, category, description, expected,
                   actual, passed, actual_response, error, duration_ms, created_at
            FROM   redteam_results
            WHERE  run_id = %s
            ORDER  BY created_at ASC
            """,
            (run_id,),
        )
        results = []
        for row in cur.fetchall():
            r = dict(row)
            # actual_response is JSONB — psycopg2 returns it already decoded
            results.append(r)

        run["results"] = results
        cur.close()
        return run
    finally:
        conn.close()
