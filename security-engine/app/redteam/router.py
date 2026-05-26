"""
router.py — FastAPI router for red-team endpoints.

Routes:
  POST /redteam/run             — run all 26 cases
  GET  /redteam/results         — list past runs
  GET  /redteam/results/{id}    — get one run with all case results
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query

from app.redteam.runner import run_all
from app.redteam.store  import save_run, list_runs, get_run

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/redteam", tags=["redteam"])


@router.post("/run")
def trigger_run() -> dict[str, Any]:
    """Execute all red-team test cases, persist results, return summary."""
    result = run_all()
    try:
        save_run(result)
    except Exception as exc:
        logger.error("redteam: failed to save run %s: %s", result.id, exc)

    return {
        "id":         result.id,
        "started_at": result.started_at.isoformat(),
        "finished_at": result.finished_at.isoformat(),
        "total":      result.total,
        "passed":     result.passed,
        "failed":     result.failed,
        "pass_rate":  result.pass_rate,
    }


@router.get("/results")
def list_results(limit: int = Query(default=50, ge=1, le=200)) -> list[dict]:
    """Return the most recent red-team runs (no case details)."""
    return list_runs(limit=limit)


@router.get("/results/{run_id}")
def get_result(run_id: str) -> dict[str, Any]:
    """Return one run with all 26 case results."""
    run = get_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    return run
