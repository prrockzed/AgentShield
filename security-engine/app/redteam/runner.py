"""
runner.py — Red-team suite executor.

Calls interceptor functions directly (no HTTP round-trip).
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from app.interceptors.prompt_interceptor     import evaluate_prompt
from app.interceptors.tool_interceptor       import evaluate_shell_command
from app.interceptors.output_interceptor     import evaluate_output
from app.interceptors.network_interceptor    import evaluate_network_request
from app.interceptors.filesystem_interceptor import evaluate_filesystem_request
from app.interceptors.browser_interceptor    import evaluate_browser_request
from app.interceptors.antivirus_interceptor  import scan_code
from app.hallucination.analyzer              import analyze_hallucination as _analyze_hallucination

from app.redteam.cases import CASES

logger = logging.getLogger(__name__)


@dataclass
class CaseResult:
    id:              str
    run_id:          str
    case_id:         str
    category:        str
    description:     str
    expected:        list[str]
    actual:          str
    passed:          bool
    actual_response: dict
    error:           str | None
    duration_ms:     float


@dataclass
class RunResult:
    id:          str
    started_at:  datetime
    finished_at: datetime
    total:       int
    passed:      int
    failed:      int
    pass_rate:   float
    results:     list[CaseResult] = field(default_factory=list)


def _run_case(case: dict, run_id: str) -> CaseResult:
    """Execute one test case and return a CaseResult."""
    category = case["category"]
    args     = case["args"]
    check    = case["check_field"]
    expected = case["expected"]
    error:   str | None = None
    response: dict[str, Any] = {}

    t0 = time.perf_counter()
    try:
        if category == "PROMPT":
            response = evaluate_prompt(**args)
        elif category == "TOOL":
            response = evaluate_shell_command(**args)
        elif category == "OUTPUT":
            response = evaluate_output(**args)
        elif category == "NETWORK":
            response = evaluate_network_request(**args)
        elif category == "FILESYSTEM":
            response = evaluate_filesystem_request(**args)
        elif category == "BROWSER":
            response = evaluate_browser_request(**args)
        elif category == "ANTIVIRUS":
            response = scan_code(**args)
        elif category == "HALLUCINATION":
            response = _analyze_hallucination(**args)
        else:
            error = f"unknown category: {category}"
    except Exception as exc:
        error = str(exc)
        logger.warning("redteam: case %s error: %s", case["id"], exc)

    duration_ms = (time.perf_counter() - t0) * 1000.0
    actual = response.get(check, "") if not error else ""
    passed = actual in expected

    return CaseResult(
        id=str(uuid.uuid4()),
        run_id=run_id,
        case_id=case["id"],
        category=category,
        description=case["description"],
        expected=expected,
        actual=actual,
        passed=passed,
        actual_response=response,
        error=error,
        duration_ms=round(duration_ms, 3),
    )


def run_all() -> RunResult:
    """Run all 26 test cases and return a RunResult."""
    run_id     = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc)

    results: list[CaseResult] = []
    for case in CASES:
        results.append(_run_case(case, run_id))

    finished_at = datetime.now(timezone.utc)
    passed  = sum(1 for r in results if r.passed)
    failed  = len(results) - passed
    total   = len(results)
    pass_rate = round(passed / total, 4) if total else 0.0

    return RunResult(
        id=run_id,
        started_at=started_at,
        finished_at=finished_at,
        total=total,
        passed=passed,
        failed=failed,
        pass_rate=pass_rate,
        results=results,
    )
