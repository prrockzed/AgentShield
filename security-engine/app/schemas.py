from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel


class EventType(str, Enum):
    PROMPT_SCAN          = "PROMPT_SCAN"
    TOOL_INTERCEPT       = "TOOL_INTERCEPT"
    OUTPUT_SCAN          = "OUTPUT_SCAN"
    NETWORK_INTERCEPT    = "NETWORK_INTERCEPT"
    FILESYSTEM_INTERCEPT = "FILESYSTEM_INTERCEPT"
    BEHAVIORAL_ALERT     = "BEHAVIORAL_ALERT"


class Decision(str, Enum):
    ALLOWED  = "ALLOWED"
    BLOCKED  = "BLOCKED"
    FLAGGED  = "FLAGGED"
    REDACTED = "REDACTED"


class Severity(str, Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityEventCreate(BaseModel):
    run_id:               str | None = None
    event_type:           EventType
    source:               str
    payload:              dict[str, Any] | None = None
    decision:             Decision
    reason:               str | None = None
    severity:             Severity
    matched_signature_id: str | None = None


class SecurityEvent(SecurityEventCreate):
    id:        str
    timestamp: datetime
