import logging
import os

import httpx

logger = logging.getLogger(__name__)

_GATEWAY_URL = os.getenv("GATEWAY_URL", "http://gateway:8080")
_ENDPOINT = f"{_GATEWAY_URL}/api/events"


def publish_event(event: dict) -> None:
    """POST a security event to the gateway. Best-effort — never raises."""
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.post(_ENDPOINT, json=event)
            if resp.status_code not in (200, 201):
                logger.warning("publish_event: status=%d body=%s", resp.status_code, resp.text[:200])
    except Exception as exc:
        logger.warning("publish_event: %s", exc)
