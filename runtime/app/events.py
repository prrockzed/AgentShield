import asyncio
import json
import logging
import os
import threading

import nats

logger = logging.getLogger(__name__)

_NATS_URL     = os.getenv("NATS_URL", "nats://nats:4222")
_STREAM       = "SECURITY_EVENTS"
_SUBJECT_BASE = "agentshield.security.events"

_loop:   asyncio.AbstractEventLoop | None = None
_nc:     nats.aio.client.Client    | None = None
_js:                                  None = None
_ready = threading.Event()


async def _run_nats() -> None:
    """Long-lived coroutine: connect once, create stream, signal ready."""
    global _nc, _js
    _nc = await nats.connect(_NATS_URL)
    _js = _nc.jetstream()
    try:
        await _js.add_stream(
            name=_STREAM,
            subjects=[f"{_SUBJECT_BASE}.>"],
            retention="limits",
            max_age=86_400,  # 24 h in seconds
        )
    except Exception as exc:
        logger.warning("NATS add_stream: %s (may already exist)", exc)
    _ready.set()
    # Keep alive until the process exits
    while True:
        await asyncio.sleep(3600)


def _start_nats_thread() -> None:
    """Daemon thread: owns the NATS event loop."""
    global _loop
    _loop = asyncio.new_event_loop()
    asyncio.set_event_loop(_loop)
    try:
        _loop.run_until_complete(_run_nats())
    except Exception as exc:
        logger.error("NATS thread exited: %s", exc)


# Start the background thread when this module is first imported.
threading.Thread(target=_start_nats_thread, daemon=True, name="nats-publisher").start()
_ready.wait(timeout=10)  # wait up to 10s for connection


def publish_event(event: dict) -> None:
    """Publish a security event to NATS JetStream (non-blocking, best-effort)."""
    if _js is None or _loop is None:
        logger.warning("NATS not ready — dropping event")
        return
    event_type = event.get("event_type", "unknown")
    subject    = f"{_SUBJECT_BASE}.{event_type}"
    payload    = json.dumps(event).encode()
    future = asyncio.run_coroutine_threadsafe(
        _js.publish(subject, payload), _loop
    )
    try:
        future.result(timeout=5)
    except Exception as exc:
        logger.warning("NATS publish failed: %s", exc)
