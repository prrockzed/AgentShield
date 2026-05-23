import logging
import os
import uuid

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from app.agents import AGENT_REGISTRY
from app.agents.base import build_agent
from app.interceptors import intercept_input, intercept_output
from app.interceptors.stubs import is_terminated, cleanup_run
from app.schemas import AgentInfo, ExecuteRequest, ExecuteResponse, ModelInfo
from app.tools import _run_id_ctx, _sandbox_id_ctx
import app.trace as trace

logger = logging.getLogger(__name__)

app = FastAPI(title="AgentShield Runtime")

_SM_URL = os.getenv("SANDBOX_MANAGER_URL", "http://sandbox-manager:8002")

_MODELS = [
    # ollama (local) — pull model first: ollama pull <name>
    ModelInfo(name="ollama_chat/qwen3:4b", provider="ollama"),
    ModelInfo(name="ollama_chat/llama3", provider="ollama"),
    ModelInfo(name="ollama_chat/llama3.1", provider="ollama"),
    ModelInfo(name="ollama_chat/mistral", provider="ollama"),
    ModelInfo(name="ollama_chat/tinyllama", provider="ollama"),
    # groq (free tier) — set GROQ_API_KEY
    ModelInfo(name="groq/llama-3.3-70b-versatile", provider="groq"),
    ModelInfo(name="groq/llama-3.1-8b-instant", provider="groq"),
    ModelInfo(name="groq/mixtral-8x7b-32768", provider="groq"),
    # gemini (free tier) — set GEMINI_API_KEY
    ModelInfo(name="gemini/gemini-1.5-flash", provider="gemini"),
    ModelInfo(name="gemini/gemini-2.0-flash", provider="gemini"),
    # mistral (free tier) — set MISTRAL_API_KEY
    ModelInfo(name="mistral/mistral-small-latest", provider="mistral"),
    # openai (paid) — set OPENAI_API_KEY
    ModelInfo(name="openai/gpt-4o-mini", provider="openai"),
    ModelInfo(name="openai/gpt-4o", provider="openai"),
    # anthropic (paid) — set ANTHROPIC_API_KEY
    ModelInfo(name="anthropic/claude-3-5-haiku-20241022", provider="anthropic"),
    ModelInfo(name="anthropic/claude-3-5-sonnet-20241022", provider="anthropic"),
]


def _create_sandbox() -> str:
    try:
        with httpx.Client(timeout=30.0) as c:
            resp = c.post(f"{_SM_URL}/sandbox/create")
            return resp.json().get("sandbox_id", "")
    except Exception as exc:
        logger.warning("sandbox create failed (fail-open): %s", exc)
        return ""


def _destroy_sandbox(sandbox_id: str) -> None:
    try:
        with httpx.Client(timeout=10.0) as c:
            c.delete(f"{_SM_URL}/sandbox/{sandbox_id}")
    except Exception as exc:
        logger.warning("sandbox destroy failed: %s", exc)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "runtime"}


@app.get("/agents", response_model=list[AgentInfo])
async def list_agents():
    result = []
    for name, module in AGENT_REGISTRY.items():
        result.append(
            AgentInfo(
                name=name,
                description=getattr(module, "DESCRIPTION", ""),
                tools=[t.name for t in module.TOOLS],
            )
        )
    return result


@app.get("/models", response_model=list[ModelInfo])
async def list_models():
    return _MODELS


@app.post("/execute", response_model=ExecuteResponse)
async def execute(request: ExecuteRequest):
    if request.agent_type not in AGENT_REGISTRY:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown agent_type: {request.agent_type}",
        )

    run_id = str(uuid.uuid4())
    module = AGENT_REGISTRY[request.agent_type]

    input_result = intercept_input(run_id, request.agent_type, request.task)
    if input_result.decision != "ALLOWED":
        return JSONResponse(
            status_code=403,
            content={"detail": input_result.reason or "Blocked by input interceptor", "run_id": run_id},
        )

    agent = build_agent(module.TOOLS, module.SYSTEM_PROMPT, request.model)

    sandbox_id = _create_sandbox()

    run_token = _run_id_ctx.set(run_id)
    sbx_token = _sandbox_id_ctx.set(sandbox_id)
    agent_error: str | None = None
    try:
        result = agent.invoke({"messages": [{"role": "user", "content": request.task}]})
    except Exception as exc:
        logger.error("agent.invoke failed for run %s: %s", run_id, exc)
        agent_error = str(exc)
        result = {}
    finally:
        _run_id_ctx.reset(run_token)
        _sandbox_id_ctx.reset(sbx_token)
        if sandbox_id:
            _destroy_sandbox(sandbox_id)

    if agent_error:
        cleanup_run(run_id)
        return ExecuteResponse(
            run_id=run_id,
            agent_type=request.agent_type,
            model=request.model,
            output=f"[Agent error] {agent_error}",
            steps=[],
            status="failed",
        )

    messages = result.get("messages", [])
    output = messages[-1].content if messages else ""

    output_result = intercept_output(run_id, output)
    if output_result.decision == "REDACTED":
        output = output_result.redacted_content
    elif output_result.decision == "BLOCKED":
        output = f"[Blocked] {output_result.reason}"

    status = "terminated" if is_terminated(run_id) else "completed"
    cleanup_run(run_id)

    return ExecuteResponse(
        run_id=run_id,
        agent_type=request.agent_type,
        model=request.model,
        output=output,
        steps=trace.get_steps(run_id),
        status=status,
    )
