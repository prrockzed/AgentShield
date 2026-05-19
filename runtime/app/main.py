import uuid

from fastapi import FastAPI, HTTPException

from app.agents import AGENT_REGISTRY
from app.agents.base import build_agent
from app.interceptors import intercept_input, intercept_output
from app.schemas import AgentInfo, ExecuteRequest, ExecuteResponse, ModelInfo
from app.tools import _run_id_ctx
import app.trace as trace

app = FastAPI(title="AgentShield Runtime")

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
        raise HTTPException(status_code=403, detail=input_result.reason or "Blocked by input interceptor")

    agent = build_agent(module.TOOLS, module.SYSTEM_PROMPT, request.model)

    token = _run_id_ctx.set(run_id)
    try:
        result = agent.invoke({"messages": [{"role": "user", "content": request.task}]})
    finally:
        _run_id_ctx.reset(token)

    messages = result.get("messages", [])
    output = messages[-1].content if messages else ""

    output_result = intercept_output(run_id, output)
    if output_result.decision != "ALLOWED":
        output = f"[Blocked] {output_result.reason}"

    return ExecuteResponse(
        run_id=run_id,
        agent_type=request.agent_type,
        model=request.model,
        output=output,
        steps=trace.get_steps(run_id),
        status="completed",
    )
