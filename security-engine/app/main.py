import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

from app.intelligence.loader import prewarm
from app.interceptors.tool_interceptor import evaluate_shell_command
from app.interceptors.prompt_interceptor import evaluate_prompt
from app.interceptors.output_interceptor import evaluate_output
from app.behavioral.analyzer import analyze as behavioral_analyze


@asynccontextmanager
async def lifespan(app: FastAPI):
    prewarm()
    yield


app = FastAPI(title="AgentShield Security Engine", lifespan=lifespan)


class AnalyzeBehaviorRequest(BaseModel):
    run_id:    str
    tool_name: str
    command:   str | None = None


class AlertInfo(BaseModel):
    rule:     str
    severity: str
    verdict:  str
    message:  str


class AnalyzeBehaviorResponse(BaseModel):
    verdict:  str                    # OK | WARN | TERMINATE
    alerts:   list[AlertInfo] = []
    counters: dict            = {}


class InterceptToolRequest(BaseModel):
    run_id: str
    tool_name: str
    args: dict


class InterceptToolResponse(BaseModel):
    decision: str
    reason: str


@app.get("/health")
async def health():
    return {"status": "ok", "service": "security-engine"}


@app.post("/intercept/tool", response_model=InterceptToolResponse)
async def intercept_tool(request: InterceptToolRequest):
    if request.tool_name != "shell_exec":
        return InterceptToolResponse(decision="ALLOWED", reason="")
    command = request.args.get("command", "")
    result = evaluate_shell_command(command)
    return InterceptToolResponse(**result)


class InterceptPromptRequest(BaseModel):
    run_id: str
    content: str
    source: str  # USER_INPUT | TOOL_OUTPUT | FETCHED_CONTENT


class InterceptPromptResponse(BaseModel):
    decision: str
    reason: str
    score: float
    matched_signature_id: str | None = None   # Phase 10


@app.post("/intercept/prompt", response_model=InterceptPromptResponse)
async def intercept_prompt_endpoint(request: InterceptPromptRequest):
    result = evaluate_prompt(request.content, request.source)
    return InterceptPromptResponse(**result)


class InterceptOutputRequest(BaseModel):
    run_id: str
    content: str


class InterceptOutputResponse(BaseModel):
    decision: str
    redacted_content: str
    detections: list[dict]


@app.post("/intercept/output", response_model=InterceptOutputResponse)
async def intercept_output_endpoint(request: InterceptOutputRequest):
    result = evaluate_output(request.content)
    return InterceptOutputResponse(**result)


@app.post("/analyze/behavior", response_model=AnalyzeBehaviorResponse)
def analyze_behavior(req: AnalyzeBehaviorRequest):
    result = behavioral_analyze(req.run_id, req.tool_name, req.command)
    return result
