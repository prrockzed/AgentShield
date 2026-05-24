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
from app.interceptors.network_interceptor import evaluate_network_request
from app.interceptors.filesystem_interceptor import evaluate_filesystem_request
from app.hallucination.analyzer import analyze_hallucination as _analyze_hallucination
from app.interceptors.browser_interceptor import evaluate_browser_request
from app.interceptors.antivirus_interceptor import scan_code


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


class InterceptNetworkRequest(BaseModel):
    run_id: str
    url:    str
    method: str = "GET"


class InterceptNetworkResponse(BaseModel):
    decision: str
    reason:   str


@app.post("/intercept/network", response_model=InterceptNetworkResponse)
async def intercept_network_endpoint(request: InterceptNetworkRequest):
    result = evaluate_network_request(request.url, request.method)
    return InterceptNetworkResponse(**result)


class InterceptFilesystemRequest(BaseModel):
    run_id:    str
    path:      str
    operation: str = "READ"


class InterceptFilesystemResponse(BaseModel):
    decision: str
    reason:   str
    severity: str


@app.post("/intercept/filesystem", response_model=InterceptFilesystemResponse)
async def intercept_filesystem_endpoint(request: InterceptFilesystemRequest):
    result = evaluate_filesystem_request(request.path, request.operation)
    return InterceptFilesystemResponse(**result)


class AnalyzeHallucinationRequest(BaseModel):
    run_id:       str
    output:       str
    tool_results: list[dict] = []


class AnalyzeHallucinationResponse(BaseModel):
    score:  float
    status: str
    flags:  list[dict] = []


@app.post("/analyze/hallucination", response_model=AnalyzeHallucinationResponse)
async def analyze_hallucination_endpoint(request: AnalyzeHallucinationRequest):
    result = _analyze_hallucination(request.output, request.tool_results)
    return AnalyzeHallucinationResponse(**result)


class InterceptBrowserRequest(BaseModel):
    run_id:       str
    url:          str
    html_content: str


class InterceptBrowserResponse(BaseModel):
    decision: str
    reason:   str
    severity: str
    findings: list[dict] = []
    score:    float = 0.0


@app.post("/intercept/browser", response_model=InterceptBrowserResponse)
async def intercept_browser_endpoint(request: InterceptBrowserRequest):
    result = evaluate_browser_request(request.url, request.html_content)
    return InterceptBrowserResponse(**result)


class ScanCodeRequest(BaseModel):
    run_id:       str
    content:      str
    content_type: str = "SHELL_SCRIPT"   # SHELL_SCRIPT | PYTHON | JAVASCRIPT | BINARY_B64


class ScanCodeResponse(BaseModel):
    decision:  str
    reason:    str
    severity:  str
    matches:   list[dict] = []
    rule_name: str | None = None


@app.post("/scan/code", response_model=ScanCodeResponse)
async def scan_code_endpoint(request: ScanCodeRequest):
    result = scan_code(request.content, request.content_type)
    return ScanCodeResponse(**result)
