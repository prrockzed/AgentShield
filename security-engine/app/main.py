from fastapi import FastAPI
from pydantic import BaseModel

from app.interceptors.tool_interceptor import evaluate_shell_command

app = FastAPI(title="AgentShield Security Engine")


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
