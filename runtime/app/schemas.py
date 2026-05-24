from pydantic import BaseModel


class ExecuteRequest(BaseModel):
    agent_type: str
    model: str
    task: str


class ExecuteResponse(BaseModel):
    run_id: str
    agent_type: str
    model: str
    output: str
    steps: list[dict]
    status: str
    hallucination_score: float = 0.0


class AgentInfo(BaseModel):
    name: str
    description: str
    tools: list[str]


class ModelInfo(BaseModel):
    name: str
    provider: str
