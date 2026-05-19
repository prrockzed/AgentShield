from langchain_community.chat_models import ChatLiteLLM
from langgraph.prebuilt import create_react_agent

import app.config  # noqa: F401 — ensures OLLAMA_API_BASE is set


def get_llm(model: str):
    return ChatLiteLLM(model=model)


def build_agent(tools: list, system_prompt: str, model: str):
    return create_react_agent(get_llm(model), tools, state_modifier=system_prompt)
