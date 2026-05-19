from langchain_openai import ChatOpenAI
from langchain_groq import ChatGroq
from langgraph.prebuilt import create_react_agent

from app.config import settings


def get_llm(model: str):
    if model.startswith("groq/"):
        return ChatGroq(model=model[5:], api_key=settings.groq_api_key)
    return ChatOpenAI(
        model=model,
        base_url=f"{settings.ollama_base_url}/v1",
        api_key="ollama",
    )


def build_agent(tools: list, system_prompt: str, model: str):
    llm = get_llm(model)
    return create_react_agent(llm, tools, state_modifier=system_prompt)
