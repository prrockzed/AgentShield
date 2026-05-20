import os
from dataclasses import dataclass


@dataclass
class Settings:
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
    default_model: str = os.getenv("DEFAULT_MODEL", "ollama_chat/qwen3:4b")
    gateway_url: str = os.getenv("GATEWAY_URL", "http://gateway:8080")
    security_engine_url: str = os.getenv("SECURITY_ENGINE_URL", "http://security-engine:8001")


settings = Settings()

# LiteLLM reads OLLAMA_API_BASE, not OLLAMA_BASE_URL
os.environ.setdefault("OLLAMA_API_BASE", settings.ollama_base_url)
