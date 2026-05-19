import os
from dataclasses import dataclass


@dataclass
class Settings:
    ollama_base_url: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    default_model: str = os.getenv("DEFAULT_MODEL", "llama3")
    groq_api_key: str = os.getenv("GROQ_API_KEY", "")


settings = Settings()
