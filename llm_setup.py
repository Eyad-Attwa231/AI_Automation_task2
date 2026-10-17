"""Point the OpenAI Agents SDK at a local Ollama server.

Usage in any file:
    from llm_setup import setup_llm, MODEL_NAME, SETTINGS
    setup_llm()
    agent = Agent(name="Triage", model=MODEL_NAME, model_settings=SETTINGS, ...)

Change the model without editing code (PowerShell):
    $env:OLLAMA_MODEL = "llama3.1:8b"
"""
import os

from agents import (ModelSettings, set_default_openai_api,
                    set_default_openai_client, set_tracing_disabled)
from openai import AsyncOpenAI

MODEL_NAME = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/v1")

# temperature 0 = most predictable output, best for tools and structured output
SETTINGS = ModelSettings(temperature=0)

_done = False


def setup_llm() -> None:
    """Safe to call many times."""
    global _done
    if _done:
        return
    client = AsyncOpenAI(base_url=OLLAMA_URL, api_key="ollama")  # key is ignored by Ollama
    set_default_openai_client(client)
    set_default_openai_api("chat_completions")
    # Default tracing uploads to OpenAI (needs a key). We use a local processor instead.
    set_tracing_disabled(True)
    _done = True
