"""
Backward-compatible wrapper — re-exports from llm_client.
New code should import from assessment.ai.llm_client directly.
"""
from assessment.ai.llm_client import (
    call_llm as _call_llm,
    InsufficientCreditsError,
    estimate_cost,
    extract_json,
    structural_truncate,
)
from assessment.config import MODEL_PRICING


def call_claude(
    model: str,
    system: str,
    user_content: str,
    max_tokens: int = 4096,
) -> tuple[str, dict]:
    """
    Thin wrapper kept for backward compatibility.
    Routes through call_llm which supports all providers.
    """
    return _call_llm(model, system, user_content, max_tokens=max_tokens)
