"""
Provider-agnostic LLM client — routes to Anthropic, OpenAI, or Google Gemini
based on the model name prefix. All providers return (text, usage_dict) in the
same format so the rest of the codebase is unaware of the underlying provider.

Model name routing:
  claude-*              → Anthropic  (requires ANTHROPIC_API_KEY)
  gpt-* / o1-* / o3-*  → OpenAI     (requires OPENAI_API_KEY)
  gemini-*              → Google     (requires GOOGLE_API_KEY or ADC)

Usage:
    from assessment.ai.llm_client import call_llm, estimate_cost, detect_provider
    text, usage = call_llm("gpt-4o-mini", system_prompt, user_prompt, max_tokens=2048)
"""
import time
import logging
import re
import json as _json
from typing import Optional

from assessment.config import MODEL_PRICING, SIMPLE_MODULES, MODULE_MAX_OUTPUT_TOKENS

logger = logging.getLogger(__name__)

MAX_RETRIES = 4
RETRY_DELAYS = [15, 30, 60, 120]


class InsufficientCreditsError(Exception):
    """Raised when any provider returns a billing/quota error — no point retrying."""
    pass


# ─── Provider detection ───────────────────────────────────────────────────────

def detect_provider(model: str) -> str:
    """Return 'anthropic', 'openai', or 'gemini' based on model name."""
    m = model.lower()
    if m.startswith("claude"):
        return "anthropic"
    if m.startswith(("gpt-", "o1-", "o3-", "o4-")):
        return "openai"
    if m.startswith("gemini"):
        return "gemini"
    raise ValueError(
        f"Cannot detect provider for model '{model}'. "
        "Model must start with 'claude-', 'gpt-', 'o1-', 'o3-', or 'gemini-'."
    )


def select_module_model(module_name: str, primary_model: str) -> str:
    """
    Return a cheaper model for low-signal modules to reduce cost.
    Only downgrades when the primary is an expensive model.
    """
    if module_name not in SIMPLE_MODULES:
        return primary_model

    provider = detect_provider(primary_model)
    # Map primary to cheaper equivalent within same provider family
    DOWNGRADE_MAP = {
        # Anthropic
        "claude-opus-4-6":            "claude-haiku-4-5-20251001",
        "claude-sonnet-4-6":          "claude-haiku-4-5-20251001",
        "claude-3-5-sonnet-20241022": "claude-3-haiku-20240307",
        # OpenAI
        "gpt-4o":                     "gpt-4o-mini",
        "gpt-4-turbo":                "gpt-4o-mini",
        "o1":                         "gpt-4o-mini",
        # Gemini
        "gemini-1.5-pro":             "gemini-1.5-flash",
        "gemini-2.0-flash-thinking":  "gemini-2.0-flash",
    }
    return DOWNGRADE_MAP.get(primary_model, primary_model)


# ─── JSON extraction helper ───────────────────────────────────────────────────

def extract_json(text: str) -> dict:
    """
    Parse JSON from LLM response robustly, handling:
    - Direct JSON response
    - JSON wrapped in markdown code fences (```json ... ```)
    - JSON preceded by reasoning text
    """
    text = text.strip()

    # Direct parse — most common case
    if text.startswith("{"):
        return _json.loads(text)

    # Markdown code fence: ```json { ... } ```
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        return _json.loads(match.group(1))

    # Find first { ... last } in any surrounding text
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        return _json.loads(text[start:end + 1])

    raise _json.JSONDecodeError("No JSON object found in response", text, 0)


# ─── Structural truncation ────────────────────────────────────────────────────

def structural_truncate(data: dict, max_chars: int) -> dict:
    """
    Remove whole objects from the largest list in data until the serialized
    size fits within max_chars. This prevents mid-JSON truncation which breaks
    the structure sent to the LLM.
    """
    import copy
    s = _json.dumps(data, default=str)
    if len(s) <= max_chars:
        return data

    data = copy.deepcopy(data)
    truncated_keys = []

    while True:
        s = _json.dumps(data, default=str)
        if len(s) <= max_chars:
            break
        # Find the list key with the largest serialized size
        list_keys = [k for k, v in data.items() if isinstance(v, list) and v]
        if not list_keys:
            break
        largest_key = max(list_keys, key=lambda k: len(_json.dumps(data[k], default=str)))
        data[largest_key].pop()
        if largest_key not in truncated_keys:
            truncated_keys.append(largest_key)

    if truncated_keys:
        data["_truncated"] = f"Items removed from: {', '.join(truncated_keys)} to fit token limit"

    return data


# ─── Main dispatch ────────────────────────────────────────────────────────────

def call_llm(
    model: str,
    system: str,
    user_content: str,
    max_tokens: Optional[int] = None,
    use_cache: bool = True,
) -> tuple[str, dict]:
    """
    Call the appropriate LLM provider for the given model.
    Returns (text_response, usage_dict) — usage_dict always has
    'input_tokens' and 'output_tokens' keys.
    """
    if max_tokens is None:
        max_tokens = MODULE_MAX_OUTPUT_TOKENS.get(model, 4096)

    provider = detect_provider(model)

    if provider == "anthropic":
        return _call_anthropic(model, system, user_content, max_tokens, use_cache)
    elif provider == "openai":
        return _call_openai(model, system, user_content, max_tokens)
    elif provider == "gemini":
        return _call_gemini(model, system, user_content, max_tokens)

    raise ValueError(f"Unknown provider for model: {model}")


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate USD cost. Falls back to Sonnet pricing for unknown models."""
    pricing = MODEL_PRICING.get(model)
    if not pricing:
        # Try prefix match for model families
        for key, p in MODEL_PRICING.items():
            if model.startswith(key.rsplit("-", 1)[0]):
                pricing = p
                break
    if not pricing:
        pricing = MODEL_PRICING["claude-sonnet-4-6"]
    cost = (input_tokens / 1_000_000 * pricing["input"] +
            output_tokens / 1_000_000 * pricing["output"])
    return round(cost, 6)


# ─── Anthropic provider ───────────────────────────────────────────────────────

_ANTHROPIC_FATAL = (
    "credit balance", "insufficient credits", "billing",
    "payment", "quota exceeded", "organization has been disabled",
)


def _call_anthropic(
    model: str, system: str, user_content: str,
    max_tokens: int, use_cache: bool,
) -> tuple[str, dict]:
    try:
        import anthropic as _anthropic
    except ImportError:
        raise ImportError("anthropic package not installed: pip install anthropic")

    client = _anthropic.Anthropic()

    # Prompt caching: mark system prompt as cacheable (saves ~90% on repeated calls)
    system_param = (
        [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]
        if use_cache else system
    )

    for attempt in range(MAX_RETRIES):
        try:
            resp = client.messages.create(
                model=model,
                max_tokens=max_tokens,
                system=system_param,
                messages=[{"role": "user", "content": user_content}],
            )
            usage = {
                "input_tokens": resp.usage.input_tokens,
                "output_tokens": resp.usage.output_tokens,
                # Cache read tokens cost 10% — track separately if available
                "cache_read_tokens": getattr(resp.usage, "cache_read_input_tokens", 0),
                "cache_write_tokens": getattr(resp.usage, "cache_creation_input_tokens", 0),
            }
            return resp.content[0].text, usage

        except _anthropic.AuthenticationError as e:
            raise RuntimeError(f"Anthropic auth failed: {e}") from e

        except _anthropic.BadRequestError as e:
            if any(p in str(e).lower() for p in _ANTHROPIC_FATAL):
                raise InsufficientCreditsError(
                    f"Anthropic billing error: {e}\n"
                    "Check https://console.anthropic.com/"
                ) from e
            raise

        except _anthropic.RateLimitError as e:
            if attempt >= MAX_RETRIES - 1:
                raise
            delay = RETRY_DELAYS[attempt]
            logger.warning(f"Anthropic rate limit (attempt {attempt+1}). Retry in {delay}s...")
            time.sleep(delay)

        except _anthropic.APIError as e:
            if any(p in str(e).lower() for p in _ANTHROPIC_FATAL):
                raise InsufficientCreditsError(f"Anthropic API billing error: {e}") from e
            if attempt >= MAX_RETRIES - 1:
                raise
            delay = RETRY_DELAYS[attempt]
            logger.warning(f"Anthropic API error (attempt {attempt+1}): {e}. Retry in {delay}s...")
            time.sleep(delay)

    raise RuntimeError("Anthropic: max retries exceeded")


# ─── OpenAI provider ──────────────────────────────────────────────────────────

_OPENAI_FATAL = (
    "insufficient_quota", "billing_hard_limit_reached",
    "account deactivated", "exceeded your current quota",
)


def _call_openai(
    model: str, system: str, user_content: str, max_tokens: int
) -> tuple[str, dict]:
    try:
        import openai as _openai
    except ImportError:
        raise ImportError(
            "openai package not installed: pip install openai\n"
            "Set OPENAI_API_KEY environment variable."
        )

    client = _openai.OpenAI()

    # o1/o3 models don't support system messages — merge into user content
    is_reasoning_model = model.startswith(("o1", "o3", "o4"))
    messages = (
        [{"role": "user", "content": f"{system}\n\n{user_content}"}]
        if is_reasoning_model
        else [
            {"role": "system", "content": system},
            {"role": "user", "content": user_content},
        ]
    )

    # o1/o3 use max_completion_tokens instead of max_tokens
    kwargs = {"model": model, "messages": messages}
    if is_reasoning_model:
        kwargs["max_completion_tokens"] = max_tokens
    else:
        kwargs["max_tokens"] = max_tokens

    for attempt in range(MAX_RETRIES):
        try:
            resp = client.chat.completions.create(**kwargs)
            usage = {
                "input_tokens": resp.usage.prompt_tokens,
                "output_tokens": resp.usage.completion_tokens,
                "cache_read_tokens": 0,
                "cache_write_tokens": 0,
            }
            return resp.choices[0].message.content, usage

        except _openai.AuthenticationError as e:
            raise RuntimeError(f"OpenAI auth failed. Set OPENAI_API_KEY. {e}") from e

        except _openai.RateLimitError as e:
            if any(p in str(e).lower() for p in _OPENAI_FATAL):
                raise InsufficientCreditsError(f"OpenAI quota error: {e}") from e
            if attempt >= MAX_RETRIES - 1:
                raise
            delay = RETRY_DELAYS[attempt]
            logger.warning(f"OpenAI rate limit (attempt {attempt+1}). Retry in {delay}s...")
            time.sleep(delay)

        except _openai.APIError as e:
            if attempt >= MAX_RETRIES - 1:
                raise
            delay = RETRY_DELAYS[attempt]
            logger.warning(f"OpenAI API error (attempt {attempt+1}): {e}. Retry in {delay}s...")
            time.sleep(delay)

    raise RuntimeError("OpenAI: max retries exceeded")


# ─── Google Gemini provider ───────────────────────────────────────────────────

_GEMINI_FATAL = (
    "quota exceeded", "resource_exhausted", "billing",
    "account suspended", "project billing",
)


def _call_gemini(
    model: str, system: str, user_content: str, max_tokens: int
) -> tuple[str, dict]:
    try:
        import google.generativeai as _genai
    except ImportError:
        raise ImportError(
            "google-generativeai package not installed: pip install google-generativeai\n"
            "Set GOOGLE_API_KEY environment variable."
        )

    import os
    api_key = os.environ.get("GOOGLE_API_KEY", "")
    if api_key:
        _genai.configure(api_key=api_key)

    generation_config = _genai.types.GenerationConfig(
        max_output_tokens=max_tokens,
        temperature=0.1,
    )

    gemini_model = _genai.GenerativeModel(
        model_name=model,
        system_instruction=system,
        generation_config=generation_config,
    )

    for attempt in range(MAX_RETRIES):
        try:
            resp = gemini_model.generate_content(user_content)
            usage_meta = resp.usage_metadata
            usage = {
                "input_tokens": getattr(usage_meta, "prompt_token_count", 0),
                "output_tokens": getattr(usage_meta, "candidates_token_count", 0),
                "cache_read_tokens": 0,
                "cache_write_tokens": 0,
            }
            text = resp.text
            return text, usage

        except Exception as e:
            err_str = str(e).lower()
            if any(p in err_str for p in _GEMINI_FATAL):
                raise InsufficientCreditsError(f"Gemini quota/billing error: {e}") from e
            if "invalid_argument" in err_str or "api_key" in err_str:
                raise RuntimeError(f"Gemini auth/config error. Set GOOGLE_API_KEY. {e}") from e
            if attempt >= MAX_RETRIES - 1:
                raise
            delay = RETRY_DELAYS[attempt]
            logger.warning(f"Gemini error (attempt {attempt+1}): {e}. Retry in {delay}s...")
            time.sleep(delay)

    raise RuntimeError("Gemini: max retries exceeded")
