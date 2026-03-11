"""
Anthropic API client wrapper with retry logic, billing error fast-fail, and token tracking.
Returns (text, usage_dict) so callers can track token costs.
"""
import time
import logging
import json
import anthropic

from assessment.config import MODEL_PRICING

logger = logging.getLogger(__name__)

MAX_RETRIES = 4
RETRY_DELAYS = [15, 30, 60, 120]

_FATAL_PHRASES = (
    "credit balance",
    "insufficient credits",
    "billing",
    "payment",
    "quota exceeded",
    "organization has been disabled",
)


class InsufficientCreditsError(Exception):
    """Raised when Anthropic returns a billing/credit error — no point retrying."""
    pass


def _is_fatal_api_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    return any(phrase in msg for phrase in _FATAL_PHRASES)


def call_claude(
    model: str,
    system: str,
    user_content: str,
    max_tokens: int = 8192,
) -> tuple[str, dict]:
    """
    Call Claude with retry logic.
    Returns (text_response, usage_dict) where usage_dict has input_tokens and output_tokens.
    """
    client = anthropic.Anthropic()

    for attempt in range(MAX_RETRIES):
        try:
            resp = client.messages.create(
                model=model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user_content}],
            )
            usage = {
                "input_tokens": resp.usage.input_tokens,
                "output_tokens": resp.usage.output_tokens,
            }
            return resp.content[0].text, usage

        except anthropic.AuthenticationError as e:
            raise RuntimeError(f"Authentication failed: {e}") from e

        except anthropic.BadRequestError as e:
            if _is_fatal_api_error(e):
                raise InsufficientCreditsError(
                    f"Anthropic API billing error: {e}\n"
                    "Check your credit balance at https://console.anthropic.com/"
                ) from e
            raise

        except anthropic.RateLimitError as e:
            if attempt >= MAX_RETRIES - 1:
                raise
            delay = RETRY_DELAYS[attempt]
            logger.warning(f"Rate limited (attempt {attempt + 1}/{MAX_RETRIES}). Retrying in {delay}s...")
            time.sleep(delay)

        except anthropic.APIError as e:
            if _is_fatal_api_error(e):
                raise InsufficientCreditsError(
                    f"Anthropic API billing error: {e}\n"
                    "Check your credit balance at https://console.anthropic.com/"
                ) from e
            if attempt >= MAX_RETRIES - 1:
                raise
            delay = RETRY_DELAYS[attempt]
            logger.warning(f"API error (attempt {attempt + 1}/{MAX_RETRIES}): {e}. Retrying in {delay}s...")
            time.sleep(delay)

        except json.JSONDecodeError as e:
            if attempt >= MAX_RETRIES - 1:
                raise
            delay = RETRY_DELAYS[attempt]
            logger.warning(f"JSON decode error (attempt {attempt + 1}/{MAX_RETRIES}). Retrying in {delay}s...")
            time.sleep(delay)

    raise RuntimeError("Max retries exceeded")


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate USD cost for a Claude API call based on token counts."""
    pricing = MODEL_PRICING.get(model, MODEL_PRICING["claude-sonnet-4-6"])
    cost = (input_tokens / 1_000_000 * pricing["input"] +
            output_tokens / 1_000_000 * pricing["output"])
    return round(cost, 6)
