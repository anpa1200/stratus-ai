"""
Anthropic API client wrapper with retry logic and billing error fast-fail.
"""
import time
import logging
import json
import anthropic

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
) -> str:
    """Call Claude with retry logic. Returns the text response."""
    client = anthropic.Anthropic()

    for attempt in range(MAX_RETRIES):
        try:
            resp = client.messages.create(
                model=model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user_content}],
            )
            return resp.content[0].text

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
