"""Model client abstraction.

``ModelClient`` talks to ANY OpenAI-compatible endpoint (Ollama, vLLM, LM Studio,
llama.cpp server, ...). ``MockClient`` returns canned strings so every scan mode
runs fully offline in tests with no model and no network.
"""

from __future__ import annotations

import os
import time
from typing import Optional


class ModelClient:
    """Thin wrapper over an OpenAI-compatible chat-completions endpoint.

    The ``openai`` package is imported lazily inside :meth:`complete` so that
    merely importing this module never fails when openai is absent (e.g. in a
    minimal test environment using :class:`MockClient`).
    """

    def __init__(
        self,
        model: str,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        temperature: float = 0.1,
        timeout: float = 120.0,
        max_retries: int = 2,
    ) -> None:
        self.model = model
        self.base_url = base_url or os.environ.get("VULNHOUND_BASE_URL")
        # Many local servers ignore the key but the SDK requires a non-empty one.
        self.api_key = api_key or os.environ.get("VULNHOUND_API_KEY") or "not-needed"
        self.temperature = temperature
        self.timeout = timeout
        self.max_retries = max_retries
        self._client = None

    def _ensure_client(self):
        if self._client is None:
            from openai import OpenAI  # lazy import

            self._client = OpenAI(
                base_url=self.base_url,
                api_key=self.api_key,
                timeout=self.timeout,
            )
        return self._client

    def complete(self, system: str, user: str) -> str:
        """Return the assistant message text for a system+user prompt."""
        client = self._ensure_client()
        last_err: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                resp = client.chat.completions.create(
                    model=self.model,
                    temperature=self.temperature,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                )
                return resp.choices[0].message.content or ""
            except Exception as err:  # noqa: BLE001 - retry any transient failure
                last_err = err
                if attempt < self.max_retries:
                    time.sleep(2 ** attempt)
                else:
                    raise
        # Unreachable, but keeps type-checkers happy.
        raise last_err if last_err else RuntimeError("model call failed")


class MockClient(ModelClient):
    """Offline stand-in. Returns canned responses based on substring matching.

    ``responses`` maps a substring -> canned reply. The first key found as a
    substring of the ``user`` prompt wins; otherwise ``default`` is returned.
    Never imports openai and never touches the network.
    """

    def __init__(
        self,
        responses: Optional[dict] = None,
        default: str = "[]",
        **_ignored,
    ) -> None:
        self.responses = responses or {}
        self.default = default
        self.model = "mock"
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:  # type: ignore[override]
        self.calls.append((system, user))
        for needle, reply in self.responses.items():
            if needle and needle in user:
                return reply
        return self.default


def get_client(config) -> ModelClient:
    """Build the right client from a Config-like object.

    Returns a :class:`MockClient` when ``config.mock`` is truthy, otherwise a
    real :class:`ModelClient`. ``config`` may also carry ``mock_responses``.
    """
    if getattr(config, "mock", False):
        return MockClient(
            responses=getattr(config, "mock_responses", None),
            default=getattr(config, "mock_default", "[]"),
        )
    return ModelClient(
        model=getattr(config, "model", "") or "",
        base_url=getattr(config, "base_url", None),
        api_key=getattr(config, "api_key", None),
        temperature=getattr(config, "temperature", 0.1),
    )
