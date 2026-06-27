"""Thin wrapper around the GapGPT (OpenAI-compatible) chat API.

Adds: lazy client creation, a simple on-disk response cache (to keep experiments
cheap and reproducible), bounded retries, and graceful degradation when the API
is unavailable.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import List, Optional

from .config import LLMConfig

_CACHE_DIR = Path(__file__).resolve().parent.parent / "results" / "cache"


class LLMClient:
    def __init__(self, cfg: LLMConfig) -> None:
        self.cfg = cfg
        self._client = None
        self.calls = 0
        self.cache_hits = 0
        self.total_latency_ms = 0.0
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # -- internal ------------------------------------------------------------ #
    def _get_client(self):
        if self._client is None:
            from openai import OpenAI

            self._client = OpenAI(
                base_url=self.cfg.base_url,
                api_key=self.cfg.api_key,
                timeout=self.cfg.request_timeout,
                max_retries=0,  # we handle retries ourselves
            )
        return self._client

    @staticmethod
    def _cache_key(model: str, system: str, user: str, temperature: float) -> str:
        blob = json.dumps([model, system, user, round(temperature, 3)], sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()[:24]

    def _cache_path(self, key: str) -> Path:
        return _CACHE_DIR / f"{key}.json"

    # -- public -------------------------------------------------------------- #
    def chat(
        self,
        model: str,
        system: str,
        user: str,
        temperature: float,
        max_tokens: int = 400,
        use_cache: bool = True,
    ) -> Optional[str]:
        """Return the assistant message text, or None on total failure."""
        key = self._cache_key(model, system, user, temperature)
        path = self._cache_path(key)
        if use_cache and path.exists():
            self.cache_hits += 1
            data = json.loads(path.read_text())
            self.total_latency_ms += data.get("latency_ms", 0.0)
            return data["content"]

        if not self.cfg.is_configured:
            return None

        last_err: Optional[Exception] = None
        for attempt in range(self.cfg.max_retries):
            try:
                start = time.perf_counter()
                resp = self._get_client().chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                latency_ms = (time.perf_counter() - start) * 1000.0
                content = (resp.choices[0].message.content or "").strip()
                self.calls += 1
                self.total_latency_ms += latency_ms
                if use_cache:
                    path.write_text(json.dumps({"content": content, "latency_ms": latency_ms}))
                return content
            except Exception as exc:  # noqa: BLE001 — bounded retry around any API error
                last_err = exc
                time.sleep(min(2.0 * (attempt + 1), 5.0))
        if last_err is not None:
            print(f"[LLMClient] API call failed after retries: {type(last_err).__name__}: {last_err}")
        return None
