"""Tier 3 — Multi-Tiered Analysis Layer (Qwen2.5-Coder-14B analog via GapGPT).

Interprets the response returned after executing a payload and classifies
whether a vulnerability was confirmed. To respect the "selective intelligence"
principle of Section III (a 14B model is expensive), the analyzer is invoked on
*responses* and falls back to a fast deterministic heuristic whenever the API is
unavailable or returns an unparizable answer.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Optional

from .config import LLMConfig
from .environment import ExecutionResponse
from .llm_client import LLMClient

_SYSTEM = (
    "You are a senior application-security analyst reviewing the HTTP response "
    "produced by a single SQL injection test against a sandboxed lab target. "
    "Decide whether the response confirms an exploitable SQL injection. "
    "Reply with a compact JSON object: "
    '{"vulnerable": true|false, "severity": "none|low|medium|high|critical", '
    '"signal": "<short reason>"}. Output JSON only.'
)

_USER_TEMPLATE = (
    "Technique tested: {strategy}\n"
    "HTTP status: {status}\n"
    "Approx response latency (ms): {latency}\n"
    "Response body (truncated):\n{body}\n\n"
    "A multi-second latency strongly suggests a successful time-based blind "
    "injection. Did this confirm a SQL injection vulnerability?"
)

# Deterministic detection signals for the offline heuristic.
_ERROR_SIGNS = re.compile(
    r"sql syntax|ORA-\d+|SQLITE_ERROR|unclosed quotation|syntax error|"
    r"updatexml|extractvalue|information_schema|rows affected|"
    r"5f4dcc3b5aa765d61d8327deb882cf99",
    re.I,
)
_BLOCK_SIGNS = re.compile(r"blocked by web application firewall|security policy", re.I)


@dataclass
class AnalysisResult:
    vulnerable: bool
    severity: str
    signal: str
    used_llm: bool


class Analyzer:
    def __init__(
        self,
        client: LLMClient,
        cfg: LLMConfig,
        llm_enabled: bool = True,
        use_cache: bool = True,
    ) -> None:
        self.client = client
        self.cfg = cfg
        self.llm_enabled = llm_enabled
        self.use_cache = use_cache
        self.llm_calls = 0
        self.heuristic_calls = 0

    def analyze(self, strategy: str, response: ExecutionResponse) -> AnalysisResult:
        # Non-LLM methods (or unavailable API) use the deterministic heuristic.
        if not self.llm_enabled:
            self.heuristic_calls += 1
            return self._heuristic(response)
        body = response.body[:600]
        # Bucket latency to a coarse value so semantically-identical responses
        # share a cache entry (raw jitter would otherwise defeat caching) while
        # preserving the time-based-blind signal (multi-second delays).
        latency_bucket = int(round(response.latency_ms / 100.0)) * 100
        user = _USER_TEMPLATE.format(
            strategy=strategy,
            status=response.status_code,
            latency=latency_bucket,
            body=body,
        )
        content = self.client.chat(
            model=self.cfg.analysis_model,
            system=_SYSTEM,
            user=user,
            temperature=self.cfg.analysis_temperature,
            max_tokens=160,
            use_cache=self.use_cache,
        )
        parsed = self._parse(content) if content else None
        if parsed is not None:
            self.llm_calls += 1
            parsed.used_llm = True
            return parsed
        # Fallback heuristic.
        self.heuristic_calls += 1
        return self._heuristic(response)

    @staticmethod
    def _parse(content: str) -> Optional[AnalysisResult]:
        match = re.search(r"\{.*\}", content, re.S)
        if not match:
            return None
        try:
            data = json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
        if "vulnerable" not in data:
            return None
        return AnalysisResult(
            vulnerable=bool(data.get("vulnerable")),
            severity=str(data.get("severity", "medium")),
            signal=str(data.get("signal", ""))[:160],
            used_llm=True,
        )

    def _heuristic(self, response: ExecutionResponse) -> AnalysisResult:
        if _BLOCK_SIGNS.search(response.body):
            return AnalysisResult(False, "none", "waf-blocked", False)
        if response.latency_ms >= 2000.0:
            return AnalysisResult(True, "high", "time-delay", False)
        if response.status_code >= 500 and _ERROR_SIGNS.search(response.body):
            return AnalysisResult(True, "high", "db-error", False)
        if _ERROR_SIGNS.search(response.body):
            return AnalysisResult(True, "high", "data/error-leak", False)
        return AnalysisResult(False, "none", "benign-response", False)
