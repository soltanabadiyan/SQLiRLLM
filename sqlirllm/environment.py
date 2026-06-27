"""Ethical, in-process simulated targets and a signature-based WAF.

Nothing here touches the network. Each :class:`SimulatedTarget` is a pure
in-memory model of an intentionally vulnerable web application, used so the
framework can be evaluated reproducibly and *safely*. The "ground truth" of
which strategies are exploitable is stored on the target and used only for
scoring — the agent never reads it directly.
"""
from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set

from .config import DATABASES, FRAMEWORKS, STRATEGIES


class Outcome(str, Enum):
    VULNERABLE = "vulnerable"   # injection succeeded (true vulnerability)
    SAFE = "safe"               # endpoint not exploitable by this strategy
    BLOCKED = "blocked"         # stopped by the WAF


# --------------------------------------------------------------------------- #
# WAF                                                                          #
# --------------------------------------------------------------------------- #
# Classic static signatures, the kind a signature-based WAF / SQLMap-era tool
# would flag. A payload is blocked when it matches a signature *and* its evasion
# score is below the WAF's bypass threshold.
_SIGNATURES: List[re.Pattern] = [
    re.compile(r"'\s*or\s*'?1'?\s*=\s*'?1", re.I),
    re.compile(r"\bunion\s+select\b", re.I),
    re.compile(r"\bor\s+1\s*=\s*1\b", re.I),
    re.compile(r"\bsleep\s*\(", re.I),
    re.compile(r"\bwaitfor\s+delay\b", re.I),
    re.compile(r"\bbenchmark\s*\(", re.I),
    re.compile(r"--\s*$", re.I),
    re.compile(r"\bdrop\s+table\b", re.I),
    re.compile(r"\bxp_cmdshell\b", re.I),
]

# Evasion techniques that help a payload slip past signature matching.
_EVASION_TECHNIQUES: List[re.Pattern] = [
    re.compile(r"/\*.*?\*/"),                 # inline comments
    re.compile(r"%[0-9a-f]{2}", re.I),         # URL-encoding
    re.compile(r"\bchar\s*\(", re.I),          # CHAR() encoding
    re.compile(r"\bconcat\s*\(", re.I),        # CONCAT obfuscation
    re.compile(r"0x[0-9a-f]+", re.I),          # hex literals
    re.compile(r"\|\|"),                       # concat operator
    re.compile(r"[A-Z][a-z][A-Z]|[a-z][A-Z][a-z]"),  # mixed case keywords
    re.compile(r"%09|%0a|%0d|\t"),             # whitespace alternatives
    re.compile(r"\bunhex\s*\(", re.I),
    re.compile(r"\+"),                         # additive spacing
]

_INJECTION_INDICATORS: List[re.Pattern] = [
    re.compile(r"'|\""),
    re.compile(r"\b(select|union|or|and|sleep|waitfor|benchmark|insert|update)\b", re.I),
    re.compile(r"--|#|/\*"),
    re.compile(r";"),
]


def evasion_score(payload: str) -> float:
    """Fraction of known evasion techniques present in ``payload`` (0..1)."""
    if not payload:
        return 0.0
    hits = sum(1 for pat in _EVASION_TECHNIQUES if pat.search(payload))
    return min(1.0, hits / 4.0)  # 4+ techniques ⇒ fully obfuscated


def looks_like_injection(payload: str) -> bool:
    """Whether the string is a genuine SQLi attempt (not empty/benign text)."""
    if not payload or len(payload.strip()) < 2:
        return False
    return sum(1 for pat in _INJECTION_INDICATORS if pat.search(payload)) >= 2


@dataclass
class WAF:
    enabled: bool = True
    strictness: float = 0.6  # higher ⇒ harder to bypass; in [0, 1]

    def inspect(self, payload: str) -> bool:
        """Return True if the WAF blocks the payload."""
        if not self.enabled:
            return False
        signature_hit = any(pat.search(payload) for pat in _SIGNATURES)
        if not signature_hit:
            return False
        # Bypass succeeds when obfuscation outweighs the configured strictness.
        return evasion_score(payload) < self.strictness


# --------------------------------------------------------------------------- #
# Simulated responses                                                         #
# --------------------------------------------------------------------------- #
_DB_ERRORS: Dict[str, str] = {
    "mysql": "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
    "postgresql": 'ERROR: syntax error at or near "\'" at character 42 (PostgreSQL)',
    "oracle": "ORA-01756: quoted string not properly terminated",
    "mssql": "Unclosed quotation mark after the character string. Microsoft SQL Server, Incorrect syntax",
    "sqlite": "SQLITE_ERROR: near \"'\": syntax error",
}


@dataclass
class ExecutionResponse:
    """What the agent/analyzer is allowed to observe after executing a payload."""

    status_code: int
    body: str
    latency_ms: float
    outcome: Outcome  # included for logging; the analyzer must infer its own label


# --------------------------------------------------------------------------- #
# Target                                                                       #
# --------------------------------------------------------------------------- #
@dataclass
class SimulatedTarget:
    target_id: str
    framework: str
    database: str
    waf: WAF
    # Ground-truth set of strategies that actually work on this target.
    vulnerable_strategies: Set[str] = field(default_factory=set)
    base_latency_ms: float = 45.0
    _rng: random.Random = field(default_factory=lambda: random.Random(0), repr=False)

    # -- observable state (Section III State Space), WAF presence is observable.
    def observable_state(self, phase: str) -> Dict[str, str]:
        return {
            "framework": self.framework,
            "database": self.database,
            "waf": "present" if self.waf.enabled else "absent",
            "phase": phase,
        }

    def execute(self, strategy: str, payload: str) -> ExecutionResponse:
        """Execute a payload against the simulated target and return a response."""
        jitter = self._rng.uniform(-8, 12)

        # 1) WAF inspection.
        if self.waf.inspect(payload):
            return ExecutionResponse(
                status_code=403,
                body="Request blocked by Web Application Firewall (security policy 1010).",
                latency_ms=self.base_latency_ms + jitter,
                outcome=Outcome.BLOCKED,
            )

        # 2) A real injection must reach the database AND match a real flaw.
        is_injection = looks_like_injection(payload)
        exploitable = strategy in self.vulnerable_strategies and is_injection

        if not exploitable:
            return ExecutionResponse(
                status_code=200,
                body="<html><body>Welcome. 3 results found.</body></html>",
                latency_ms=self.base_latency_ms + jitter,
                outcome=Outcome.SAFE,
            )

        # 3) Strategy-specific successful-injection signal.
        return self._vulnerable_response(strategy, jitter)

    def _vulnerable_response(self, strategy: str, jitter: float) -> ExecutionResponse:
        db_err = _DB_ERRORS.get(self.database, _DB_ERRORS["mysql"])
        base = self.base_latency_ms + jitter
        if strategy == "error_based":
            return ExecutionResponse(500, f"<pre>{db_err}</pre>", base, Outcome.VULNERABLE)
        if strategy == "union_based":
            body = "<html><body>admin:5f4dcc3b5aa765d61d8327deb882cf99 | root:8.0.32</body></html>"
            return ExecutionResponse(200, body, base, Outcome.VULNERABLE)
        if strategy == "boolean_blind":
            body = "<html><body>Welcome back, administrator. 1 result found.</body></html>"
            return ExecutionResponse(200, body, base, Outcome.VULNERABLE)
        if strategy == "time_blind":
            # Successful time-based blind injection ⇒ large, deliberate delay.
            return ExecutionResponse(200, "<html><body>OK</body></html>", base + 5000.0, Outcome.VULNERABLE)
        if strategy == "stacked_queries":
            return ExecutionResponse(200, "Query OK, 1 row affected. Statement executed.", base, Outcome.VULNERABLE)
        if strategy == "second_order":
            body = "<html><body>Profile saved. Stored value executed on retrieval (id=1; admin).</body></html>"
            return ExecutionResponse(200, body, base, Outcome.VULNERABLE)
        return ExecutionResponse(200, "<html><body>OK</body></html>", base, Outcome.VULNERABLE)


# --------------------------------------------------------------------------- #
# Target factory                                                              #
# --------------------------------------------------------------------------- #
def build_target_suite(n: int = 24, seed: int = 42, waf_ratio: float = 0.6) -> List[SimulatedTarget]:
    """Construct a reproducible, diverse suite of simulated targets.

    Each target gets a random framework/database, a WAF (with probability
    ``waf_ratio``) and a random non-empty subset of exploitable strategies.
    """
    rng = random.Random(seed)
    targets: List[SimulatedTarget] = []
    for i in range(n):
        framework = rng.choice(FRAMEWORKS)
        database = rng.choice(DATABASES)
        waf_enabled = rng.random() < waf_ratio
        waf = WAF(enabled=waf_enabled, strictness=round(rng.uniform(0.45, 0.75), 2))
        k = rng.randint(1, 3)
        vulns = set(rng.sample(STRATEGIES, k))
        targets.append(
            SimulatedTarget(
                target_id=f"T{i:02d}",
                framework=framework,
                database=database,
                waf=waf,
                vulnerable_strategies=vulns,
                base_latency_ms=round(rng.uniform(30, 70), 1),
                _rng=random.Random(seed + i),
            )
        )
    return targets
