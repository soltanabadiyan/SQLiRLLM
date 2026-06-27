"""Evaluation metrics for Section IV.

Accumulates the confusion-matrix counts needed to derive the paper's headline
metrics: Vulnerability Detection Rate (VDR), False Positive Rate (FPR), Ethical
Safeguard Rating (ESR), WAF-bypass rate, and mean time per test.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class MetricAccumulator:
    name: str = ""
    true_positive: int = 0   # vulnerable strategy correctly confirmed
    false_negative: int = 0  # vulnerable strategy missed
    false_positive: int = 0  # non-vulnerable flagged as vulnerable
    true_negative: int = 0   # non-vulnerable correctly cleared
    waf_encounters: int = 0
    waf_bypasses: int = 0
    ethical_violations: int = 0
    total_actions: int = 0
    latencies_ms: List[float] = field(default_factory=list)
    rewards: List[float] = field(default_factory=list)
    per_strategy_success: Dict[str, int] = field(default_factory=dict)
    per_strategy_attempts: Dict[str, int] = field(default_factory=dict)

    # -- derived metrics ----------------------------------------------------- #
    @property
    def vdr(self) -> float:
        denom = self.true_positive + self.false_negative
        return self.true_positive / denom if denom else 0.0

    @property
    def fpr(self) -> float:
        denom = self.false_positive + self.true_negative
        return self.false_positive / denom if denom else 0.0

    @property
    def precision(self) -> float:
        denom = self.true_positive + self.false_positive
        return self.true_positive / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.vdr
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def waf_bypass_rate(self) -> float:
        return self.waf_bypasses / self.waf_encounters if self.waf_encounters else 0.0

    @property
    def esr(self) -> float:
        if self.total_actions == 0:
            return 1.0
        return 1.0 - (self.ethical_violations / self.total_actions)

    @property
    def mean_latency_ms(self) -> float:
        return sum(self.latencies_ms) / len(self.latencies_ms) if self.latencies_ms else 0.0

    @property
    def mean_reward(self) -> float:
        return sum(self.rewards) / len(self.rewards) if self.rewards else 0.0

    def record_strategy(self, strategy: str, success: bool) -> None:
        self.per_strategy_attempts[strategy] = self.per_strategy_attempts.get(strategy, 0) + 1
        if success:
            self.per_strategy_success[strategy] = self.per_strategy_success.get(strategy, 0) + 1

    def summary(self) -> Dict[str, float]:
        return {
            "VDR": round(self.vdr, 4),
            "FPR": round(self.fpr, 4),
            "Precision": round(self.precision, 4),
            "F1": round(self.f1, 4),
            "ESR": round(self.esr, 4),
            "WAF_bypass_rate": round(self.waf_bypass_rate, 4),
            "mean_time_ms": round(self.mean_latency_ms, 1),
            "mean_reward": round(self.mean_reward, 4),
            "actions": self.total_actions,
        }
