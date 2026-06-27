"""Multi-objective reward function (Section III, Reward Logic).

    R(s, a, s') = alpha*VDR(a) + beta*ESR(a) - gamma*FPR(a) - delta*Time(a)

with alpha=0.6, beta=0.3, gamma=0.1, delta=0.05, and a hard -100 penalty for any
ethical violation. Per-action signals are binary/normalised:

* VDR(a)  : 1 if the action detected a true vulnerability, else 0.
* ESR(a)  : 1 if the action was ethically compliant, else 0.
* FPR(a)  : 1 if the action raised a false positive, else 0.
* Time(a) : execution latency normalised into [0, 1].
"""
from __future__ import annotations

from dataclasses import dataclass

from .config import RewardWeights


@dataclass
class ActionSignals:
    detected_true_vuln: bool      # VDR component
    ethically_compliant: bool     # ESR component
    false_positive: bool          # FPR component
    latency_ms: float             # raw latency
    ethical_violation: bool = False  # triggers the -100 penalty

    def normalized_time(self, ceiling_ms: float = 6000.0) -> float:
        return max(0.0, min(1.0, self.latency_ms / ceiling_ms))


def compute_reward(signals: ActionSignals, weights: RewardWeights) -> float:
    """Return the scalar reward for one action."""
    if signals.ethical_violation:
        return weights.ethical_violation_penalty

    vdr = 1.0 if signals.detected_true_vuln else 0.0
    esr = 1.0 if signals.ethically_compliant else 0.0
    fpr = 1.0 if signals.false_positive else 0.0
    time_term = signals.normalized_time()

    return (
        weights.alpha * vdr
        + weights.beta * esr
        - weights.gamma * fpr
        - weights.delta * time_term
    )
