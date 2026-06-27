"""Ethical safeguard layer (Section III, "Embedded Ethical Constraints").

The guard enforces an explicit authorization scope. Any attempt to act on a
target outside the operator-approved allowlist is an *ethical violation*, which
the reward function punishes with a large negative reward (-100). This is what
makes the framework suitable for authorized Red-Team engagements rather than
indiscriminate scanning.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Set


@dataclass
class EthicsReport:
    authorized: bool
    reason: str = ""


@dataclass
class EthicsGuard:
    """Authorization-scope enforcement for the SQLiRLLM agent."""

    authorized_targets: Set[str] = field(default_factory=set)
    # Destructive strategies require explicit opt-in even when in scope.
    destructive_strategies: Set[str] = field(default_factory=lambda: {"stacked_queries"})
    allow_destructive: bool = True
    violations: List[str] = field(default_factory=list)
    checks: int = 0

    def authorize(self, target_id: str, strategy: str) -> EthicsReport:
        """Validate a single (target, strategy) action against the scope."""
        self.checks += 1
        if target_id not in self.authorized_targets:
            msg = f"target {target_id} is OUT OF SCOPE"
            self.violations.append(msg)
            return EthicsReport(False, msg)
        if strategy in self.destructive_strategies and not self.allow_destructive:
            msg = f"destructive strategy '{strategy}' not authorized for {target_id}"
            self.violations.append(msg)
            return EthicsReport(False, msg)
        return EthicsReport(True, "in scope")

    @property
    def safeguard_rating(self) -> float:
        """Ethical Safeguard Rating (ESR): fraction of actions that were compliant."""
        if self.checks == 0:
            return 1.0
        return 1.0 - (len(self.violations) / self.checks)

    def reset(self) -> None:
        self.violations.clear()
        self.checks = 0
