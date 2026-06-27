"""Tier 1 — Strategic Planning Layer (tabular Q-Learning).

A transparent, low-overhead Q-table maps the observable target state to one of
the six SQLi strategies. Chosen over PPO/SAC for interpretability and minimal
compute, as argued in Section III ("Testing Strategies").
"""
from __future__ import annotations

import random
from collections import defaultdict
from typing import Dict, List, Tuple

from .config import STRATEGIES, QLearningParams


State = Tuple[str, str, str, str]  # (framework, database, waf, phase)


def encode_state(observable: Dict[str, str]) -> State:
    return (
        observable["framework"],
        observable["database"],
        observable["waf"],
        observable["phase"],
    )


class QLearningAgent:
    """Epsilon-greedy tabular Q-learning over the six-strategy action space."""

    def __init__(self, params: QLearningParams, seed: int = 42) -> None:
        self.params = params
        self.epsilon = params.epsilon_start
        self._rng = random.Random(seed)
        # Q[state][action] -> value
        self.q: Dict[State, Dict[str, float]] = defaultdict(
            lambda: {a: 0.0 for a in STRATEGIES}
        )
        self.updates = 0

    # -- action selection ---------------------------------------------------- #
    def select(self, state: State, explore: bool = True) -> str:
        if explore and self._rng.random() < self.epsilon:
            return self._rng.choice(STRATEGIES)
        return self._greedy(state)

    def _greedy(self, state: State) -> str:
        row = self.q[state]
        best = max(row.values())
        # Break ties randomly for robustness.
        candidates = [a for a, v in row.items() if v == best]
        return self._rng.choice(candidates)

    # -- learning ------------------------------------------------------------ #
    def update(self, state: State, action: str, reward: float, next_state: State) -> None:
        lr = self.params.learning_rate
        gamma = self.params.discount_factor
        best_next = max(self.q[next_state].values())
        old = self.q[state][action]
        self.q[state][action] = old + lr * (reward + gamma * best_next - old)
        self.updates += 1

    def decay_epsilon(self) -> None:
        self.epsilon = max(self.params.epsilon_min, self.epsilon * self.params.epsilon_decay)

    # -- introspection ------------------------------------------------------- #
    def policy_table(self) -> Dict[str, str]:
        """Human-readable best-action-per-state map (for auditing the Q-table)."""
        return {
            "|".join(state): self._greedy(state)
            for state in self.q
        }

    def ranked_strategies(self, state: State) -> List[str]:
        row = self.q[state]
        return sorted(row, key=row.get, reverse=True)
