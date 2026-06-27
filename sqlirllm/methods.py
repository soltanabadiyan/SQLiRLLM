"""Full multi-method comparison harness for Section IV.

Defines a uniform :class:`ComparisonMethod` and instantiates the five methods
evaluated in the paper's results section. Together they form a controlled
ablation that isolates the contribution of each tier:

    M1  Static-Signature   (SQLMap-style)    : canonical payloads, fixed order, heuristic
    M2  Random-Select                          : random strategy order, canonical payloads
    M3  RL-only (Q-Learning)                   : learned order, canonical payloads (no LLM)
    M4  LLM-only (no RL)                       : fixed order, LLM payloads + LLM analysis
    M5  SQLiRLLM (proposed, full multi-tier)   : learned order + LLM payloads + LLM analysis + ethics

Comparing M1->M4 isolates the *semantic* (LLM) contribution; comparing
M2/M3->M5 isolates the *strategic planning* (RL) contribution; M5 alone carries
the embedded ethical safeguard.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .analyzer import AnalysisResult, Analyzer
from .baseline import canonical_payloads
from .config import PHASES, STRATEGIES, RewardWeights
from .environment import SimulatedTarget
from .ethics import EthicsGuard
from .metrics import MetricAccumulator
from .qlearning import QLearningAgent, State, encode_state
from .reward import ActionSignals, compute_reward

PayloadProvider = Callable[[str, Dict[str, str], int], str]
OrderFn = Callable[[State], List[str]]


def _next_phase(phase: str) -> str:
    idx = PHASES.index(phase)
    return PHASES[min(idx + 1, len(PHASES) - 1)]


@dataclass
class ComparisonMethod:
    """A single method under test with a uniform evaluation interface."""

    name: str
    short: str
    payload_provider: PayloadProvider
    analyzer: Analyzer
    order_fn: OrderFn
    uses_rl: bool
    uses_llm: bool
    has_ethics: bool
    weights: RewardWeights
    guard: Optional[EthicsGuard] = None
    max_attempts: int = 1

    # ------------------------------------------------------------------ #
    # Full-coverage evaluation -> confusion matrix and quality metrics.   #
    # ------------------------------------------------------------------ #
    def evaluate_coverage(self, targets: List[SimulatedTarget]) -> MetricAccumulator:
        m = MetricAccumulator(name=self.name)
        if self.guard is not None:
            self.guard.reset()
        for target in targets:
            phase = "initial"
            state = encode_state(target.observable_state(phase))
            for strategy in self.order_fn(state):
                # Ethical authorization (only methods with a guard enforce scope).
                m.total_actions += 1
                if self.guard is not None:
                    report = self.guard.authorize(target.target_id, strategy)
                    if not report.authorized:
                        m.ethical_violations += 1
                        continue

                ground_truth = strategy in target.vulnerable_strategies
                context = target.observable_state(phase)

                detected = False
                attempt_latencies: List[float] = []
                waf_seen = False
                waf_bypassed = False
                for attempt in range(self.max_attempts):
                    payload = self.payload_provider(strategy, context, attempt)
                    if target.waf.enabled:
                        waf_seen = True
                        if not target.waf.inspect(payload):
                            waf_bypassed = True
                    response = target.execute(strategy, payload)
                    attempt_latencies.append(response.latency_ms)
                    if self.analyzer.analyze(strategy, response).vulnerable:
                        detected = True
                        break

                if waf_seen:
                    m.waf_encounters += 1
                    if waf_bypassed:
                        m.waf_bypasses += 1
                m.latencies_ms.extend(attempt_latencies)

                detected_true = detected and ground_truth
                false_pos = detected and not ground_truth
                m.record_strategy(strategy, detected_true)

                if ground_truth and detected:
                    m.true_positive += 1
                elif ground_truth and not detected:
                    m.false_negative += 1
                elif not ground_truth and detected:
                    m.false_positive += 1
                else:
                    m.true_negative += 1

                signals = ActionSignals(detected_true, True, false_pos, sum(attempt_latencies))
                m.rewards.append(compute_reward(signals, self.weights))
        return m

    # ------------------------------------------------------------------ #
    # Budgeted evaluation -> detection efficiency (value of ordering).    #
    # ------------------------------------------------------------------ #
    def evaluate_budget(self, targets: List[SimulatedTarget], budget: int) -> float:
        detected = 0
        total = 0
        for target in targets:
            if not target.vulnerable_strategies:
                continue
            total += 1
            phase = "initial"
            state = encode_state(target.observable_state(phase))
            found = False
            for strategy in self.order_fn(state)[:budget]:
                if self.guard is not None and not self.guard.authorize(target.target_id, strategy).authorized:
                    continue
                context = target.observable_state(phase)
                for attempt in range(self.max_attempts):
                    payload = self.payload_provider(strategy, context, attempt)
                    response = target.execute(strategy, payload)
                    if self.analyzer.analyze(strategy, response).vulnerable and \
                            strategy in target.vulnerable_strategies:
                        found = True
                        break
                if found:
                    break
            detected += int(found)
        return detected / total if total else 0.0


# --------------------------------------------------------------------------- #
# Ordering strategies                                                         #
# --------------------------------------------------------------------------- #
def fixed_order(_state: State) -> List[str]:
    return list(STRATEGIES)


def make_random_order(seed: int = 42) -> OrderFn:
    rng = random.Random(seed)

    def _order(_state: State) -> List[str]:
        order = list(STRATEGIES)
        rng.shuffle(order)
        return order

    return _order


def make_policy_order(agent: QLearningAgent) -> OrderFn:
    def _order(state: State) -> List[str]:
        return agent.ranked_strategies(state)

    return _order


# --------------------------------------------------------------------------- #
# Payload providers                                                           #
# --------------------------------------------------------------------------- #
def canonical_provider(strategy: str, _context: Dict[str, str], attempt: int = 0) -> str:
    payloads = canonical_payloads(strategy)
    return payloads[attempt % len(payloads)]


# --------------------------------------------------------------------------- #
# Strategic-planner training (Tier 1)                                         #
# --------------------------------------------------------------------------- #
def train_policy(
    agent: QLearningAgent,
    targets: List[SimulatedTarget],
    payload_provider: PayloadProvider,
    analyzer: Analyzer,
    weights: RewardWeights,
    guard: Optional[EthicsGuard] = None,
    episodes: int = 300,
    max_steps: int = 12,
    seed: int = 42,
) -> List[float]:
    """Train the tabular Q-policy and return the per-episode reward history.

    The planner is trained in simulation with an effective (WAF-bypassing)
    payload provider so it can learn the underlying strategy<->vulnerability
    mapping; payload *quality* is then measured per method at evaluation time.
    """
    rng = random.Random(seed)
    history: List[float] = []
    for _ in range(episodes):
        target = rng.choice(targets)
        phase = "initial"
        ep_reward = 0.0
        for _step in range(max_steps):
            state = encode_state(target.observable_state(phase))
            strategy = agent.select(state, explore=True)

            if guard is not None:
                report = guard.authorize(target.target_id, strategy)
                if not report.authorized:
                    signals = ActionSignals(False, False, False, 0.0, ethical_violation=True)
                    reward = compute_reward(signals, weights)
                    agent.update(state, strategy, reward, state)
                    ep_reward += reward
                    continue

            context = target.observable_state(phase)
            payload = payload_provider(strategy, context, 0)
            response = target.execute(strategy, payload)
            result = analyzer.analyze(strategy, response)

            ground_truth = strategy in target.vulnerable_strategies
            detected_true = result.vulnerable and ground_truth
            false_pos = result.vulnerable and not ground_truth
            signals = ActionSignals(detected_true, True, false_pos, response.latency_ms)
            reward = compute_reward(signals, weights)
            ep_reward += reward

            next_phase = _next_phase(phase) if detected_true else phase
            next_state = encode_state(target.observable_state(next_phase))
            agent.update(state, strategy, reward, next_state)
            phase = next_phase
            if phase == "verification" and detected_true:
                break
        agent.decay_epsilon()
        history.append(ep_reward)
    return history
