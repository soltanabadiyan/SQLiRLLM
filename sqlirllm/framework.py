"""SQLiRLLM orchestrator — integrates the three tiers, ethics, and reward.

Pipeline per action (Figure 1):
    state ──▶ Tier 1 (Q-learning) picks a strategy
          ──▶ Ethics guard authorizes the (target, strategy) action
          ──▶ Tier 2 (LLM) generates a context-aware payload
          ──▶ simulated execution (+ WAF)
          ──▶ Tier 3 (LLM) analyzes the response
          ──▶ reward updates the Q-table   (feedback loop)
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import List, Optional

from .analyzer import Analyzer
from .config import CONFIG, Config, PHASES, STRATEGIES
from .environment import SimulatedTarget
from .ethics import EthicsGuard
from .llm_client import LLMClient
from .metrics import MetricAccumulator
from .payload_generator import PayloadGenerator
from .qlearning import QLearningAgent, encode_state
from .reward import ActionSignals, compute_reward


def _next_phase(phase: str) -> str:
    idx = PHASES.index(phase)
    return PHASES[min(idx + 1, len(PHASES) - 1)]


@dataclass
class SQLiRLLM:
    agent: QLearningAgent
    payload_gen: PayloadGenerator
    analyzer: Analyzer
    guard: EthicsGuard
    config: Config

    # ------------------------------------------------------------------ #
    # Training — drives Q-table convergence (data for Section IV.B plot). #
    # ------------------------------------------------------------------ #
    def train(self, targets: List[SimulatedTarget], episodes: int = 200, seed: int = 42) -> List[float]:
        rng = random.Random(seed)
        weights = self.config.reward
        history: List[float] = []
        for ep in range(episodes):
            target = rng.choice(targets)
            phase = "initial"
            ep_reward = 0.0
            for _ in range(self.config.qlearning.max_steps_per_episode):
                state = encode_state(target.observable_state(phase))
                strategy = self.agent.select(state, explore=True)

                report = self.guard.authorize(target.target_id, strategy)
                if not report.authorized:
                    signals = ActionSignals(False, False, False, 0.0, ethical_violation=True)
                    reward = compute_reward(signals, weights)
                    self.agent.update(state, strategy, reward, state)
                    ep_reward += reward
                    continue

                context = target.observable_state(phase)
                payload = self.payload_gen.generate(strategy, context)
                response = target.execute(strategy, payload)
                result = self.analyzer.analyze(strategy, response)

                ground_truth = strategy in target.vulnerable_strategies
                detected_true = result.vulnerable and ground_truth
                false_pos = result.vulnerable and not ground_truth
                signals = ActionSignals(
                    detected_true_vuln=detected_true,
                    ethically_compliant=True,
                    false_positive=false_pos,
                    latency_ms=response.latency_ms,
                )
                reward = compute_reward(signals, weights)
                ep_reward += reward

                next_phase = _next_phase(phase) if detected_true else phase
                next_state = encode_state(target.observable_state(next_phase))
                self.agent.update(state, strategy, reward, next_state)

                phase = next_phase
                if phase == "verification" and detected_true:
                    break
            self.agent.decay_epsilon()
            history.append(ep_reward)
        return history

    # ------------------------------------------------------------------ #
    # Coverage evaluation — confusion matrix comparable to the baseline. #
    # ------------------------------------------------------------------ #
    def evaluate(self, targets: List[SimulatedTarget]) -> MetricAccumulator:
        m = MetricAccumulator(name="SQLiRLLM")
        weights = self.config.reward
        for target in targets:
            phase = "initial"
            for strategy in STRATEGIES:
                report = self.guard.authorize(target.target_id, strategy)
                m.total_actions += 1
                if not report.authorized:
                    # Ethical safeguard: a compliant agent refuses and records a violation.
                    m.ethical_violations += 1
                    continue

                ground_truth = strategy in target.vulnerable_strategies
                context = target.observable_state(phase)
                payload = self.payload_gen.generate(strategy, context)

                if target.waf.enabled:
                    m.waf_encounters += 1
                    if not target.waf.inspect(payload):
                        m.waf_bypasses += 1

                response = target.execute(strategy, payload)
                result = self.analyzer.analyze(strategy, response)
                m.latencies_ms.append(response.latency_ms)

                detected = result.vulnerable
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

                signals = ActionSignals(detected_true, True, false_pos, response.latency_ms)
                m.rewards.append(compute_reward(signals, weights))

                if detected_true:
                    phase = _next_phase(phase)
        return m

    # ------------------------------------------------------------------ #
    # Budgeted evaluation — shows the value of the learned policy.        #
    # ------------------------------------------------------------------ #
    def evaluate_budgeted(self, targets: List[SimulatedTarget], budget: int) -> float:
        """Detection rate when only ``budget`` strategies may be tried per target.

        Strategies are ordered by the learned Q-policy, so a good policy spends a
        small request budget on the strategies most likely to succeed.
        """
        detected_targets = 0
        total_with_vuln = 0
        for target in targets:
            if not target.vulnerable_strategies:
                continue
            total_with_vuln += 1
            phase = "initial"
            state = encode_state(target.observable_state(phase))
            ordered = self.agent.ranked_strategies(state)
            found = False
            for strategy in ordered[:budget]:
                if not self.guard.authorize(target.target_id, strategy).authorized:
                    continue
                context = target.observable_state(phase)
                payload = self.payload_gen.generate(strategy, context)
                response = target.execute(strategy, payload)
                if self.analyzer.analyze(strategy, response).vulnerable and \
                        strategy in target.vulnerable_strategies:
                    found = True
                    break
            detected_targets += int(found)
        return detected_targets / total_with_vuln if total_with_vuln else 0.0


# --------------------------------------------------------------------------- #
# Convenience builder                                                         #
# --------------------------------------------------------------------------- #
def build_framework(
    config: Config = CONFIG,
    authorized_targets: Optional[List[str]] = None,
    allow_destructive: bool = True,
) -> SQLiRLLM:
    client = LLMClient(config.llm)
    agent = QLearningAgent(config.qlearning, seed=config.seed)
    payload_gen = PayloadGenerator(client, config.llm, seed=config.seed)
    analyzer = Analyzer(client, config.llm)
    guard = EthicsGuard(
        authorized_targets=set(authorized_targets or []),
        allow_destructive=allow_destructive,
    )
    return SQLiRLLM(agent, payload_gen, analyzer, guard, config)
