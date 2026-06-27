"""End-to-end experiment runner for SQLiRLLM (generates Section IV evidence).

Produces, under ./results/:
  * convergence.csv / convergence.png       — Q-learning reward vs. episode
  * comparison.csv                          — SQLiRLLM vs. static baseline
  * comparison.png                          — grouped bar chart of key metrics
  * per_strategy.csv / per_strategy.png     — success per injection technique
  * budget.csv / budget.png                 — detection rate vs. request budget
  * ethics.csv                              — ethical-violation stress test
  * summary.json                            — everything, machine-readable

Run:  python -m experiments.run_experiments --episodes 200 --targets 24
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from sqlirllm.analyzer import Analyzer
from sqlirllm.baseline import StaticBaseline
from sqlirllm.config import CONFIG, STRATEGIES
from sqlirllm.environment import build_target_suite
from sqlirllm.framework import build_framework
from sqlirllm.llm_client import LLMClient

RESULTS = Path(__file__).resolve().parent.parent / "results"


def _moving_average(values: List[float], window: int = 10) -> np.ndarray:
    if len(values) < window:
        return np.array(values, dtype=float)
    kernel = np.ones(window) / window
    return np.convolve(values, kernel, mode="valid")


def run(episodes: int, n_targets: int, seed: int) -> Dict:
    RESULTS.mkdir(parents=True, exist_ok=True)
    print(f"[1/6] Building {n_targets} simulated targets (seed={seed}) ...")
    targets = build_target_suite(n=n_targets, seed=seed)
    authorized = [t.target_id for t in targets]

    cfg = CONFIG
    print(f"      LLM configured: {cfg.llm.is_configured} | "
          f"payload={cfg.llm.payload_model} | analysis={cfg.llm.analysis_model}")

    framework = build_framework(cfg, authorized_targets=authorized)

    # ---------------------------------------------------------------- #
    # 1) Training / convergence                                        #
    # ---------------------------------------------------------------- #
    print(f"[2/6] Training Q-learning policy for {episodes} episodes ...")
    history = framework.train(targets, episodes=episodes, seed=seed)
    smooth = _moving_average(history, window=max(5, episodes // 20))
    pd.DataFrame({"episode": range(len(history)), "reward": history}).to_csv(
        RESULTS / "convergence.csv", index=False)

    plt.figure(figsize=(7, 4))
    plt.plot(history, color="#9ec9ff", alpha=0.6, label="Episode reward")
    plt.plot(range(len(history) - len(smooth), len(history)), smooth,
             color="#1f6feb", linewidth=2, label="Moving average")
    plt.xlabel("Training episode")
    plt.ylabel("Cumulative reward")
    plt.title("SQLiRLLM — Q-learning convergence")
    plt.legend()
    plt.tight_layout()
    plt.savefig(RESULTS / "convergence.png", dpi=140)
    plt.close()

    # ---------------------------------------------------------------- #
    # 2) Coverage comparison vs. static baseline                       #
    # ---------------------------------------------------------------- #
    print("[3/6] Evaluating SQLiRLLM and the static baseline ...")
    framework.guard.reset()
    sqli_metrics = framework.evaluate(targets)

    baseline_client = LLMClient(cfg.llm)
    baseline_analyzer = Analyzer(baseline_client, cfg.llm)
    baseline = StaticBaseline(baseline_analyzer)
    base_metrics = baseline.run(targets)

    comparison = {"SQLiRLLM": sqli_metrics.summary(), "Static-Baseline": base_metrics.summary()}
    pd.DataFrame(comparison).T.to_csv(RESULTS / "comparison.csv")

    metric_keys = ["VDR", "FPR", "Precision", "F1", "WAF_bypass_rate", "ESR"]
    x = np.arange(len(metric_keys))
    width = 0.38
    plt.figure(figsize=(8, 4.5))
    plt.bar(x - width / 2, [sqli_metrics.summary()[k] for k in metric_keys], width,
            label="SQLiRLLM", color="#1f6feb")
    plt.bar(x + width / 2, [base_metrics.summary()[k] for k in metric_keys], width,
            label="Static baseline", color="#f0883e")
    plt.xticks(x, metric_keys)
    plt.ylim(0, 1.05)
    plt.ylabel("Score")
    plt.title("SQLiRLLM vs. static signature-based baseline")
    plt.legend()
    plt.tight_layout()
    plt.savefig(RESULTS / "comparison.png", dpi=140)
    plt.close()

    # ---------------------------------------------------------------- #
    # 3) Per-strategy success                                          #
    # ---------------------------------------------------------------- #
    print("[4/6] Computing per-strategy success rates ...")
    rows = []
    for s in STRATEGIES:
        sa = sqli_metrics.per_strategy_attempts.get(s, 0)
        ss = sqli_metrics.per_strategy_success.get(s, 0)
        ba = base_metrics.per_strategy_attempts.get(s, 0)
        bs = base_metrics.per_strategy_success.get(s, 0)
        rows.append({
            "strategy": s,
            "sqlirllm_rate": round(ss / sa, 3) if sa else 0.0,
            "baseline_rate": round(bs / ba, 3) if ba else 0.0,
        })
    per_strategy = pd.DataFrame(rows)
    per_strategy.to_csv(RESULTS / "per_strategy.csv", index=False)

    x = np.arange(len(STRATEGIES))
    plt.figure(figsize=(9, 4.5))
    plt.bar(x - width / 2, per_strategy["sqlirllm_rate"], width, label="SQLiRLLM", color="#1f6feb")
    plt.bar(x + width / 2, per_strategy["baseline_rate"], width, label="Static baseline", color="#f0883e")
    plt.xticks(x, [s.replace("_", "\n") for s in STRATEGIES], fontsize=8)
    plt.ylim(0, 1.05)
    plt.ylabel("Detection success rate")
    plt.title("Per-strategy detection success")
    plt.legend()
    plt.tight_layout()
    plt.savefig(RESULTS / "per_strategy.png", dpi=140)
    plt.close()

    # ---------------------------------------------------------------- #
    # 4) Budgeted efficiency (value of the learned policy)             #
    # ---------------------------------------------------------------- #
    print("[5/6] Measuring detection vs. request budget ...")
    budgets = list(range(1, len(STRATEGIES) + 1))
    budget_rates = [round(framework.evaluate_budgeted(targets, b), 3) for b in budgets]
    # Random-ordering reference: expected detection of a target with v of 6 vulns
    # within b random draws (no learning).
    random_ref = []
    vuln_counts = [len(t.vulnerable_strategies) for t in targets if t.vulnerable_strategies]
    for b in budgets:
        probs = [1 - np.prod([(6 - v - j) / (6 - j) for j in range(b)]) if v < 6 else 1.0
                 for v in vuln_counts]
        random_ref.append(round(float(np.mean(probs)), 3))
    pd.DataFrame({"budget": budgets, "sqlirllm": budget_rates, "random_order": random_ref}).to_csv(
        RESULTS / "budget.csv", index=False)

    plt.figure(figsize=(7, 4))
    plt.plot(budgets, budget_rates, "o-", color="#1f6feb", label="SQLiRLLM (learned policy)")
    plt.plot(budgets, random_ref, "s--", color="#8b949e", label="Random strategy order")
    plt.xlabel("Request budget (strategies tried per target)")
    plt.ylabel("Targets detected (fraction)")
    plt.ylim(0, 1.05)
    plt.title("Detection efficiency under a limited request budget")
    plt.legend()
    plt.tight_layout()
    plt.savefig(RESULTS / "budget.png", dpi=140)
    plt.close()

    # ---------------------------------------------------------------- #
    # 5) Ethics stress test                                            #
    # ---------------------------------------------------------------- #
    print("[6/6] Running ethical-constraint stress test ...")
    # Authorize only the first half of targets; the rest are out of scope.
    half = authorized[: len(authorized) // 2]
    restricted = build_framework(cfg, authorized_targets=half)
    restricted.agent.q = framework.agent.q  # reuse the learned policy
    restricted.guard.reset()
    restricted_metrics = restricted.evaluate(targets)
    ethics = {
        "authorized_targets": len(half),
        "total_targets": len(authorized),
        "actions": restricted_metrics.total_actions,
        "ethical_violations_caught": restricted_metrics.ethical_violations,
        "ESR": round(restricted_metrics.esr, 4),
    }
    pd.DataFrame([ethics]).to_csv(RESULTS / "ethics.csv", index=False)

    summary = {
        "config": {
            "episodes": episodes,
            "n_targets": n_targets,
            "seed": seed,
            "llm_configured": cfg.llm.is_configured,
            "payload_model": cfg.llm.payload_model,
            "analysis_model": cfg.llm.analysis_model,
            "reward_weights": vars(cfg.reward),
        },
        "comparison": comparison,
        "per_strategy": rows,
        "budget": {"budgets": budgets, "sqlirllm": budget_rates, "random": random_ref},
        "ethics": ethics,
        "llm_usage": {
            "payload_offline_fallbacks": framework.payload_gen.offline_used,
            "analyzer_llm_calls": framework.analyzer.llm_calls,
            "analyzer_heuristic_calls": framework.analyzer.heuristic_calls,
            "final_epsilon": round(framework.agent.epsilon, 4),
            "q_states_learned": len(framework.agent.q),
        },
    }
    (RESULTS / "summary.json").write_text(json.dumps(summary, indent=2))

    print("\n================ RESULTS ================")
    print(json.dumps(comparison, indent=2))
    print(f"Ethics stress test: {ethics}")
    print(f"Budget@1..6: {budget_rates}")
    print(f"Artifacts written to: {RESULTS}")
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Run SQLiRLLM experiments.")
    parser.add_argument("--episodes", type=int, default=200)
    parser.add_argument("--targets", type=int, default=24)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    run(args.episodes, args.targets, args.seed)


if __name__ == "__main__":
    main()
