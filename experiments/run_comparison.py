"""Comprehensive multi-method evaluation for SQLiRLLM (Section IV).

Runs a controlled ablation/comparison of five methods on a shared suite of
sandboxed targets and writes all academic artifacts to ./results/.

Important: this runner is simulation-only (no real network pentesting). For
live Docker targets, use:
    python -m experiments.live.sqlirllm_runner
    python -m experiments.live.sqlmap_runner
    python -m experiments.live.compare

  comparison_quality.csv      detection-quality table (all methods)
  comparison_quality.png      grouped bar chart of VDR/FPR/F1/WAF/ESR
  table1_empirical.csv        paper-style Table-I with measured numbers + literature
  convergence.csv / .png      Q-learning training reward curve
  budget.csv / .png           detection rate vs. request budget (ordered methods)
  per_strategy.csv / .png      per-technique detection success
  ethics.csv                  out-of-scope authorization stress test
  summary.json                everything, machine-readable

Usage:  python -m experiments.run_comparison --episodes 300 --targets 24
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
from sqlirllm.config import CONFIG, STRATEGIES
from sqlirllm.environment import build_target_suite
from sqlirllm.ethics import EthicsGuard
from sqlirllm.llm_client import LLMClient
from sqlirllm.metrics import MetricAccumulator
from sqlirllm.methods import (
    ComparisonMethod,
    canonical_provider,
    fixed_order,
    make_policy_order,
    make_random_order,
    train_policy,
)
from sqlirllm.payload_generator import PayloadGenerator
from sqlirllm.qlearning import QLearningAgent

RESULTS = Path(__file__).resolve().parent.parent / "results"

# Literature-reported figures (from the paper's Related Work / Table I), shown
# alongside our measured numbers and clearly labelled as reported, not measured.
LITERATURE = {
    "SQLMap [13]":   {"RL": "No",  "LM": "No",  "Ethical": "Partial", "evasion_reported": None},
    "SSQLi [3]":     {"RL": "SAC", "LM": "No",  "Ethical": "No",      "evasion_reported": 0.9739},
    "XPLOITSQL [4]": {"RL": "AC",  "LM": "T5",  "Ethical": "No",      "evasion_reported": None},
}


def _moving_average(values: List[float], window: int) -> np.ndarray:
    if len(values) < window or window < 2:
        return np.array(values, dtype=float)
    return np.convolve(values, np.ones(window) / window, mode="valid")


def _norm01(values: np.ndarray) -> np.ndarray:
    """Min-max normalize a vector to [0, 1] (constant -> zeros)."""
    if values.size == 0:
        return values
    lo, hi = float(values.min()), float(values.max())
    if np.isclose(lo, hi):
        return np.zeros_like(values, dtype=float)
    return (values - lo) / (hi - lo)


def build_methods(cfg, agent: QLearningAgent, seed: int):
    """Instantiate the five comparison methods sharing one trained policy."""
    client = LLMClient(cfg.llm)

    # Analyzers: heuristic-only for non-LLM methods, LLM-backed for LLM methods.
    heur_analyzer = Analyzer(client, cfg.llm, llm_enabled=False)
    llm_analyzer = Analyzer(client, cfg.llm, llm_enabled=True)

    # Tier-2 LLM payload synthesiser.
    payload_gen = PayloadGenerator(client, cfg.llm, seed=seed)

    def llm_provider(strategy: str, context: Dict[str, str], attempt: int = 0) -> str:
        return payload_gen.generate(strategy, context, attempt)

    w = cfg.reward
    policy_order = make_policy_order(agent)

    methods = [
        ComparisonMethod(
            name="Static-Signature (SQLMap-style)", short="Static",
            payload_provider=canonical_provider, analyzer=heur_analyzer,
            order_fn=fixed_order, uses_rl=False, uses_llm=False, has_ethics=False, weights=w,
            max_attempts=3,
        ),
        ComparisonMethod(
            name="Random-Select", short="Random",
            payload_provider=canonical_provider, analyzer=heur_analyzer,
            order_fn=make_random_order(seed), uses_rl=False, uses_llm=False, has_ethics=False, weights=w,
            max_attempts=3,
        ),
        ComparisonMethod(
            name="RL-only (Q-Learning, no LLM)", short="RL-only",
            payload_provider=canonical_provider, analyzer=heur_analyzer,
            order_fn=policy_order, uses_rl=True, uses_llm=False, has_ethics=False, weights=w,
            max_attempts=3,
        ),
        ComparisonMethod(
            name="LLM-only (no RL)", short="LLM-only",
            payload_provider=llm_provider, analyzer=llm_analyzer,
            order_fn=fixed_order, uses_rl=False, uses_llm=True, has_ethics=False, weights=w,
            max_attempts=3,
        ),
        ComparisonMethod(
            name="SQLiRLLM (proposed)", short="SQLiRLLM",
            payload_provider=llm_provider, analyzer=llm_analyzer,
            order_fn=policy_order, uses_rl=True, uses_llm=True, has_ethics=True, weights=w,
            guard=EthicsGuard(authorized_targets=set()),  # populated per run
            max_attempts=3,
        ),
    ]
    return methods, payload_gen, client


def run(episodes: int, n_targets: int, seed: int) -> Dict:
    RESULTS.mkdir(parents=True, exist_ok=True)
    cfg = CONFIG
    print("[note] run_comparison is simulation-only and does not send HTTP traffic.")
    print("[note] for real Docker targets, run experiments.live.sqlirllm_runner/sqlmap_runner.")
    print(f"[1/7] Building {n_targets} sandboxed targets (seed={seed}) ...")
    targets = build_target_suite(n=n_targets, seed=seed)
    authorized = {t.target_id for t in targets}
    print(f"      LLM configured={cfg.llm.is_configured} payload={cfg.llm.payload_model} "
          f"analysis={cfg.llm.analysis_model}")

    # ---------------------------------------------------------------- #
    # Train the shared strategic planner (fast, offline reward signal). #
    # ---------------------------------------------------------------- #
    print(f"[2/7] Training Tier-1 Q-policy for {episodes} episodes ...")
    agent = QLearningAgent(cfg.qlearning, seed=seed)
    train_client = LLMClient(cfg.llm)
    train_analyzer = Analyzer(train_client, cfg.llm, llm_enabled=False)
    train_payload_gen = PayloadGenerator(train_client, cfg.llm, seed=seed)

    def training_provider(strategy, context, attempt=0):
        # Obfuscated offline templates -> bypass WAF -> clean learning signal.
        return train_payload_gen._offline(strategy)
    history = train_policy(
        agent, targets, training_provider, train_analyzer, cfg.reward,
        episodes=episodes, max_steps=cfg.qlearning.max_steps_per_episode, seed=seed,
    )
    pd.DataFrame({"episode": range(len(history)), "reward": history}).to_csv(
        RESULTS / "convergence.csv", index=False)

    smooth = _moving_average(history, max(5, episodes // 20))
    plt.figure(figsize=(7, 4))
    plt.plot(history, color="#9ec9ff", alpha=0.55, label="Episode reward")
    if len(smooth) > 1:
        plt.plot(range(len(history) - len(smooth), len(history)), smooth,
                 color="#1f6feb", linewidth=2, label="Moving average")
    plt.xlabel("Training episode")
    plt.ylabel("Cumulative reward")
    plt.title("Tier-1 strategic planner — Q-learning convergence")
    plt.figtext(0.5, 0.01,
                "Interpretation: higher and stabilizing reward indicates better policy quality.",
                ha="center", fontsize=8)
    plt.legend(); plt.tight_layout()
    plt.savefig(RESULTS / "convergence.png", dpi=140); plt.close()

    # ---------------------------------------------------------------- #
    # Instantiate methods (sharing the trained policy).                #
    # ---------------------------------------------------------------- #
    methods, payload_gen, client = build_methods(cfg, agent, seed)
    # Authorize all in-scope targets for the ethical method's main evaluation.
    for mth in methods:
        if mth.guard is not None:
            mth.guard.authorized_targets = set(authorized)

    # ---------------------------------------------------------------- #
    # Detection-quality (full coverage) for every method.              #
    # ---------------------------------------------------------------- #
    print("[3/7] Evaluating detection quality (full coverage) for all methods ...")
    quality: Dict[str, MetricAccumulator] = {}
    for mth in methods:
        print(f"      - {mth.short} ...", flush=True)
        quality[mth.short] = mth.evaluate_coverage(targets)

    quality_rows = {short: m.summary() for short, m in quality.items()}
    qdf = pd.DataFrame(quality_rows).T
    qdf.to_csv(RESULTS / "comparison_quality.csv")
    print(qdf.to_string())

    metric_keys = ["VDR", "FPR", "Precision", "F1", "WAF_bypass_rate", "ESR"]
    shorts = list(quality.keys())
    x = np.arange(len(metric_keys))
    width = 0.15
    plt.figure(figsize=(11, 5))
    palette = ["#8b949e", "#c9a227", "#f0883e", "#3fb950", "#1f6feb"]
    for i, short in enumerate(shorts):
        vals = [quality[short].summary()[k] for k in metric_keys]
        plt.bar(x + (i - 2) * width, vals, width, label=short, color=palette[i % len(palette)])
    plt.xticks(x, metric_keys); plt.ylim(0, 1.08); plt.ylabel("Score")
    plt.title("Detection-quality comparison across methods")
    plt.figtext(0.5, 0.01,
                "Direction: VDR/Precision/F1/WAF/ESR higher is better; FPR lower is better.",
                ha="center", fontsize=8)
    plt.legend(ncol=3, fontsize=8); plt.tight_layout()
    plt.savefig(RESULTS / "comparison_quality.png", dpi=140); plt.close()

    # Heatmap view for fast academic reading of method-vs-metric patterns.
    direction_labels = {
        "VDR": "VDR (higher better)",
        "FPR": "FPR (lower better)",
        "Precision": "Precision (higher better)",
        "F1": "F1 (higher better)",
        "WAF_bypass_rate": "WAF-bypass (higher better)",
        "ESR": "ESR (higher better)",
    }
    hcols = list(direction_labels.keys())
    hdata = qdf[hcols].copy()
    hplot = hdata.copy()
    # Convert FPR so all heatmap colors move in the same "better" direction.
    hplot["FPR"] = 1.0 - hplot["FPR"]
    plt.figure(figsize=(10.5, 4.5))
    im = plt.imshow(hplot.values, aspect="auto", cmap="YlGnBu", vmin=0.0, vmax=1.0)
    plt.colorbar(im, fraction=0.03, pad=0.02, label="Normalized score (higher better)")
    plt.yticks(range(len(hplot.index)), hplot.index)
    plt.xticks(range(len(hcols)), [direction_labels[c] for c in hcols], rotation=18, ha="right")
    for yi in range(hplot.shape[0]):
        for xi in range(hplot.shape[1]):
            raw_val = hdata.iloc[yi, xi]
            plt.text(xi, yi, f"{raw_val:.3f}", ha="center", va="center", fontsize=8, color="#0d1117")
    plt.title("Method x metric heatmap (FPR color uses 1-FPR so brighter means better)")
    plt.tight_layout()
    plt.savefig(RESULTS / "quality_heatmap.png", dpi=140)
    plt.close()

    # Pareto-style tradeoff: detection vs false positives with time as bubble size.
    plt.figure(figsize=(7.5, 5))
    fpr = qdf["FPR"].to_numpy(dtype=float)
    vdr = qdf["VDR"].to_numpy(dtype=float)
    time_ms = qdf["mean_time_ms"].to_numpy(dtype=float)
    bubble = 150 + (time_ms.max() - time_ms + 1.0) * 3.5
    colors = [palette[i % len(palette)] for i in range(len(shorts))]
    plt.scatter(fpr, vdr, s=bubble, c=colors, alpha=0.85, edgecolors="#0d1117", linewidths=0.6)
    for i, short in enumerate(shorts):
        plt.annotate(short, (fpr[i], vdr[i]), textcoords="offset points", xytext=(6, 5), fontsize=8)
    plt.xlim(-0.01, 1.01); plt.ylim(-0.01, 1.01)
    plt.xlabel("FPR (lower better)")
    plt.ylabel("VDR (higher better)")
    plt.title("Detection tradeoff frontier (bubble size: faster methods are larger)")
    plt.grid(alpha=0.2, linestyle="--")
    plt.tight_layout()
    plt.savefig(RESULTS / "pareto_vdr_fpr.png", dpi=140)
    plt.close()

    # Delta-vs-static: direct contribution view for each method.
    static_row = qdf.loc["Static"]
    delta_methods = [m for m in shorts if m != "Static"]
    delta_rows = []
    for m in delta_methods:
        row = qdf.loc[m]
        delta_rows.append({
            "Method": m,
            "VDR_gain": float(row["VDR"] - static_row["VDR"]),
            "F1_gain": float(row["F1"] - static_row["F1"]),
            "WAF_gain": float(row["WAF_bypass_rate"] - static_row["WAF_bypass_rate"]),
            "FPR_reduction": float(static_row["FPR"] - row["FPR"]),
        })
    ddf = pd.DataFrame(delta_rows)
    ddf.to_csv(RESULTS / "delta_vs_static.csv", index=False)
    dx = np.arange(len(delta_methods))
    dw = 0.2
    plt.figure(figsize=(10.5, 4.8))
    plt.bar(dx - 1.5 * dw, ddf["VDR_gain"], dw, label="VDR gain (higher better)", color="#1f6feb")
    plt.bar(dx - 0.5 * dw, ddf["F1_gain"], dw, label="F1 gain (higher better)", color="#3fb950")
    plt.bar(dx + 0.5 * dw, ddf["WAF_gain"], dw, label="WAF gain (higher better)", color="#f0883e")
    plt.bar(dx + 1.5 * dw, ddf["FPR_reduction"], dw, label="FPR reduction (higher better)", color="#c9a227")
    plt.axhline(0.0, color="#6e7681", linewidth=0.8)
    plt.xticks(dx, delta_methods)
    plt.ylabel("Delta relative to Static")
    plt.title("Ablation gains relative to Static baseline")
    plt.legend(ncol=2, fontsize=8)
    plt.tight_layout()
    plt.savefig(RESULTS / "delta_vs_static.png", dpi=140)
    plt.close()

    # Composite score ranking (normalized, direction-aware) for quick comparison.
    benefit = pd.DataFrame(index=qdf.index)
    benefit["VDR"] = qdf["VDR"]
    benefit["FPR"] = 1.0 - qdf["FPR"]
    benefit["F1"] = qdf["F1"]
    benefit["WAF_bypass_rate"] = qdf["WAF_bypass_rate"]
    benefit["ESR"] = qdf["ESR"]
    benefit["Time"] = 1.0 - _norm01(qdf["mean_time_ms"].to_numpy(dtype=float))
    score = (
        0.35 * benefit["VDR"] +
        0.25 * benefit["F1"] +
        0.20 * benefit["WAF_bypass_rate"] +
        0.10 * benefit["FPR"] +
        0.05 * benefit["ESR"] +
        0.05 * benefit["Time"]
    )
    rank_df = pd.DataFrame({
        "method": qdf.index,
        "composite_score": score.round(4),
    }).sort_values("composite_score", ascending=True)
    rank_df.to_csv(RESULTS / "composite_score.csv", index=False)
    plt.figure(figsize=(8.2, 4.2))
    plt.barh(rank_df["method"], rank_df["composite_score"], color="#58a6ff")
    plt.xlim(0, 1.0)
    plt.xlabel("Composite score (higher better)")
    plt.title("Overall ranking (direction-aware normalized composite)")
    plt.tight_layout()
    plt.savefig(RESULTS / "composite_score.png", dpi=140)
    plt.close()

    # ---------------------------------------------------------------- #
    # Paper-style Table I with empirical numbers + literature.         #
    # ---------------------------------------------------------------- #
    print("[4/7] Assembling empirical Table I ...")
    table_rows = []
    rl_label = {"Static": "No", "Random": "No", "RL-only": "Q-L", "LLM-only": "No", "SQLiRLLM": "Q-L"}
    lm_label = {"Static": "No", "Random": "No", "RL-only": "No", "LLM-only": "LLM", "SQLiRLLM": "Multi"}
    eth_label = {"Static": "No", "Random": "No", "RL-only": "No", "LLM-only": "No", "SQLiRLLM": "Yes"}
    for short, m in quality.items():
        s = m.summary()
        table_rows.append({
            "Method": short, "RL": rl_label[short], "LM": lm_label[short], "Ethical": eth_label[short],
            "VDR": s["VDR"], "FPR": s["FPR"], "F1": s["F1"],
            "WAF_bypass": s["WAF_bypass_rate"], "ESR": s["ESR"], "Time_ms": s["mean_time_ms"],
        })
    for name, meta in LITERATURE.items():
        table_rows.append({
            "Method": name, "RL": meta["RL"], "LM": meta["LM"], "Ethical": meta["Ethical"],
            "VDR": "—", "FPR": "—", "F1": "—",
            "WAF_bypass": (meta["evasion_reported"] if meta["evasion_reported"] is not None else "—"),
            "ESR": "—", "Time_ms": "—",
        })
    pd.DataFrame(table_rows).to_csv(RESULTS / "table1_empirical.csv", index=False)

    # ---------------------------------------------------------------- #
    # Budgeted detection efficiency (ordered methods).                 #
    # ---------------------------------------------------------------- #
    print("[5/7] Measuring detection vs. request budget ...")
    budgets = list(range(1, len(STRATEGIES) + 1))
    budget_curves: Dict[str, List[float]] = {}
    for mth in methods:
        if mth.short in ("Random", "RL-only", "SQLiRLLM"):
            budget_curves[mth.short] = [round(mth.evaluate_budget(targets, b), 3) for b in budgets]
    pd.DataFrame({"budget": budgets, **budget_curves}).to_csv(RESULTS / "budget.csv", index=False)

    plt.figure(figsize=(7, 4.5))
    styles = {"Random": ("s--", "#8b949e"), "RL-only": ("^-", "#f0883e"), "SQLiRLLM": ("o-", "#1f6feb")}
    for short, curve in budget_curves.items():
        st, col = styles.get(short, ("o-", "#1f6feb"))
        plt.plot(budgets, curve, st, color=col, label=short)
    plt.xlabel("Request budget (strategies tried per target)")
    plt.ylabel("Targets detected (fraction)"); plt.ylim(0, 1.05)
    plt.title("Detection efficiency under a limited request budget")
    plt.figtext(0.5, 0.01,
                "Interpretation: higher curve at lower budget is better.",
                ha="center", fontsize=8)
    plt.legend(); plt.tight_layout()
    plt.savefig(RESULTS / "budget.png", dpi=140); plt.close()

    # ---------------------------------------------------------------- #
    # Per-strategy detection success (Static vs SQLiRLLM).             #
    # ---------------------------------------------------------------- #
    print("[6/7] Computing per-strategy success ...")
    rows = []
    qs, qb = quality["SQLiRLLM"], quality["Static"]
    for s in STRATEGIES:
        sa, ss = qs.per_strategy_attempts.get(s, 0), qs.per_strategy_success.get(s, 0)
        ba, bs = qb.per_strategy_attempts.get(s, 0), qb.per_strategy_success.get(s, 0)
        rows.append({"strategy": s,
                     "sqlirllm_rate": round(ss / sa, 3) if sa else 0.0,
                     "static_rate": round(bs / ba, 3) if ba else 0.0})
    pd.DataFrame(rows).to_csv(RESULTS / "per_strategy.csv", index=False)
    xs = np.arange(len(STRATEGIES))
    plt.figure(figsize=(9, 4.5))
    plt.bar(xs - 0.2, [r["sqlirllm_rate"] for r in rows], 0.4, label="SQLiRLLM", color="#1f6feb")
    plt.bar(xs + 0.2, [r["static_rate"] for r in rows], 0.4, label="Static baseline", color="#8b949e")
    plt.xticks(xs, [s.replace("_", "\n") for s in STRATEGIES], fontsize=8)
    plt.ylim(0, 1.08); plt.ylabel("Detection success rate")
    plt.title("Per-strategy detection success"); plt.legend(); plt.tight_layout()
    plt.figtext(0.5, 0.01,
                "Interpretation: higher bars indicate stronger strategy effectiveness.",
                ha="center", fontsize=8)
    plt.savefig(RESULTS / "per_strategy.png", dpi=140); plt.close()

    # ---------------------------------------------------------------- #
    # Ethics stress test — half the targets out of scope.              #
    # ---------------------------------------------------------------- #
    print("[7/7] Ethical-constraint stress test ...")
    sqli_method = methods[-1]
    half = set(sorted(authorized)[: len(authorized) // 2])
    sqli_method.guard.authorized_targets = half
    restricted = sqli_method.evaluate_coverage(targets)
    # A non-ethical method (LLM-only) for contrast: it has no guard, so it would
    # act on every target -> 0 refusals on out-of-scope systems.
    ethics_rows = [{
        "method": "SQLiRLLM (ethics on)", "authorized_targets": len(half),
        "total_targets": len(authorized), "actions": restricted.total_actions,
        "violations_caught": restricted.ethical_violations, "ESR": round(restricted.esr, 4),
    }, {
        "method": "LLM-only (no ethics)", "authorized_targets": len(half),
        "total_targets": len(authorized), "actions": quality["LLM-only"].total_actions,
        "violations_caught": 0, "ESR": round(len(half) / len(authorized), 4),
    }]
    pd.DataFrame(ethics_rows).to_csv(RESULTS / "ethics.csv", index=False)
    # Restore full authorization.
    sqli_method.guard.authorized_targets = set(authorized)

    summary = {
        "config": {
            "episodes": episodes, "n_targets": n_targets, "seed": seed,
            "llm_configured": cfg.llm.is_configured,
            "payload_model": cfg.llm.payload_model, "analysis_model": cfg.llm.analysis_model,
            "reward_weights": vars(cfg.reward),
        },
        "quality": quality_rows,
        "table1": table_rows,
        "budget": {"budgets": budgets, **budget_curves},
        "per_strategy": rows,
        "ethics": ethics_rows,
        "llm_usage": {
            "payload_offline_fallbacks": payload_gen.offline_used,
            "analyzer_llm_calls": methods[-1].analyzer.llm_calls,
            "analyzer_heuristic_calls": methods[-1].analyzer.heuristic_calls,
            "api_calls": client.calls, "cache_hits": client.cache_hits,
            "final_epsilon": round(agent.epsilon, 4), "q_states_learned": len(agent.q),
        },
        "figure_guide": {
            "comparison_quality.png": "Grouped bars over core metrics. Better: VDR/F1/Precision/WAF/ESR up, FPR down.",
            "quality_heatmap.png": "Method x metric matrix with raw values. FPR color uses 1-FPR so brighter is better.",
            "pareto_vdr_fpr.png": "Tradeoff map: ideal region is top-left (high VDR, low FPR). Bubble size favors lower time.",
            "delta_vs_static.png": "Improvements versus static baseline. Positive bars indicate better-than-static.",
            "composite_score.png": "Direction-aware normalized ranking score. Higher composite is better.",
            "budget.png": "Detection under constrained requests. Curves closer to 1 with fewer requests are better.",
            "per_strategy.png": "Technique-specific success rates; higher bars indicate stronger exploitation capability.",
            "convergence.png": "Training reward trend; stable upward behavior indicates policy learning convergence.",
        },
    }
    pd.DataFrame([
        {"figure": "convergence.png", "primary_signal": "reward trajectory", "better_direction": "higher and stable"},
        {"figure": "comparison_quality.png", "primary_signal": "multi-metric quality", "better_direction": "higher except FPR"},
        {"figure": "quality_heatmap.png", "primary_signal": "method x metric matrix", "better_direction": "brighter better (FPR uses 1-FPR for color)"},
        {"figure": "pareto_vdr_fpr.png", "primary_signal": "VDR/FPR frontier", "better_direction": "top-left region"},
        {"figure": "delta_vs_static.png", "primary_signal": "improvement over static", "better_direction": "positive values"},
        {"figure": "composite_score.png", "primary_signal": "direction-aware rank", "better_direction": "higher"},
        {"figure": "budget.png", "primary_signal": "detection under request constraints", "better_direction": "higher at lower budget"},
        {"figure": "per_strategy.png", "primary_signal": "technique success profile", "better_direction": "higher"},
    ]).to_csv(RESULTS / "graph_notes.csv", index=False)
    (RESULTS / "summary.json").write_text(json.dumps(summary, indent=2))

    print("\n================ SUMMARY ================")
    print(qdf[["VDR", "FPR", "F1", "WAF_bypass_rate", "ESR", "mean_time_ms"]].to_string())
    print(f"\nBudget curves: {budget_curves}")
    print(f"Ethics: {ethics_rows}")
    print(f"LLM usage: {summary['llm_usage']}")
    print(f"\nArtifacts -> {RESULTS}")
    return summary


def main() -> None:
    p = argparse.ArgumentParser(description="SQLiRLLM full multi-method comparison.")
    p.add_argument("--episodes", type=int, default=400)
    p.add_argument("--targets", type=int, default=40)
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()
    run(args.episodes, args.targets, args.seed)


if __name__ == "__main__":
    main()
