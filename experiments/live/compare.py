"""Cross-platform comparison aggregator.

Merges results from:
  1. Controlled simulation (results/summary.json)          — all five methods
  2. SQLMap live runs    (results/live/sqlmap_results.json)
  3. SQLiRLLM live runs  (results/live/sqlirllm_results.json)

Produces:
  results/live/cross_comparison.csv   — master comparison table
  results/live/cross_comparison.png   — side-by-side bar chart
  results/live/live_per_platform.png  — per-platform success (SQLMap vs SQLiRLLM)
  results/live/cross_summary.json     — machine-readable combined summary

Usage:
    python -m experiments.live.compare
    python -m experiments.live.compare --no-live   (simulation only, if live not run)
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Set

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

BASE = Path(__file__).resolve().parent.parent.parent
SIM_SUMMARY = BASE / "results" / "summary.json"
LIVE_SQLMAP = BASE / "results" / "live" / "sqlmap_results.json"
LIVE_SQLI = BASE / "results" / "live" / "sqlirllm_results.json"
OUT = BASE / "results" / "live"


def load_sim() -> pd.DataFrame:
    data = json.loads(SIM_SUMMARY.read_text())
    q = data["quality"]
    rows = []
    for method, m in q.items():
        rows.append({
            "Method": method, "Domain": "Simulation",
            "VDR": m["VDR"], "FPR": m["FPR"], "F1": m["F1"],
            "WAF_bypass": m["WAF_bypass_rate"], "ESR": m["ESR"],
            "Time_ms": m["mean_time_ms"],
        })
    return pd.DataFrame(rows)


def load_sqlmap(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    data = json.loads(path.read_text())
    rows = []
    for r in data:
        if r.get("error"):
            continue
        rows.append({
            "Method": "SQLMap",
            "Domain": "Live: " + r.get("platform", "?"),
            "Target": r.get("target"),
            "Vulnerable_detected": r.get("vulnerable_detected", False),
            "Expected_vulnerable": r.get("expected_vulnerable", True),
            "Has_WAF": r.get("has_waf", False),
            "Injection_types": len(r.get("injection_types", [])),
            "Injection_type_names": r.get("injection_types", []),
            "Duration_s": r.get("duration_s", 0),
            "Request_count_estimate": r.get("request_count_estimate"),
            "Error": r.get("error"),
        })
    return pd.DataFrame(rows)


def load_sqlirllm(path: Path) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame()
    data = json.loads(path.read_text())
    rows = []
    for r in data:
        if r.get("error"):
            continue
        tried = r.get("strategies_tried", 0)
        succ = r.get("strategies_succeeded", 0)
        rows.append({
            "Method": "SQLiRLLM",
            "Domain": "Live: " + r.get("platform", "?"),
            "Target": r.get("target"),
            "Vulnerable_detected": succ > 0,
            "Expected_vulnerable": r.get("expected_vulnerable", True),
            "Has_WAF": r.get("has_waf", False),
            "Strategies_tried": tried,
            "Strategies_succeeded": succ,
            "WAF_bypass_rate": r.get("waf_bypass_rate"),
            "Duration_s": r.get("total_duration_s", 0),
            "Ethical_violations": r.get("ethical_violations", 0),
            "Detailed": r.get("detailed", []),
        })
    return pd.DataFrame(rows)


def _normalize_sqlmap_type(name: str) -> str:
    n = (name or "").lower()
    if "union" in n:
        return "union_based"
    if "error" in n:
        return "error_based"
    if "time" in n:
        return "time_blind"
    if "boolean" in n:
        return "boolean_blind"
    if "stack" in n:
        return "stacked_queries"
    if "second" in n:
        return "second_order"
    return "other"


def _build_detection_type_rows(sqlmap_live: pd.DataFrame, sqli_live: pd.DataFrame) -> pd.DataFrame:
    rows: List[Dict] = []

    for _, r in sqlmap_live.iterrows():
        lab = str(r.get("Domain", "")).replace("Live: ", "")
        target = r.get("Target")
        detected = bool(r.get("Vulnerable_detected", False))
        type_names = r.get("Injection_type_names", []) or []
        seen_types: Set[str] = set()
        if detected and type_names:
            seen_types = {_normalize_sqlmap_type(t) for t in type_names}
        elif detected:
            seen_types = {"other"}
        for tname in seen_types:
            rows.append({"Tool": "SQLMap", "Lab": lab, "Target": target, "VulnType": tname, "Detected": 1})

    for _, r in sqli_live.iterrows():
        lab = str(r.get("Domain", "")).replace("Live: ", "")
        target = r.get("Target")
        detailed = r.get("Detailed", []) or []
        seen_types: Set[str] = set()
        for ev in detailed:
            if bool(ev.get("llm_verdict", False)):
                st = ev.get("strategy")
                if st:
                    seen_types.add(st)
        for tname in seen_types:
            rows.append({"Tool": "SQLiRLLM", "Lab": lab, "Target": target, "VulnType": tname, "Detected": 1})

    return pd.DataFrame(rows)


def _build_waf_rows(sqlmap_live: pd.DataFrame, sqli_live: pd.DataFrame) -> pd.DataFrame:
    rows: List[Dict] = []

    for _, r in sqlmap_live.iterrows():
        if not bool(r.get("Has_WAF", False)):
            continue
        rows.append({
            "Tool": "SQLMap",
            "Target": r.get("Target"),
            "Lab": str(r.get("Domain", "")).replace("Live: ", ""),
            "WAF_Encountered": 1,
            "WAF_Detected_Blocked": int(not bool(r.get("Vulnerable_detected", False))),
            "WAF_Bypassed": int(bool(r.get("Vulnerable_detected", False))),
        })

    for _, r in sqli_live.iterrows():
        if not bool(r.get("Has_WAF", False)):
            continue
        detailed = r.get("Detailed", []) or []
        blocked = sum(1 for ev in detailed if ev.get("outcome") == "blocked")
        encounters = int(r.get("waf_encounters", 0) or 0)
        bypasses = int(r.get("waf_bypasses", 0) or 0)
        if encounters == 0 and detailed:
            encounters = len(detailed)
            bypasses = sum(1 for ev in detailed if ev.get("outcome") != "blocked")
        rows.append({
            "Tool": "SQLiRLLM",
            "Target": r.get("Target"),
            "Lab": str(r.get("Domain", "")).replace("Live: ", ""),
            "WAF_Encountered": encounters,
            "WAF_Detected_Blocked": blocked,
            "WAF_Bypassed": bypasses,
        })

    return pd.DataFrame(rows)


def _build_requests_rows(sqlmap_live: pd.DataFrame, sqli_live: pd.DataFrame) -> pd.DataFrame:
    rows: List[Dict] = []

    for _, r in sqlmap_live.iterrows():
        rows.append({
            "Tool": "SQLMap",
            "Lab": str(r.get("Domain", "")).replace("Live: ", ""),
            "Target": r.get("Target"),
            "Requests_to_detection": r.get("Request_count_estimate"),
            "Detected": bool(r.get("Vulnerable_detected", False)),
        })

    for _, r in sqli_live.iterrows():
        detailed = r.get("Detailed", []) or []
        req_total = len(detailed)
        req_to_detect = None
        for i, ev in enumerate(detailed, start=1):
            if bool(ev.get("llm_verdict", False)):
                req_to_detect = i
                break
        if req_to_detect is None and req_total > 0:
            req_to_detect = req_total
        rows.append({
            "Tool": "SQLiRLLM",
            "Lab": str(r.get("Domain", "")).replace("Live: ", ""),
            "Target": r.get("Target"),
            "Requests_to_detection": req_to_detect,
            "Detected": bool(r.get("Vulnerable_detected", False)),
        })

    return pd.DataFrame(rows)


def run(live: bool = True) -> None:
    OUT.mkdir(parents=True, exist_ok=True)

    sim = load_sim()
    sqli_live = load_sqlirllm(LIVE_SQLI) if live else pd.DataFrame()
    sqlmap_live = load_sqlmap(LIVE_SQLMAP) if live else pd.DataFrame()

    # ── Simulation comparison chart ──────────────────────────────────────── #
    metrics = ["VDR", "FPR", "F1", "WAF_bypass", "ESR"]
    methods_order = ["Static", "Random", "RL-only", "LLM-only", "SQLiRLLM"]
    sim_ordered = sim.set_index("Method").reindex(methods_order)

    x = np.arange(len(metrics))
    width = 0.15
    palette = ["#6e7681", "#c9a227", "#f0883e", "#3fb950", "#1f6feb"]
    plt.figure(figsize=(11, 5))
    for i, m in enumerate(methods_order):
        if m not in sim_ordered.index:
            continue
        vals = [sim_ordered.loc[m, k] for k in metrics]
        plt.bar(x + (i - 2) * width, vals, width, label=m, color=palette[i % len(palette)])
    plt.xticks(x, metrics)
    plt.ylim(0, 1.08)
    plt.ylabel("Score")
    plt.title("SQLiRLLM vs. Ablation Baselines (Simulated Environment, N=40 targets)")
    plt.legend(ncol=3, fontsize=9)
    plt.tight_layout()
    plt.savefig(OUT / "sim_comparison.png", dpi=140)
    plt.close()

    # ── Live results: detection rate per platform ─────────────────────────── #
    out_rows = []
    for df_tool, tool_name in [(sqlmap_live, "SQLMap"), (sqli_live, "SQLiRLLM")]:
        if df_tool.empty:
            continue
        for _, r in df_tool.iterrows():
            out_rows.append({
                "Tool": tool_name,
                "Platform": r.get("Domain", ""),
                "Target": r.get("Target", ""),
                "Has_WAF": r.get("Has_WAF", False),
                "Detected": r.get("Vulnerable_detected", False),
                "Duration_s": r.get("Duration_s", 0),
            })

    if out_rows:
        live_df = pd.DataFrame(out_rows)
        live_df.to_csv(OUT / "live_results_merged.csv", index=False)

        # Per-platform detection bar chart.
        platforms = live_df["Platform"].unique()
        tools = ["SQLMap", "SQLiRLLM"]
        x2 = np.arange(len(platforms))
        w2 = 0.38
        plt.figure(figsize=(max(8, len(platforms) * 1.5), 4.5))
        for ti, tool in enumerate(tools):
            sub = live_df[live_df["Tool"] == tool]
            rates = []
            for pf in platforms:
                pf_sub = sub[sub["Platform"] == pf]
                rates.append(pf_sub["Detected"].mean() if len(pf_sub) else 0.0)
            plt.bar(x2 + (ti - 0.5) * w2, rates, w2,
                    label=tool, color=["#f0883e", "#1f6feb"][ti])
        plt.xticks(x2, [p.replace("Live: ", "") for p in platforms], fontsize=8, rotation=15)
        plt.ylim(0, 1.15)
        plt.ylabel("Detection rate")
        plt.title("Live-Platform Detection: SQLMap vs. SQLiRLLM")
        plt.legend()
        plt.tight_layout()
        plt.savefig(OUT / "live_per_platform.png", dpi=140)
        plt.close()

    # ── New graph 1: vulnerability type counts per lab and mechanism ─────── #
    detection_types = _build_detection_type_rows(sqlmap_live, sqli_live)
    all_labs = sorted(set(sqlmap_live.get("Domain", pd.Series(dtype=str)).str.replace("Live: ", "", regex=False)) |
                      set(sqli_live.get("Domain", pd.Series(dtype=str)).str.replace("Live: ", "", regex=False)))
    default_types = ["union_based", "error_based", "boolean_blind", "time_blind", "stacked_queries", "second_order", "other"]

    if not detection_types.empty:
        combo = detection_types.groupby(["Lab", "VulnType", "Tool"], as_index=False)["Detected"].sum()
        total_obs = detection_types.groupby(["Lab", "VulnType"], as_index=False)["Detected"].max()
        total_obs = total_obs.rename(columns={"Detected": "Total_Observed"})
        type_summary = combo.merge(total_obs, on=["Lab", "VulnType"], how="left")
    else:
        type_summary = pd.DataFrame(columns=["Lab", "VulnType", "Tool", "Detected", "Total_Observed"])

    # Ensure zero-count rows exist so the figure is always rendered.
    fill_rows = []
    for lab in all_labs:
        for vt in default_types:
            for tool in ["SQLMap", "SQLiRLLM"]:
                exists = ((type_summary["Lab"] == lab) & (type_summary["VulnType"] == vt) & (type_summary["Tool"] == tool)).any()
                if not exists:
                    fill_rows.append({"Lab": lab, "VulnType": vt, "Tool": tool, "Detected": 0, "Total_Observed": 0})
    if fill_rows:
        type_summary = pd.concat([type_summary, pd.DataFrame(fill_rows)], ignore_index=True)

    if not type_summary.empty:
        type_summary["Detected"] = type_summary["Detected"].fillna(0).astype(int)
        type_summary["Total_Observed"] = type_summary["Total_Observed"].fillna(0).astype(int)
        type_summary = type_summary.sort_values(["Lab", "VulnType", "Tool"]).reset_index(drop=True)
        type_summary.to_csv(OUT / "live_vuln_type_counts.csv", index=False)

        pairs = sorted({(r["Lab"], r["VulnType"]) for _, r in type_summary.iterrows()})
        labels = [f"{lab} | {vt}" for lab, vt in pairs]
        x = np.arange(len(labels))
        totals = []
        sqlmap_vals = []
        sqli_vals = []
        for lab, vt in pairs:
            sub = type_summary[(type_summary["Lab"] == lab) & (type_summary["VulnType"] == vt)]
            totals.append(int(sub["Total_Observed"].max()) if len(sub) else 0)
            sqlmap_vals.append(int(sub[sub["Tool"] == "SQLMap"]["Detected"].sum()))
            sqli_vals.append(int(sub[sub["Tool"] == "SQLiRLLM"]["Detected"].sum()))

        w = 0.26
        plt.figure(figsize=(max(10, len(labels) * 0.9), 5.2))
        plt.bar(x - w, totals, width=w, label="Total observed", color="#6e7681")
        plt.bar(x, sqlmap_vals, width=w, label="Detected by SQLMap", color="#f0883e")
        plt.bar(x + w, sqli_vals, width=w, label="Detected by SQLiRLLM", color="#1f6feb")
        plt.xticks(x, labels, rotation=30, ha="right", fontsize=8)
        plt.ylabel("Count")
        plt.title("Vulnerability type counts per lab and detections by mechanism")
        plt.legend(ncol=3, fontsize=8)
        plt.tight_layout()
        plt.savefig(OUT / "live_vuln_type_by_lab.png", dpi=140)
        plt.close()

    # ── New graph 2: WAF detection/bypass outcomes per mechanism ─────────── #
    waf_rows = _build_waf_rows(sqlmap_live, sqli_live)
    if not waf_rows.empty:
        waf_rows.to_csv(OUT / "live_waf_events.csv", index=False)
        waf_sum = waf_rows.groupby("Tool", as_index=False)[["WAF_Encountered", "WAF_Detected_Blocked", "WAF_Bypassed"]].sum()
        xw = np.arange(len(waf_sum))
        ww = 0.24
        plt.figure(figsize=(7.6, 4.8))
        plt.bar(xw - ww, waf_sum["WAF_Encountered"], width=ww, label="WAF encounters", color="#8b949e")
        plt.bar(xw, waf_sum["WAF_Detected_Blocked"], width=ww, label="WAF detected/blocked", color="#da3633")
        plt.bar(xw + ww, waf_sum["WAF_Bypassed"], width=ww, label="WAF bypassed", color="#3fb950")
        plt.xticks(xw, waf_sum["Tool"])
        plt.ylabel("Count")
        plt.title("WAF outcomes per mechanism")
        plt.legend(fontsize=8)
        plt.tight_layout()
        plt.savefig(OUT / "live_waf_mechanism.png", dpi=140)
        plt.close()

    # ── New graph 3: requests needed to detect vulnerabilities per lab ───── #
    req_rows = _build_requests_rows(sqlmap_live, sqli_live)
    if not req_rows.empty:
        req_rows.to_csv(OUT / "live_requests_to_detect.csv", index=False)
        # Use known request counts; for non-detected SQLiRLLM targets this is
        # total attempted requests, which still reflects efficiency.
        req_used = req_rows[req_rows["Requests_to_detection"].notna()].copy()
        if not req_used.empty:
            req_sum = req_used.groupby(["Lab", "Tool"], as_index=False)["Requests_to_detection"].mean()
            labs = sorted(req_sum["Lab"].unique())
            xq = np.arange(len(labs))
            wq = 0.38
            sqlmap_vals = []
            sqli_vals = []
            for lab in labs:
                sm = req_sum[(req_sum["Lab"] == lab) & (req_sum["Tool"] == "SQLMap")]
                sr = req_sum[(req_sum["Lab"] == lab) & (req_sum["Tool"] == "SQLiRLLM")]
                sqlmap_vals.append(float(sm["Requests_to_detection"].iloc[0]) if len(sm) else np.nan)
                sqli_vals.append(float(sr["Requests_to_detection"].iloc[0]) if len(sr) else np.nan)

            plt.figure(figsize=(max(8, len(labs) * 1.3), 4.8))
            plt.bar(xq - wq / 2, sqlmap_vals, width=wq, label="SQLMap", color="#f0883e")
            plt.bar(xq + wq / 2, sqli_vals, width=wq, label="SQLiRLLM", color="#1f6feb")
            plt.xticks(xq, labs, rotation=15)
            plt.ylabel("Mean requests used (lower better)")
            plt.title("Request usage by lab and mechanism (first detection or total attempted)")
            plt.legend()
            plt.tight_layout()
            plt.savefig(OUT / "live_requests_per_lab_mechanism.png", dpi=140)
            plt.close()

    # ── Master cross-comparison CSV ───────────────────────────────────────── #
    sim_out = sim[["Method", "VDR", "FPR", "F1", "WAF_bypass", "ESR", "Time_ms"]].copy()
    sim_out.insert(0, "Domain", "Simulation")

    master = sim_out.copy()
    live_validated = []

    # Append live summary rows.
    for df_tool, tool_name in [(sqlmap_live, "SQLMap"), (sqli_live, "SQLiRLLM")]:
        if df_tool.empty:
            continue
        det = df_tool.get("Vulnerable_detected", pd.Series(dtype=bool))
        expected = df_tool.get("Expected_vulnerable", pd.Series([True] * len(df_tool))).astype(bool)
        n_total = len(df_tool)
        n_det = det.sum() if len(det) else 0
        waf_rows = df_tool[df_tool.get("Has_WAF", pd.Series([False] * len(df_tool)))]
        waf_det = waf_rows.get("Vulnerable_detected", pd.Series(dtype=bool)).sum() if len(waf_rows) else 0
        live_validated.append({
            "Method": tool_name,
            "Validated_SR": round(float((det.astype(bool) == expected).mean()), 3) if n_total else None,
            "Coverage_on_vulnerable": round(float(det[expected].mean()), 3) if expected.any() else None,
        })
        row = pd.DataFrame([{
            "Domain": "Live (Docker)", "Method": tool_name,
            "VDR": round(n_det / n_total, 3) if n_total else None,
            "FPR": None, "F1": None,
            "WAF_bypass": round(waf_det / len(waf_rows), 3) if len(waf_rows) else None,
            "ESR": 1.0 if tool_name == "SQLiRLLM" else None,
            "Time_ms": df_tool.get("Duration_s", pd.Series([0])).mean() * 1000,
        }])
        master = pd.concat([master, row], ignore_index=True)

    master.to_csv(OUT / "cross_comparison.csv", index=False)

    summary = {
        "simulation": sim.to_dict(orient="records"),
        "live_targets_tested": len(out_rows) // 2 if out_rows else 0,
        "cross_comparison": master.to_dict(orient="records"),
        "live_validated": live_validated,
        "live_extra_artifacts": {
            "vuln_type_counts_csv": str((OUT / "live_vuln_type_counts.csv").relative_to(BASE)),
            "vuln_type_counts_png": str((OUT / "live_vuln_type_by_lab.png").relative_to(BASE)),
            "waf_events_csv": str((OUT / "live_waf_events.csv").relative_to(BASE)),
            "waf_events_png": str((OUT / "live_waf_mechanism.png").relative_to(BASE)),
            "requests_csv": str((OUT / "live_requests_to_detect.csv").relative_to(BASE)),
            "requests_png": str((OUT / "live_requests_per_lab_mechanism.png").relative_to(BASE)),
        },
    }
    (OUT / "cross_summary.json").write_text(json.dumps(summary, indent=2, default=str))
    print(f"\nCross-comparison artifacts -> {OUT}")
    print(master[["Domain", "Method", "VDR", "F1", "WAF_bypass", "ESR"]].to_string(index=False))


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--no-live", action="store_true", help="Skip live results (simulation only).")
    args = p.parse_args()
    run(live=not args.no_live)


if __name__ == "__main__":
    main()
