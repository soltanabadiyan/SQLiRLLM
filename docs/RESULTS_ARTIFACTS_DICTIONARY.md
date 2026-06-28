# Results Artifacts Dictionary

This document explains every important generated artifact and how to interpret it.

## 1. Simulation Artifacts (`results/`)

## 1.1 Core Summary

- `results/summary.json`
  - canonical machine-readable simulation summary,
  - contains quality metrics by method,
  - includes ethics-related summary information.

## 1.2 CSV Tables

- `results/comparison_quality.csv`: method-level quality metrics table.
- `results/convergence.csv`: episode reward history for convergence analysis.
- `results/per_strategy.csv`: per-technique success breakdown.
- `results/budget.csv`: performance vs strategy budget constraints.
- `results/delta_vs_static.csv`: relative gains versus static baseline.
- `results/composite_score.csv`: normalized composite ranking table.
- `results/table1_empirical.csv`: paper-ready empirical summary table.
- `results/ethics.csv`: ethical guard stress-test outcomes.
- `results/graph_notes.csv`: figure metadata/notes.

## 1.3 Figures

- `results/convergence.png`: training reward trend over episodes.
- `results/comparison_quality.png`: grouped metric comparison across methods.
- `results/quality_heatmap.png`: method-vs-metric heatmap.
- `results/pareto_vdr_fpr.png`: VDR/FPR trade-off map.
- `results/delta_vs_static.png`: gains over static baseline.
- `results/composite_score.png`: one-score ranking visualization.
- `results/budget.png`: detection vs request-budget chart.
- `results/per_strategy.png`: per-strategy effectiveness chart.

## 2. Live Raw Artifacts (`results/live/`)

## 2.1 Tool Raw Outputs

- `results/live/sqlmap_results.json`
  - per-target SQLMap structured results,
  - includes detection flags, injection-type list, timing, errors.

- `results/live/sqlirllm_results.json`
  - per-target SQLiRLLM structured results,
  - includes strategies tried/succeeded, detailed attempts, timing, WAF counters.

- `results/live/sqlirllm_telemetry.json`
  - telemetry details for SQLiRLLM run behavior.

## 2.2 Merged and Comparative Outputs

- `results/live/live_results_merged.csv`
  - merged per-target rows across tools.

- `results/live/cross_comparison.csv`
  - cross-domain comparison table combining simulation and live views.

- `results/live/cross_summary.json`
  - high-level JSON summary,
  - includes `simulation`, `cross_comparison`, and `live_validated` sections.

## 2.3 Live Analysis Helper Tables

- `results/live/live_vuln_type_counts.csv`
  - vulnerability-type counts by lab and tool.

- `results/live/live_waf_events.csv`
  - WAF encountered/blocked/bypassed event counts.

- `results/live/live_requests_to_detect.csv`
  - request usage until detection (or total attempts).

## 2.4 Live Figures

- `results/live/sim_comparison.png`: simulation metrics chart rendered in live report folder.
- `results/live/live_per_platform.png`: per-platform detection comparison (SQLMap vs SQLiRLLM).
- `results/live/live_vuln_type_by_lab.png`: vulnerability-type coverage by lab.
- `results/live/live_waf_mechanism.png`: WAF outcome visualization.
- `results/live/live_requests_per_lab_mechanism.png`: request-efficiency by target/mechanism.

## 2.5 Final Canonical Reports

- `results/live/final_report.md`
  - human-readable run report with run config and summary metrics.

- `results/live/final_report.json`
  - canonical machine-readable final report,
  - includes run config, simulation highlights, and live tool summaries,
  - best source for synchronizing docs and paper text.

## 3. Recommended Interpretation Order

1. read `results/live/final_report.json`,
2. inspect `results/live/cross_summary.json`,
3. inspect per-target raw JSON files,
4. use figures/CSVs to support narrative.

## 4. Metric Notes

- Raw live detection rate can differ from validated success rate.
- Validated success uses expected-vulnerability labels.
- Coverage-on-vulnerable focuses only on expected-vulnerable targets.
- Time metrics in live outputs are tool-specific execution durations.

## 5. Documentation Synchronization Rule

When run metrics change, update these first:

1. `README.md`,
2. `RESULTS.md`,
3. `IMPLEMENTATION_SUMMARY.md`,
4. report/paper artifacts (for example `docs/my final.pdf.html`).

Source of truth priority:

1. `results/live/final_report.json`
2. `results/live/cross_summary.json`
3. raw per-tool JSON files
