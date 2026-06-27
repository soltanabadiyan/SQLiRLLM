# SQLiRLLM Unified Final Report

Generated: 2026-06-27 22:32:52Z

## Pipeline Summary

This report was generated from a full rerun pipeline using the current 9-target Docker benchmark scope and updated SQLiRLLM WAF-evasion implementation.

## Run Configuration

- Simulation episodes: 400
- Simulation targets: 40
- Seed: 42
- Skip simulation: 0
- Selected live tools: both
- Selected lab targets: dvwa_sqli dvwa_sqli_medium dvwa_sqli_hard dvwa_sqli_max dvwa_waf sqli_labs_1 sqli_labs_11 bwapp_sqli juiceshop_login
- SQLiRLLM strategies: union_based,error_based,boolean_blind,time_blind,stacked_queries,second_order
- SQLiRLLM max attempts/strategy: 4
- SQLiRLLM request timeout (s): 15
- SQLMap level/risk: 3 / 2
- SQLMap technique: BEUSTQ
- SQLMap tamper: space2comment,charencode
- SQLMap process timeout (s): 45
- SQLMap request timeout (s): 15
- SQLMap threads: 2

## Simulation Highlights (SQLiRLLM)

- VDR (higher better): 0.4615
- FPR (lower better): 0.0905
- F1 (higher better): 0.5596
- WAF-bypass (higher better): 0.624
- ESR (higher better): 1.0

## Live Highlights

- SQLMap detection: 4/9 = 0.444
- SQLiRLLM detection: 6/9 = 0.667

## Output Artifacts

- Simulation summary: results/summary.json
- Simulation plots/tables: results/
- SQLMap live raw: results/live/sqlmap_results.json
- SQLiRLLM live raw: results/live/sqlirllm_results.json
- Cross comparison: results/live/cross_comparison.csv
- Cross summary: results/live/cross_summary.json
- This report: results/live/final_report.md

## Interpretation Notes

1. In all quality figures, higher is better for VDR, Precision, F1, WAF-bypass, ESR.
2. Lower is better for FPR and latency/time.
3. Live outcomes should be interpreted as feasibility evidence unless repeated across multiple runs and seeds.
