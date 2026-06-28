# SQLiRLLM Project Overview

This document describes all major parts of the project and how they interact from experiment setup to final reporting.

## 1. Project Goal

SQLiRLLM is a research framework for authorized SQL injection assessment with:

- strategic action selection (Q-learning),
- context-aware payload generation (LLM + deterministic fallbacks),
- response analysis (LLM or deterministic heuristics),
- embedded ethical authorization constraints,
- reproducible simulation and live benchmark pipelines.

The system is intended for controlled, legal environments only.

## 2. Top-Level Structure

- `sqlirllm/`: core framework logic (agent, payload generation, analysis, reward, metrics, ethics, simulation environment).
- `experiments/`: runnable experiment entry points for simulation and live benchmarks.
- `experiments/live/`: live runners for SQLiRLLM and SQLMap plus cross-domain comparison tooling.
- `docker/`: reproducible vulnerable target stack and toolbox container.
- `results/`: generated artifacts (tables, JSON summaries, CSV analytics, plots).
- `paper/`: LaTeX source sections for paper/report content.
- `docs/`: rendered/auxiliary documentation artifacts.
- `run_full_report.sh`: single-command orchestrator for full pipeline.

## 3. Core Pipeline Modes

## 3.1 Controlled Simulation Mode

Purpose:

- train/evaluate strategic behavior under deterministic and reproducible conditions,
- compare SQLiRLLM against baselines using consistent synthetic targets.

Main flow:

1. create simulated targets,
2. choose strategy via Q-learning,
3. authorize action via ethics guard,
4. generate payload,
5. execute in simulated target+WAF model,
6. analyze response,
7. compute reward and update policy,
8. aggregate metrics and export plots/CSVs.

Primary command:

- `python -m experiments.run_comparison --episodes 400 --targets 40 --seed 42`

## 3.2 Live Docker Benchmark Mode

Purpose:

- evaluate external plausibility on real intentionally vulnerable apps.

Target set includes:

- DVWA (low/medium/hard/impossible),
- DVWA behind ModSecurity CRS,
- sqli-labs (Less-1 and Less-11),
- bWAPP,
- OWASP Juice Shop.

Main flow:

1. initialize/login/bootstrap target sessions where required,
2. run SQLMap baseline,
3. run SQLiRLLM live probing,
4. compute merged cross-domain summaries,
5. generate final report JSON/MD outputs.

Primary commands:

- `python -m experiments.live.sqlmap_runner`
- `python -m experiments.live.sqlirllm_runner`
- `python -m experiments.live.compare`

## 3.3 Unified End-to-End Mode

Single command pipeline:

- `./run_full_report.sh`

This script can:

- optionally run or skip simulation,
- start docker stack,
- execute SQLMap and/or SQLiRLLM live tests,
- aggregate outputs,
- produce `results/live/final_report.md` and `results/live/final_report.json`.

## 4. Methodological Building Blocks

## 4.1 Tier 1: Strategy Planning

- Tabular Q-learning maps state to ranked strategy choices.
- State dimensions: framework, database, WAF presence, phase.
- Output: ordered strategies to maximize reward under budget.

## 4.2 Tier 2: Payload Synthesis

- LLM generation guided by strategy and context.
- Deterministic fallback templates when APIs are unavailable.
- WAF-focused post-processing with escalation levels and polymorphic rewrites.

## 4.3 Tier 3: Response Analysis

- LLM-based JSON classification where enabled.
- Deterministic heuristics for robustness and cost control.
- Live runner additionally uses target-specific proof checks.

## 4.4 Ethics Layer

- Action gate on each attempt.
- Out-of-scope or disallowed actions are rejected and penalized.
- ESR (Ethical Safeguard Rating) tracks compliance behavior.

## 5. Evaluation Outputs

The project exports two categories:

- simulation quality outputs (VDR/FPR/F1/WAF/ESR/time and visualizations),
- live benchmark outputs (per-target detections, merged comparisons, validated success views).

Important final artifacts:

- `results/summary.json`
- `results/live/sqlmap_results.json`
- `results/live/sqlirllm_results.json`
- `results/live/cross_summary.json`
- `results/live/final_report.json`
- `results/live/final_report.md`

## 6. Reproducibility and Safety Principles

- deterministic seeds and cached LLM responses for reproducibility,
- explicit scope authorization and ethics penalties,
- benchmark-only target stack with known vulnerable apps,
- documented run configuration persisted in final report outputs.

## 7. Typical User Journey

1. install dependencies and configure `.env`,
2. bring up docker targets,
3. run full report pipeline,
4. inspect generated summaries/plots,
5. sync report and paper documentation.

## 8. Where to Go Next

- For exact file responsibilities: see [CODEBASE_REFERENCE](CODEBASE_REFERENCE.md).
- For operations and commands: see [OPERATIONS_RUNBOOK](OPERATIONS_RUNBOOK.md).
- For output semantics: see [RESULTS_ARTIFACTS_DICTIONARY](RESULTS_ARTIFACTS_DICTIONARY.md).
- For coding-agent context: see [AI_SYSTEM_CONTEXT](AI_SYSTEM_CONTEXT.md).
