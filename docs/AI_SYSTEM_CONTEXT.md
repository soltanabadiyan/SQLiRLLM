# AI System Context (Machine-Oriented Brief)

This file is designed for coding agents that need fast, accurate understanding of the repository.

## 1. One-Screen Summary

Project type:

- Research codebase for adaptive SQL injection testing in authorized lab environments.

Primary modes:

- simulation (reproducible synthetic targets),
- live docker benchmark (real vulnerable apps),
- unified full pipeline (`run_full_report.sh`).

Primary outputs:

- `results/summary.json` (simulation),
- `results/live/sqlmap_results.json`,
- `results/live/sqlirllm_results.json`,
- `results/live/cross_summary.json`,
- `results/live/final_report.json`.

## 2. Core Runtime Graph

1. choose strategy (Q-learning),
2. ethics authorize action,
3. generate payload (LLM/offline templates + WAF hardening),
4. execute against target (simulation or live),
5. analyze response (LLM/heuristic/proof),
6. update metrics and reward,
7. emit reports.

## 3. Critical Files by Concern

- strategy learning: `sqlirllm/qlearning.py`, `sqlirllm/framework.py`, `sqlirllm/reward.py`
- payload behavior: `sqlirllm/payload_generator.py`
- analysis verdicts: `sqlirllm/analyzer.py`
- ethics/scope: `sqlirllm/ethics.py`
- simulation target model: `sqlirllm/environment.py`
- live target execution: `experiments/live/sqlirllm_runner.py`
- SQLMap baseline: `experiments/live/sqlmap_runner.py`
- cross-aggregation: `experiments/live/compare.py`
- orchestration/reporting: `run_full_report.sh`

## 4. Important Invariants

- operate on authorized lab targets only,
- preserve expected-vulnerability semantics used by validated metrics,
- keep live target names consistent across sqlmap/sqlirllm runners,
- avoid breaking final report schema fields consumed by docs,
- preserve deterministic fallback paths when LLM/API is unavailable.

## 5. Canonical Data Sources for Claims

Use this precedence for numbers used in docs:

1. `results/live/final_report.json`
2. `results/live/cross_summary.json`
3. raw live JSON files
4. markdown docs

Never treat markdown docs as canonical when JSON artifacts disagree.

## 6. High-Impact Failure Modes

- auth/session drift in DVWA/bWAPP causing false negatives,
- host mismatch (`localhost` vs `127.0.0.1`) causing cookie/session inconsistency,
- stale docs after reruns,
- changing target definitions in one runner but not the other,
- report-generation schema drift breaking downstream docs.

## 7. Safe Extension Points

- add strategy templates and evasion transforms in `payload_generator.py`,
- add proof rules per target in `experiments/live/sqlirllm_runner.py`,
- add comparison metrics in `experiments/live/compare.py`,
- add report fields in `run_full_report.sh` final JSON/MD emitter.

## 8. Minimal Verification After Edits

1. run relevant runner(s),
2. ensure JSON outputs are generated and parseable,
3. verify aggregate outputs regenerate,
4. verify docs referencing changed metrics are synchronized.

## 9. Suggested Agent Workflow

1. inspect canonical JSON outputs,
2. patch code or docs,
3. run targeted validation,
4. regenerate aggregates if needed,
5. run stale-value grep checks,
6. summarize deltas clearly.
