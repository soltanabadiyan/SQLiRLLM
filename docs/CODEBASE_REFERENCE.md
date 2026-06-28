# Codebase Reference

This is a practical file-level reference for all major modules in the repository.

## 1. Root-Level Files

- `README.md`: high-level project introduction, quick start, and headline results.
- `ARCHITECTURE.md`: conceptual and methodological architecture details.
- `RESULTS.md`: interpreted experiment outcomes and comparative tables.
- `IMPLEMENTATION_SUMMARY.md`: implementation changes and aggregate status.
- `WAF_EVASION_IMPROVEMENTS.md`: initial WAF evasion design notes.
- `WAF_EVASION_IMPROVEMENTS_v2.md`: enhanced WAF evasion iteration notes.
- `run_full_report.sh`: unified orchestrator for simulation, live runs, aggregation, and final report.
- `requirements.txt`: Python dependencies.

## 2. Core Package: `sqlirllm/`

## 2.1 Orchestration and Method Logic

- `framework.py`
  - main SQLiRLLM orchestrator,
  - training loop, evaluation loop, budgeted evaluation,
  - `build_framework(...)` convenience constructor.

- `methods.py`
  - baseline and method orchestration helpers,
  - strategy ordering providers,
  - comparison/evaluation utility routines.

- `baseline.py`
  - static baseline payloads,
  - baseline behavior primitives for non-adaptive comparison.

## 2.2 Learning and Decision Components

- `qlearning.py`
  - tabular Q-learning agent,
  - epsilon-greedy selection,
  - Q-value updates,
  - strategy ranking per encoded state.

- `reward.py`
  - reward equation implementation,
  - action signal abstraction,
  - ethical penalty integration.

- `config.py`
  - global experiment config,
  - reward weights,
  - Q-learning hyperparameters,
  - model names and LLM settings,
  - strategy/phase constants.

## 2.3 Payload and Analysis Components

- `payload_generator.py`
  - strategy-conditioned payload generation,
  - LLM prompting and cleanup,
  - deterministic offline template fallback,
  - WAF hardening/escalation transformations.

- `analyzer.py`
  - response interpretation,
  - LLM JSON parsing path,
  - deterministic heuristic fallback,
  - signal extraction for vulnerability verdicts.

- `llm_client.py`
  - model API wrapper,
  - retries and timeout handling,
  - cache integration,
  - optional fallback behavior.

## 2.4 Environment, Ethics, and Metrics

- `environment.py`
  - simulated target model,
  - signature-based WAF approximation,
  - execution response semantics,
  - synthetic target suite builder.

- `ethics.py`
  - scope authorization guard,
  - destructive-strategy controls,
  - violation accounting,
  - ESR computation support.

- `metrics.py`
  - confusion matrix accounting,
  - VDR/FPR/Precision/F1/ESR/WAF-bypass metrics,
  - aggregation and export-ready summary structures.

## 3. Experiment Entrypoints: `experiments/`

- `run_comparison.py`
  - controlled simulation comparison pipeline,
  - baseline + SQLiRLLM evaluation,
  - figure and CSV generation in `results/`.

- `run_experiments.py`
  - additional experiment runner flows and metric export variants.

- `smoke_test.py`
  - quick sanity checks for environment/model plumbing.

## 4. Live Benchmark Package: `experiments/live/`

- `sqlmap_runner.py`
  - SQLMap baseline execution over defined live targets,
  - session/bootstrap helpers for app readiness,
  - structured JSON output for downstream aggregation.

- `sqlirllm_runner.py`
  - SQLiRLLM live probing over same target scope,
  - per-target request flow handling,
  - deterministic proof checks,
  - structured per-target detailed event export.

- `compare.py`
  - merges simulation + live outputs,
  - builds comparative CSV/JSON summaries,
  - emits multiple visualization artifacts.

## 5. Docker and Tooling

- `docker/docker-compose.yml`
  - vulnerable app stack and WAF topology,
  - toolbox container definition,
  - port mappings and service relationships.

- `docker/toolbox/Dockerfile`
  - toolbox image build instructions.

- `docker/toolbox/run_sqlmap_targets.sh`
  - containerized SQLMap runner helper.

- `docker/toolbox/run_live_compare.sh`
  - helper for containerized comparison flow.

## 6. Results and Reporting

- `results/`
  - simulation artifacts (CSV/PNG/JSON),
  - benchmark summaries.

- `results/live/`
  - raw live runner outputs,
  - merged cross-comparison files,
  - final report JSON/MD.

- `paper/sections_IV_V.tex`
  - paper sections bound to results and interpretation.

- `docs/my final.pdf.html`
  - rendered report/paper HTML artifact.

## 7. CI and Automation

- `.github/workflows/ci.yml`
  - automated validation workflow(s) for repository checks.

## 8. Fast Mapping by Task Type

- Modify strategic learning behavior:
  - `sqlirllm/qlearning.py`, `sqlirllm/reward.py`, `sqlirllm/framework.py`.

- Modify payload generation or WAF evasion:
  - `sqlirllm/payload_generator.py`.

- Modify analysis verdict logic:
  - `sqlirllm/analyzer.py`, plus live proof logic in `experiments/live/sqlirllm_runner.py`.

- Modify live target definitions/auth/session flows:
  - `experiments/live/sqlirllm_runner.py`, `experiments/live/sqlmap_runner.py`.

- Modify final report fields or aggregation logic:
  - `experiments/live/compare.py`, `run_full_report.sh`.

- Modify benchmark infrastructure:
  - `docker/docker-compose.yml`, toolbox scripts.
