# AI Editing Playbook

This playbook maps common change requests to exact edit locations and validation steps.

## 1. If User Asks to Improve Detection Quality

Likely touchpoints:

- `sqlirllm/payload_generator.py`
- `sqlirllm/analyzer.py`
- `experiments/live/sqlirllm_runner.py`

Typical actions:

1. improve payload variation/evasion logic,
2. refine proof or heuristic verdict logic,
3. tune attempts/timeouts/strategy subsets.

Validation:

- run `python -m experiments.live.sqlirllm_runner ...`
- compare before/after in `results/live/sqlirllm_results.json`.

## 2. If User Asks to Improve SQLMap Baseline Fairness

Likely touchpoints:

- `experiments/live/sqlmap_runner.py`

Typical actions:

1. align target URLs/params with current stack,
2. improve session/bootstrap setup,
3. tune SQLMap flags (level/risk/technique/tamper/threads).

Validation:

- run `python -m experiments.live.sqlmap_runner ...`
- confirm output parsing and detection summaries.

## 3. If User Asks for New Live Metrics

Likely touchpoints:

- `experiments/live/compare.py`
- `run_full_report.sh`

Typical actions:

1. add metric derivation in compare step,
2. persist metric in `cross_summary.json`,
3. include metric in final report JSON/MD.

Validation:

- run `python -m experiments.live.compare`
- run `./run_full_report.sh --skip-sim ...`
- inspect `results/live/final_report.json` fields.

## 4. If User Asks to Update Documentation After Rerun

Canonical source:

- `results/live/final_report.json`

Required sync targets:

- `README.md`
- `RESULTS.md`
- `IMPLEMENTATION_SUMMARY.md`
- `docs/my final.pdf.html`

Validation:

- grep stale numbers in edited docs.

## 5. If User Asks for Faster Runs

Likely touchpoints:

- `run_full_report.sh` (default args),
- `experiments/live/sqlirllm_runner.py` (analysis mode, attempts),
- `sqlirllm/llm_client.py` (cache/retry behavior).

Typical strategies:

1. reduce strategy set,
2. reduce max attempts,
3. keep deterministic analysis where appropriate,
4. optimize timeouts conservatively.

## 6. If User Asks for New Target Integration

Likely touchpoints:

- add target definition in both runners:
  - `experiments/live/sqlirllm_runner.py`
  - `experiments/live/sqlmap_runner.py`
- update docs and runbook target tables.

Checklist:

1. method/url/param/cookie/content-type defined,
2. expected vulnerability label defined,
3. session/bootstrap logic added if target requires auth,
4. compare pipeline handles new target consistently.

## 7. Do-Not-Break Rules

- keep result JSON schemas backward compatible unless deliberately migrated,
- keep target IDs stable when possible,
- do not mix source-of-truth metrics (always JSON first),
- preserve ethics/scope behavior,
- preserve reproducibility flags and seed flow.

## 8. Quick Triage Commands

```bash
# Check latest final metrics
python3 - <<'PY'
import json
from pathlib import Path
p=Path('results/live/final_report.json')
print(json.loads(p.read_text())['live'])
PY

# Rebuild merge artifacts only
python -m experiments.live.compare

# Full pipeline (reuse simulation)
SKIP_SIM=1 ./run_full_report.sh --run-tools both
```

## 9. Agent Completion Criteria

Before declaring completion, ensure:

1. code/docs changes are applied,
2. relevant outputs are regenerated,
3. stale values are checked,
4. user-requested files are all covered.
