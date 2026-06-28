# Operations Runbook

This runbook provides practical commands and expected outputs for operating the project.

## 1. Prerequisites

- Linux/macOS shell environment.
- Python 3.10+.
- Docker + Docker Compose plugin.
- Network access for model API (if live LLM mode enabled).

## 2. Initial Setup

1. Install Python dependencies:

```bash
pip install -r requirements.txt
```

2. Configure environment file:

```bash
cp .env.example .env
```

3. Set model API key in `.env` when required.

## 3. Start/Stop Docker Benchmark Stack

Start stack:

```bash
docker compose -f docker/docker-compose.yml up -d
```

Check status:

```bash
docker compose -f docker/docker-compose.yml ps
```

Stop and clean:

```bash
docker compose -f docker/docker-compose.yml down -v
```

## 4. Simulation-Only Execution

Primary simulation command:

```bash
python -m experiments.run_comparison --episodes 400 --targets 40 --seed 42
```

Expected output family:

- `results/summary.json`
- `results/comparison_quality.csv`
- `results/convergence.csv`
- `results/*.png` plots

## 5. Live-Only Execution

Run SQLMap baseline:

```bash
python -m experiments.live.sqlmap_runner
```

Run SQLiRLLM live benchmark:

```bash
python -m experiments.live.sqlirllm_runner
```

Merge and summarize:

```bash
python -m experiments.live.compare
```

Expected output family:

- `results/live/sqlmap_results.json`
- `results/live/sqlirllm_results.json`
- `results/live/cross_comparison.csv`
- `results/live/cross_summary.json`

## 6. Full End-to-End Pipeline

Default full pipeline:

```bash
./run_full_report.sh
```

Example tuned pipeline:

```bash
./run_full_report.sh \
  --skip-sim \
  --run-tools both \
  --live-targets "dvwa_sqli dvwa_sqli_medium dvwa_sqli_hard dvwa_sqli_max dvwa_waf sqli_labs_1 sqli_labs_11 bwapp_sqli juiceshop_login" \
  --sqlirllm-strategies "error_based,boolean_blind,union_based,time_blind" \
  --sqlirllm-max-attempts 2 \
  --sqlirllm-timeout 15 \
  --sqlmap-level 5 \
  --sqlmap-risk 3 \
  --sqlmap-technique BEUSTQ \
  --sqlmap-tamper "space2comment,charencode" \
  --sqlmap-threads 3
```

Final expected artifacts:

- `results/live/final_report.md`
- `results/live/final_report.json`

## 7. Validation Checklist After a Run

- Confirm both live JSON files exist.
- Confirm `cross_summary.json` contains `live_validated` section.
- Confirm `final_report.json` has run config and both tool summaries.
- Confirm documentation tables are synchronized with latest numbers.

## 8. Common Troubleshooting

## 8.1 Docker Services Not Ready

Symptoms:

- connection refused/timeouts for target URLs.

Actions:

1. `docker compose -f docker/docker-compose.yml ps`
2. `docker compose -f docker/docker-compose.yml logs --tail=200`
3. restart stack if needed.

## 8.2 Authentication-Dependent Targets Failing

Symptoms:

- DVWA/bWAPP responses return login/setup pages.

Actions:

1. ensure target setup helpers run in live runners,
2. verify cookie/session flow in `experiments/live/sqlirllm_runner.py` and `experiments/live/sqlmap_runner.py`,
3. verify host consistency (`127.0.0.1` vs `localhost`).

## 8.3 LLM/API Instability

Symptoms:

- intermittent API errors, high latency, missing model responses.

Actions:

1. use deterministic/offline-safe pathways where supported,
2. keep cache enabled unless testing cache behavior,
3. rerun with strict API flags only when debugging API integrity.

## 8.4 Stale Documentation After New Runs

Actions:

1. read `results/live/final_report.json` as canonical source,
2. update high-level docs and paper HTML,
3. grep for stale values (for example old detection rates).

## 9. Reproducibility Recommendations

- Fix seed values for comparable runs.
- Record all CLI flags used.
- Keep generated final report JSON with each benchmark run.
- Use same target set ordering for direct run-to-run comparison.
