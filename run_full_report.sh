#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

EPISODES="${EPISODES:-400}"
TARGETS_N="${TARGETS_N:-40}"
SEED="${SEED:-42}"
SKIP_SIM="${SKIP_SIM:-0}"
LIVE_TARGETS="${LIVE_TARGETS:-dvwa_sqli sqli_labs_1 sqli_labs_11 bwapp_sqli juiceshop_login}"
COMPOSE_FILE="${COMPOSE_FILE:-docker/docker-compose.yml}"
RUN_TOOLS="${RUN_TOOLS:-both}"            # both | sqlmap | sqlirllm
SQLIRLLM_STRATEGIES="${SQLIRLLM_STRATEGIES:-}"  # e.g. error_based,time_blind
SQLIRLLM_MAX_ATTEMPTS="${SQLIRLLM_MAX_ATTEMPTS:-3}"
SQLIRLLM_REQUEST_TIMEOUT="${SQLIRLLM_REQUEST_TIMEOUT:-12}"
SQLIRLLM_NO_CACHE="${SQLIRLLM_NO_CACHE:-0}"
SQLIRLLM_STRICT_API="${SQLIRLLM_STRICT_API:-0}"
SQLIRLLM_VERIFY_API_PING="${SQLIRLLM_VERIFY_API_PING:-0}"
SQLMAP_LEVEL="${SQLMAP_LEVEL:-3}"
SQLMAP_RISK="${SQLMAP_RISK:-2}"
SQLMAP_TIMEOUT_S="${SQLMAP_TIMEOUT_S:-180}"
SQLMAP_REQUEST_TIMEOUT="${SQLMAP_REQUEST_TIMEOUT:-30}"
SQLMAP_TECHNIQUE="${SQLMAP_TECHNIQUE:-}"
SQLMAP_TAMPER="${SQLMAP_TAMPER:-}"
SQLMAP_THREADS="${SQLMAP_THREADS:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --episodes) EPISODES="$2"; shift 2 ;;
    --targets-n) TARGETS_N="$2"; shift 2 ;;
    --seed) SEED="$2"; shift 2 ;;
    --skip-sim) SKIP_SIM="1"; shift ;;
    --live-targets) LIVE_TARGETS="$2"; shift 2 ;;
    --run-tools) RUN_TOOLS="$2"; shift 2 ;;
    --sqlirllm-strategies) SQLIRLLM_STRATEGIES="$2"; shift 2 ;;
    --sqlirllm-max-attempts) SQLIRLLM_MAX_ATTEMPTS="$2"; shift 2 ;;
    --sqlirllm-timeout) SQLIRLLM_REQUEST_TIMEOUT="$2"; shift 2 ;;
    --sqlirllm-no-cache) SQLIRLLM_NO_CACHE="1"; shift ;;
    --sqlirllm-strict-api) SQLIRLLM_STRICT_API="1"; shift ;;
    --sqlirllm-verify-api-ping) SQLIRLLM_VERIFY_API_PING="1"; shift ;;
    --sqlmap-level) SQLMAP_LEVEL="$2"; shift 2 ;;
    --sqlmap-risk) SQLMAP_RISK="$2"; shift 2 ;;
    --sqlmap-timeout-s) SQLMAP_TIMEOUT_S="$2"; shift 2 ;;
    --sqlmap-request-timeout) SQLMAP_REQUEST_TIMEOUT="$2"; shift 2 ;;
    --sqlmap-technique) SQLMAP_TECHNIQUE="$2"; shift 2 ;;
    --sqlmap-tamper) SQLMAP_TAMPER="$2"; shift 2 ;;
    --sqlmap-threads) SQLMAP_THREADS="$2"; shift 2 ;;
    -h|--help)
      cat <<'EOF'
Usage: ./run_full_report.sh [options]

Simulation controls:
  --episodes N
  --targets-n N
  --seed N
  --skip-sim

Lab/tool controls:
  --live-targets "t1 t2 ..."
  --run-tools both|sqlmap|sqlirllm

SQLiRLLM live controls:
  --sqlirllm-strategies "error_based,time_blind"
  --sqlirllm-max-attempts N
  --sqlirllm-timeout SECONDS
  --sqlirllm-no-cache
  --sqlirllm-strict-api
  --sqlirllm-verify-api-ping

SQLMap live controls:
  --sqlmap-level N
  --sqlmap-risk N
  --sqlmap-timeout-s N
  --sqlmap-request-timeout N
  --sqlmap-technique BEUSTQ
  --sqlmap-tamper "space2comment,charencode"
  --sqlmap-threads N
EOF
      exit 0
      ;;
    *)
      echo "[error] Unknown option: $1"
      echo "        Run ./run_full_report.sh --help"
      exit 1
      ;;
  esac
done

if [[ "$RUN_TOOLS" != "both" && "$RUN_TOOLS" != "sqlmap" && "$RUN_TOOLS" != "sqlirllm" ]]; then
  echo "[error] RUN_TOOLS must be one of: both, sqlmap, sqlirllm"
  exit 1
fi

read -r -a LIVE_TARGETS_ARR <<< "$LIVE_TARGETS"

echo "[SQLiRLLM] Unified pipeline started"
echo "  episodes=${EPISODES} targets_n=${TARGETS_N} seed=${SEED} skip_sim=${SKIP_SIM}"
echo "  live_targets=${LIVE_TARGETS}"
echo "  run_tools=${RUN_TOOLS}"
echo "  sqlirllm_strategies=${SQLIRLLM_STRATEGIES:-all} max_attempts=${SQLIRLLM_MAX_ATTEMPTS} timeout=${SQLIRLLM_REQUEST_TIMEOUT}s"
echo "  sqlirllm_no_cache=${SQLIRLLM_NO_CACHE} strict_api=${SQLIRLLM_STRICT_API} verify_api_ping=${SQLIRLLM_VERIFY_API_PING}"
echo "  sqlmap_level=${SQLMAP_LEVEL} risk=${SQLMAP_RISK} technique=${SQLMAP_TECHNIQUE:-default}"

# --------------------------------------------------------------------------- #
# Step 1/4: Controlled simulation (for Section IV artifacts and baseline CSVs)
# --------------------------------------------------------------------------- #
if [[ "$SKIP_SIM" == "1" ]]; then
  if [[ ! -f "results/summary.json" ]]; then
    echo "[error] SKIP_SIM=1 but results/summary.json is missing."
    echo "        Re-run with SKIP_SIM=0 (default) to generate simulation outputs."
    exit 1
  fi
  echo "[1/4] Skipping simulation; reusing existing results/summary.json"
else
  echo "[1/4] Running simulation comparison"
  python -m experiments.run_comparison \
    --episodes "$EPISODES" \
    --targets "$TARGETS_N" \
    --seed "$SEED"
fi

# --------------------------------------------------------------------------- #
# Step 2/4: Start live Docker stack
# --------------------------------------------------------------------------- #
echo "[2/4] Starting Docker stack"
docker compose -f "$COMPOSE_FILE" up -d
docker compose -f "$COMPOSE_FILE" ps

# --------------------------------------------------------------------------- #
# Step 3/4: Run live baselines and proposed method
# --------------------------------------------------------------------------- #
echo "[3/4] Running selected live tools"
if [[ "$RUN_TOOLS" == "both" || "$RUN_TOOLS" == "sqlmap" ]]; then
  SQLMAP_CMD=(
    python -m experiments.live.sqlmap_runner
    --targets "${LIVE_TARGETS_ARR[@]}"
    --level "$SQLMAP_LEVEL"
    --risk "$SQLMAP_RISK"
    --timeout-s "$SQLMAP_TIMEOUT_S"
    --request-timeout "$SQLMAP_REQUEST_TIMEOUT"
  )
  if [[ -n "$SQLMAP_TECHNIQUE" ]]; then
    SQLMAP_CMD+=(--technique "$SQLMAP_TECHNIQUE")
  fi
  if [[ -n "$SQLMAP_TAMPER" ]]; then
    SQLMAP_CMD+=(--tamper "$SQLMAP_TAMPER")
  fi
  if [[ -n "$SQLMAP_THREADS" ]]; then
    SQLMAP_CMD+=(--threads "$SQLMAP_THREADS")
  fi
  "${SQLMAP_CMD[@]}"
fi

if [[ "$RUN_TOOLS" == "both" || "$RUN_TOOLS" == "sqlirllm" ]]; then
  SQLIRLLM_CMD=(
    python -m experiments.live.sqlirllm_runner
    --targets "${LIVE_TARGETS_ARR[@]}"
    --max-attempts "$SQLIRLLM_MAX_ATTEMPTS"
    --request-timeout "$SQLIRLLM_REQUEST_TIMEOUT"
    --seed "$SEED"
  )
  if [[ -n "$SQLIRLLM_STRATEGIES" ]]; then
    IFS=',' read -r -a STRAT_ARR <<< "$SQLIRLLM_STRATEGIES"
    SQLIRLLM_CMD+=(--strategies "${STRAT_ARR[@]}")
  fi
  if [[ "$SQLIRLLM_NO_CACHE" == "1" ]]; then
    SQLIRLLM_CMD+=(--no-llm-cache)
  fi
  if [[ "$SQLIRLLM_STRICT_API" == "1" ]]; then
    SQLIRLLM_CMD+=(--strict-llm-api)
  fi
  if [[ "$SQLIRLLM_VERIFY_API_PING" == "1" ]]; then
    SQLIRLLM_CMD+=(--verify-api-ping)
  fi
  "${SQLIRLLM_CMD[@]}"
fi

# --------------------------------------------------------------------------- #
# Step 4/4: Aggregate and emit final report
# --------------------------------------------------------------------------- #
echo "[4/4] Building cross-comparison artifacts and final report"
python -m experiments.live.compare

export SQLIRLLM_REPORT_EPISODES="$EPISODES"
export SQLIRLLM_REPORT_TARGETS_N="$TARGETS_N"
export SQLIRLLM_REPORT_SEED="$SEED"
export SQLIRLLM_REPORT_SKIP_SIM="$SKIP_SIM"
export SQLIRLLM_REPORT_RUN_TOOLS="$RUN_TOOLS"
export SQLIRLLM_REPORT_LIVE_TARGETS="$LIVE_TARGETS"
export SQLIRLLM_REPORT_SQLIRLLM_STRATEGIES="$SQLIRLLM_STRATEGIES"
export SQLIRLLM_REPORT_SQLIRLLM_MAX_ATTEMPTS="$SQLIRLLM_MAX_ATTEMPTS"
export SQLIRLLM_REPORT_SQLIRLLM_TIMEOUT="$SQLIRLLM_REQUEST_TIMEOUT"
export SQLIRLLM_REPORT_SQLMAP_LEVEL="$SQLMAP_LEVEL"
export SQLIRLLM_REPORT_SQLMAP_RISK="$SQLMAP_RISK"
export SQLIRLLM_REPORT_SQLMAP_TIMEOUT_S="$SQLMAP_TIMEOUT_S"
export SQLIRLLM_REPORT_SQLMAP_REQUEST_TIMEOUT="$SQLMAP_REQUEST_TIMEOUT"
export SQLIRLLM_REPORT_SQLMAP_TECHNIQUE="$SQLMAP_TECHNIQUE"
export SQLIRLLM_REPORT_SQLMAP_TAMPER="$SQLMAP_TAMPER"
export SQLIRLLM_REPORT_SQLMAP_THREADS="$SQLMAP_THREADS"

python - <<'PY'
import json
import os
from datetime import datetime, timezone
from pathlib import Path

root = Path.cwd()
results = root / "results"
live = results / "live"
live.mkdir(parents=True, exist_ok=True)

summary_path = results / "summary.json"
sqlmap_path = live / "sqlmap_results.json"
sqli_path = live / "sqlirllm_results.json"

summary = json.loads(summary_path.read_text()) if summary_path.exists() else {}
sqlmap_rows = json.loads(sqlmap_path.read_text()) if sqlmap_path.exists() else []
sqli_rows = json.loads(sqli_path.read_text()) if sqli_path.exists() else []

def det_rate(rows, key):
    clean = [r for r in rows if not r.get("error")]
    if not clean:
        return 0, 0, 0.0
    det = sum(1 for r in clean if bool(r.get(key, False)))
    return det, len(clean), det / len(clean)

sqlmap_det, sqlmap_total, sqlmap_rate = det_rate(sqlmap_rows, "vulnerable_detected")
sqli_det = sum(1 for r in sqli_rows if (not r.get("error")) and (r.get("strategies_succeeded", 0) > 0))
sqli_clean = [r for r in sqli_rows if not r.get("error")]
sqli_total = len(sqli_clean)
sqli_rate = (sqli_det / sqli_total) if sqli_total else 0.0

quality = summary.get("quality", {})
proposed = quality.get("SQLiRLLM", {})

report_md = live / "final_report.md"
timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
run_cfg = {
  "episodes": os.getenv("SQLIRLLM_REPORT_EPISODES"),
  "targets_n": os.getenv("SQLIRLLM_REPORT_TARGETS_N"),
  "seed": os.getenv("SQLIRLLM_REPORT_SEED"),
  "skip_sim": os.getenv("SQLIRLLM_REPORT_SKIP_SIM"),
  "run_tools": os.getenv("SQLIRLLM_REPORT_RUN_TOOLS"),
  "live_targets": os.getenv("SQLIRLLM_REPORT_LIVE_TARGETS"),
  "sqlirllm_strategies": os.getenv("SQLIRLLM_REPORT_SQLIRLLM_STRATEGIES") or "all",
  "sqlirllm_max_attempts": os.getenv("SQLIRLLM_REPORT_SQLIRLLM_MAX_ATTEMPTS"),
  "sqlirllm_timeout_s": os.getenv("SQLIRLLM_REPORT_SQLIRLLM_TIMEOUT"),
  "sqlmap_level": os.getenv("SQLIRLLM_REPORT_SQLMAP_LEVEL"),
  "sqlmap_risk": os.getenv("SQLIRLLM_REPORT_SQLMAP_RISK"),
  "sqlmap_timeout_s": os.getenv("SQLIRLLM_REPORT_SQLMAP_TIMEOUT_S"),
  "sqlmap_request_timeout_s": os.getenv("SQLIRLLM_REPORT_SQLMAP_REQUEST_TIMEOUT"),
  "sqlmap_technique": os.getenv("SQLIRLLM_REPORT_SQLMAP_TECHNIQUE") or "default",
  "sqlmap_tamper": os.getenv("SQLIRLLM_REPORT_SQLMAP_TAMPER") or "target-default",
  "sqlmap_threads": os.getenv("SQLIRLLM_REPORT_SQLMAP_THREADS") or "default",
}

content = f"""# SQLiRLLM Unified Final Report

Generated: {timestamp}

## Pipeline Summary

This report was generated by a single command pipeline that executes:

1. Controlled simulation (`experiments.run_comparison`)
2. Docker live stack startup (`docker compose up -d`)
3. Live scans (`experiments.live.sqlmap_runner` and `experiments.live.sqlirllm_runner`)
4. Cross-domain aggregation (`experiments.live.compare`)

## Run Configuration

- Simulation episodes: {run_cfg['episodes']}
- Simulation targets: {run_cfg['targets_n']}
- Seed: {run_cfg['seed']}
- Skip simulation: {run_cfg['skip_sim']}
- Selected live tools: {run_cfg['run_tools']}
- Selected lab targets: {run_cfg['live_targets']}
- SQLiRLLM strategies: {run_cfg['sqlirllm_strategies']}
- SQLiRLLM max attempts/strategy: {run_cfg['sqlirllm_max_attempts']}
- SQLiRLLM request timeout (s): {run_cfg['sqlirllm_timeout_s']}
- SQLMap level/risk: {run_cfg['sqlmap_level']} / {run_cfg['sqlmap_risk']}
- SQLMap technique: {run_cfg['sqlmap_technique']}
- SQLMap tamper: {run_cfg['sqlmap_tamper']}
- SQLMap process timeout (s): {run_cfg['sqlmap_timeout_s']}
- SQLMap request timeout (s): {run_cfg['sqlmap_request_timeout_s']}
- SQLMap threads: {run_cfg['sqlmap_threads']}

## Simulation Highlights (SQLiRLLM)

- VDR (higher better): {proposed.get('VDR', 'NA')}
- FPR (lower better): {proposed.get('FPR', 'NA')}
- F1 (higher better): {proposed.get('F1', 'NA')}
- WAF-bypass (higher better): {proposed.get('WAF_bypass_rate', 'NA')}
- ESR (higher better): {proposed.get('ESR', 'NA')}

## Live Highlights

- SQLMap detection: {sqlmap_det}/{sqlmap_total} = {sqlmap_rate:.3f}
- SQLiRLLM detection: {sqli_det}/{sqli_total} = {sqli_rate:.3f}

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
"""

report_md.write_text(content)

report_json = live / "final_report.json"
report_json.write_text(json.dumps({
    "generated_utc": timestamp,
  "run_config": run_cfg,
    "simulation": {"SQLiRLLM": proposed},
    "live": {
        "SQLMap": {"detected": sqlmap_det, "total": sqlmap_total, "rate": round(sqlmap_rate, 4)},
        "SQLiRLLM": {"detected": sqli_det, "total": sqli_total, "rate": round(sqli_rate, 4)},
    },
    "artifacts": {
        "summary": "results/summary.json",
        "cross_csv": "results/live/cross_comparison.csv",
        "cross_summary": "results/live/cross_summary.json",
        "report_md": "results/live/final_report.md",
    },
}, indent=2))

print(f"[report] Wrote {report_md}")
print(f"[report] Wrote {report_json}")
PY

echo
echo "[done] Unified pipeline complete"
echo "[done] Final report: results/live/final_report.md"