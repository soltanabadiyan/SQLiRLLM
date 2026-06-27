#!/usr/bin/env bash
set -euo pipefail

cd /workspace

python -m experiments.live.sqlirllm_runner --targets dvwa_sqli sqli_labs_1 sqli_labs_11 bwapp_sqli juiceshop_login
python -m experiments.live.compare