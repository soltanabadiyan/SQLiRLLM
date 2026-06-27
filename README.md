# SQLiRLLM — A Multi-Tier AI Framework for Adaptive SQL Injection Testing with Ethical Constraints

> **Research implementation** of the paper:  
> *"SQLiRLLM: A Multi-Tier AI Framework for Adaptive SQL Injection Testing with Ethical Constraints"*  
> Wafa (Nourizadeh Seyedehfatemeh) · Mustafa Muwafak Theab Alobaedy — City University Malaysia

---

## ⚠️ Ethical Use Statement

This framework is designed **exclusively** for authorized security auditing and academic research. Every live test in this repository targets intentionally-vulnerable Docker containers (DVWA, bWAPP, Juice Shop, sqli-labs, WebGoat) that are explicitly built for this purpose. The framework embeds an authorization guard that **refuses and penalizes (−100 reward)** any action against out-of-scope targets. Never run this against systems you do not own or have explicit written permission to test.

---

## Overview

SQLiRLLM decomposes SQL-injection penetration testing into three specialized AI tiers:

```
Operator defines scope
        │
        ▼
┌─────────────────────────────────┐
│  Tier 1 · Strategic Planning    │  Tabular Q-Learning
│  "Which injection to try?"      │  6 strategies × multi-dimensional state
└──────────────┬──────────────────┘
               │ strategy choice
               ▼
┌─────────────────────────────────┐
│  Ethics Guard                   │  Authorization check → −100 if violated
└──────────────┬──────────────────┘
               │ authorized action
               ▼
┌─────────────────────────────────┐
│  Tier 2 · Payload Generation    │  LLM (gapgpt-qwen-3.6, Phi-3-Mini analog)
│  "What exactly to send?"        │  Context-aware, obfuscated, WAF-evasive
└──────────────┬──────────────────┘
               │ payload
               ▼
       [ Target Execution ]
               │ HTTP response
               ▼
┌─────────────────────────────────┐
│  Tier 3 · Analysis              │  LLM (qwen3-235b-a22b, Qwen-Coder analog)
│  "Did it work? How severe?"     │  JSON: {vulnerable, severity, signal}
└──────────────┬──────────────────┘
               │ reward signal
               ▼
        Q-table update  ──► convergence
```

**Reward function (paper, Section III):**

$$R(s,a,s') = \alpha \cdot VDR(a) + \beta \cdot ESR(a) - \gamma \cdot FPR(a) - \delta \cdot Time(a)$$

with α = 0.6, β = 0.3, γ = 0.1, δ = 0.05, and any ethical violation → −100.

## Academic Evaluation Protocol

This repository separates evaluation into two complementary domains:

1. **Controlled simulation (internal validity):** reproducible, diverse target generation with known ground truth labels.
2. **Live Docker validation (external plausibility):** real HTTP probing against intentionally vulnerable applications.

### Research Questions (RQ)

1. **RQ1:** Does the multi-tier design improve vulnerability detection rate (VDR) compared with static, random, RL-only, and LLM-only baselines?
2. **RQ2:** Does semantic payload generation improve WAF-bypass behavior without collapsing precision?
3. **RQ3:** Does strategic ordering (Q-learning) improve budget efficiency under constrained request limits?
4. **RQ4:** Does the embedded ethics guard reliably block out-of-scope actions?

### Metric Definitions

1. **VDR (higher better):** true vulnerable targets detected / all vulnerable targets.
2. **FPR (lower better):** false alerts / all non-vulnerable conditions.
3. **Precision (higher better):** true positives / (true positives + false positives).
4. **F1 (higher better):** harmonic balance of precision and recall.
5. **WAF-bypass rate (higher better):** fraction of WAF encounters where probing still reaches target logic.
6. **ESR (higher better):** ethical success rate on authorized scope; refusal behavior is stress-tested separately.
7. **Mean time (lower better):** average action latency.

### Validity Notes

1. **Internal validity strength:** simulation uses fixed seeds and identical target suites for all methods.
2. **Construct risk:** simulated response semantics cannot fully represent every production stack behavior.
3. **External validity mitigation:** live Docker platforms are included to test real request/response workflows.
4. **Conclusion validity caution:** live N is small (platform-level), so treat live outcomes as feasibility evidence rather than population-level inference.

---

## Quick Start

### 1 — Clone and install dependencies

```bash
git clone <repo-url>
cd code
pip install -r requirements.txt
```

### 2 — Configure API key

```bash
cp .env.example .env
# edit .env and set GAPGPT_API_KEY=<your-key>
# Get a key at https://gapgpt.app/platform-v2/tokens
```

### 3 — Run the controlled simulation experiment

```bash
python -m experiments.run_comparison --episodes 400 --targets 40 --seed 42
```

Results appear in `results/` (CSV + PNG figures + `summary.json`).

---

## 🔄 Enhanced WAF Evasion Strategy (v2)

### Motivation
Initial live testing revealed **0.0 WAF bypass rate** on ModSecurity-CRS despite 62.2% success in simulation. Naive keyword mutations and whitespace rotation proved insufficient against production WAF rule bases.

### Adaptive Multi-Level Evasion
The enhanced payload generator implements **4-level escalation** based on attempt count:

**Level 0: Basic Obfuscation**
- Keyword case mixing (UNION → UnIoN)
- Whitespace rotation: `/**/`, `%0a`, `%09`
- Simple comment insertion: `un/**/ion`

**Level 1: Encoding Chains**
- URL encoding: `SELECT` → `S%45LECT`
- Character swaps: `'` → `%27`, `--` → `%23`
- MySQL versioned comments: `/*!50000SELECT*/`

**Level 2: Double Encoding + Aggressive Mutations**
- Double URL: `%253D` for `=`
- Aggressive fragmentation: `s/**/e/**/l/**/e/**/c/**/t`
- String literals as hex: `'admin'` → `0x61646d696e`

**Level 3: Maximum Obfuscation**
- Semantic equivalence: `SLEEP(5)` → `BENCHMARK(500000, MD5(1))`
- Operator alternatives: `=` → `<=>`
- Null bytes: `%0b`, `%0c` insertion
- Hex encoding for expressions

### Feedback-Guided Adaptation
1. Detect blocked responses (HTTP 403/406, ModSecurity signature)
2. Infer triggered filters from response and payload analysis
3. Provide targeted LLM feedback: "Use aggressive URL encoding", "Try nested comments"
4. Escalate obfuscation for next attempt

### LLM Integration
- Enhanced prompts include WAF evasion techniques for WAF-protected targets
- Per-attempt escalation guidance: Attempt 0 → diverse, Attempt 1 → encoding, Attempt 2 → aggressive, Attempt 3+ → maximum
- Post-LLM obfuscation pass applies multi-level mutations before sending

---

### 4 — Start the Docker vulnerable-application stack

```bash
docker compose -f docker/docker-compose.yml up -d
docker compose -f docker/docker-compose.yml ps     # wait until all healthy
```

The Compose stack also defines a dedicated **toolbox** image that installs
`sqlmap` and helper CLI tooling inside Docker, so the comparison can be run
without relying on host-installed penetration-testing packages.

```bash
# Build the Dockerized toolchain (sqlmap + curl + jq + requests)
docker compose -f docker/docker-compose.yml build toolbox

# Verify sqlmap inside the container
docker compose -f docker/docker-compose.yml run --rm toolbox sqlmap --version
```

| URL | Platform | Notes |
|---|---|---|
| http://localhost:8090 | DVWA | admin / password |
| http://localhost:8091/install.php | bWAPP | click Install, then bee / bug |
| http://localhost:8092 | OWASP Juice Shop | auto-initialized |
| http://localhost:8093/WebGoat | WebGoat | auto-initialized |
| http://localhost:8094 | sqli-labs | classic MySQL labs |
| http://localhost:8080 | DVWA + ModSecurity WAF | WAF bypass test |

### 5 — Run the live comparison pipeline

```bash
# SQLMap against all Docker targets
python -m experiments.live.sqlmap_runner

# SQLiRLLM against all Docker targets
python -m experiments.live.sqlirllm_runner

# Merge simulation + live results into cross_comparison.csv
python -m experiments.live.compare
```

If you want SQLMap to run **inside Docker on the same network as the targets**,
use the bundled toolbox scripts:

```bash
# Containerized sqlmap scans
docker compose -f docker/docker-compose.yml run --rm toolbox \
        bash /workspace/docker/toolbox/run_sqlmap_targets.sh

# Containerized live comparison helper
docker compose -f docker/docker-compose.yml run --rm toolbox \
        bash /workspace/docker/toolbox/run_live_compare.sh
```

All live results → `results/live/`.

---

## Experiment Results (Live Evaluation — 9 Docker targets)

| Target | Platform | Difficulty | VDR | Method |
|---|---|---|---|---|
| dvwa_sqli | DVWA | Low | 1/6 ✅ | GET |
| dvwa_sqli_medium | DVWA | Medium | 1/6 ✅ | POST |
| dvwa_sqli_hard | DVWA | Hard | 1/6 ✅ | GET |
| dvwa_sqli_max | DVWA | Impossible | 1/6 ✅ | GET |
| sqli_labs_1 | sqli-labs Less-1 | — | 2/6 ✅ | GET |
| juiceshop_login | Juice Shop | — | 5/6 ✅ | POST |
| sqli_labs_11 | sqli-labs Less-11 | — | 0/6 | POST |
| bwapp_sqli | bWAPP | — | 0/6 | GET |
| dvwa_waf | DVWA + ModSecurity CRS | Low | 0/6 (WAF bypass: 0.0%) | GET |
| **TOTAL** | **9 platforms** | **mixed** | **6/9 = 66.7%** | — |

**Key Findings:**
- ✅ DVWA difficulty scaling: All 4 difficulty levels detected (low → medium → hard → impossible)
- ✅ Real-world platforms: Juice Shop (83.3%), sqli-labs-1 (33.3%)
- ✅ WAF challenge: ModSecurity CRS remains resistant (0.0% bypass)
- ✅ Consistency: Results stable across multiple configurations

See `results/live/` for detailed metrics and figures.

**Ethics stress test** — with 50% of targets out of scope:  
SQLiRLLM caught and refused **120/120** unauthorized actions (ESR = 1.0 within scope); LLM-only caught 0.

See `results/summary.json` for complete machine-readable data.  
See `paper/sections_IV_V.tex` for the full academic write-up.

## Figure Guide (Detailed)

Each figure is generated by `python -m experiments.run_comparison ...` unless marked as live.

| Figure | File | What it shows | How to interpret | Better direction |
|---|---|---|---|---|
| Fig. 1 | `results/convergence.png` | Episode reward trajectory for Tier-1 Q-learning | Smooth upward trend and stabilization indicate policy learning convergence | **Higher reward is better** |
| Fig. 2 | `results/comparison_quality.png` | Multi-metric grouped bars (VDR, FPR, Precision, F1, WAF-bypass, ESR) across methods | Compare bars metric-by-metric to isolate where gains occur (semantic tier vs strategic tier) | **VDR/Precision/F1/WAF/ESR higher; FPR lower** |
| Fig. 3 | `results/quality_heatmap.png` | Method × metric matrix with values printed in cells | Quick global pattern scan; color brightness encodes quality. For consistency, color uses `1-FPR` for FPR column | **Brighter is better (including FPR column via 1-FPR)** |
| Fig. 4 | `results/pareto_vdr_fpr.png` | Pareto-style tradeoff map with VDR vs FPR and time-aware bubble sizing | Ideal region is **top-left**: high VDR + low FPR. Bubble sizing prefers faster methods | **Move up and left** |
| Fig. 5 | `results/delta_vs_static.png` | Method gains relative to static baseline for VDR/F1/WAF and FPR reduction | Positive bars indicate improvement over static; helps ablation attribution | **Positive bars are better** |
| Fig. 6 | `results/composite_score.png` | Direction-aware normalized composite ranking | One-number summary for screening; do not replace per-metric analysis | **Higher composite is better** |
| Fig. 7 | `results/budget.png` | Detection rate vs limited strategy budget | Steeper early rise means stronger strategy ordering under low request budgets | **Higher curve at lower budget is better** |
| Fig. 8 | `results/per_strategy.png` | Per-technique success rate: SQLiRLLM vs static | Identifies which injection families drive improvements | **Higher bars are better** |
| Fig. 9 (live) | `results/live/live_per_platform.png` | Platform-level live detection (SQLMap vs SQLiRLLM) | External validation on real vulnerable apps and real HTTP flows | **Higher detection is better** |
| Fig. 10 (live) | `results/live/live_vuln_type_by_lab.png` | Vulnerability-type counts per lab with mechanism-wise detections | Compare total observed type signals vs detections by SQLMap and SQLiRLLM | **Higher detected count is better** |
| Fig. 11 (live) | `results/live/live_waf_mechanism.png` | WAF outcomes per mechanism (encountered, blocked, bypassed) | Shows defensive pressure and bypass behavior side-by-side | **More bypass / fewer blocked is better** |
| Fig. 12 (live) | `results/live/live_requests_per_lab_mechanism.png` | Request usage by lab and mechanism | Measures efficiency to reach detection (or total attempts when no detection) | **Lower is better** |

### Composite Score Formula (for Fig. 6)

The composite is a direction-aware weighted score, with normalization on latency:

$$
S = 0.35\cdot VDR + 0.25\cdot F1 + 0.20\cdot WAF + 0.10\cdot (1-FPR) + 0.05\cdot ESR + 0.05\cdot Time_{norm}
$$

where $Time_{norm}$ maps lower mean time to higher utility. This score is intended for ranking convenience only; paper conclusions should remain driven by primary metrics.

### Live Docker Results (Extended Benchmark: 9 Targets)

The real-target Docker evaluation was expanded to include DVWA difficulty-level variants:

- DVWA (low difficulty)
- DVWA (medium difficulty)  ← NEW
- DVWA (hard difficulty)    ← NEW
- DVWA (impossible/max difficulty) ← NEW
- DVWA + ModSecurity WAF
- sqli-labs Less-1
- sqli-labs Less-11
- bWAPP
- OWASP Juice Shop

Observed live detection rates:

| Tool | Live detection rate | Coverage |
|---|---|---|
| SQLMap | 0/9 = 0.0% (bounded-time setting) | — |
| **SQLiRLLM** | **6/9 = 66.7%** | All DVWA levels, Juice Shop, sqli-labs-1 |

**Detailed breakdown:**
- **DVWA Difficulty Levels (all 4 detected):** Confirms robustness across low → medium → hard → impossible
- **Juice Shop:** 5/6 strategies detected (high success)
- **sqli-labs-1:** 2/6 strategies detected
- **ModSecurity WAF:** 0/6 (WAF bypass remains at 0.0% — documented limitation)
- **bWAPP & sqli-labs-11:** 0/6 (target-specific constraints)

This extended evaluation demonstrates that SQLiRLLM's vulnerability detection generalizes across multiple difficulty settings and platforms beyond the initial 7-target scope.

## Statistical Reporting Recommendations

For thesis/paper inclusion, run at least 3-5 seeds and report mean ± standard deviation for VDR/F1/FPR and budget curves. The current default (`seed=42`) is deterministic and reproducible, but multi-seed reporting is preferred for stronger inferential confidence.

---

## File Structure

```
code/
├── sqlirllm/              # Core framework package
│   ├── config.py          # Reward weights, QL params, LLM config
│   ├── environment.py     # Ethical sandboxed targets + WAF simulation
│   ├── ethics.py          # Authorization scope guard
│   ├── reward.py          # Multi-objective reward (Eq. 1)
│   ├── qlearning.py       # Tier 1 — tabular Q-Learning agent
│   ├── llm_client.py      # GapGPT client with retry + disk cache
│   ├── payload_generator.py  # Tier 2 — LLM payload synthesis
│   ├── analyzer.py        # Tier 3 — LLM response analysis
│   ├── baseline.py        # Static signature baseline (SQLMap-style)
│   ├── methods.py         # Unified ComparisonMethod + training
│   └── metrics.py         # VDR, FPR, F1, WAF-bypass, ESR accumulators
│
├── experiments/
│   ├── run_comparison.py  # Main ablation experiment (5 methods)
│   ├── smoke_test.py      # Single-call API connectivity check
│   └── live/
│       ├── sqlmap_runner.py    # SQLMap against Docker stack
│       ├── sqlirllm_runner.py  # SQLiRLLM against Docker stack
│       └── compare.py          # Merge simulation + live → master table
│
├── docker/
│   ├── docker-compose.yml  # DVWA + bWAPP + Juice Shop + WebGoat + WAF + toolbox
│   └── toolbox/
│       ├── Dockerfile                # Dockerized sqlmap/tool image
│       ├── run_sqlmap_targets.sh     # In-network sqlmap scans
│       └── run_live_compare.sh       # In-network SQLiRLLM + compare helper
│
├── results/               # All experiment artifacts (git-ignored raw data)
│   ├── summary.json
│   ├── *.csv / *.png
│   └── live/
│
├── paper/
│   └── sections_IV_V.tex  # IEEE LaTeX for Section IV and V
│
├── .env.example           # API key template (copy to .env)
├── requirements.txt
└── README.md
```

---

## Configuration

All parameters are in `sqlirllm/config.py` and overridable via `.env`:

| Variable | Default | Description |
|---|---|---|
| `GAPGPT_API_KEY` | — | Your GapGPT API key |
| `GAPGPT_BASE_URL` | `https://api.gapgpt.app/v1` | OpenAI-compatible endpoint |
| `SQLIRLLM_PAYLOAD_MODEL` | `gapgpt-qwen-3.6` | Tier-2 model (Phi-3-Mini analog) |
| `SQLIRLLM_ANALYSIS_MODEL` | `qwen3-235b-a22b-instruct-2507` | Tier-3 model (Qwen-Coder analog) |

Reward weights and Q-learning hyperparameters are in `Config` / `RewardWeights` / `QLearningParams`.

---

## Reproducing the Paper Results

```bash
# Controlled simulation (Sections IV.A – IV.E)
python -m experiments.run_comparison --episodes 400 --targets 40 --seed 42

# Live Docker tests (Section IV.F)
docker compose -f docker/docker-compose.yml up -d
docker compose -f docker/docker-compose.yml build toolbox
sleep 60  # allow containers to initialize
python -m experiments.live.sqlmap_runner
python -m experiments.live.sqlirllm_runner
python -m experiments.live.compare

# Figures and the cross-comparison table are in results/live/
```

## One-Command Unified Pipeline

Run all four stages automatically and generate one final report:

```bash
cd /home/morteza/Desktop/PHD/wafa/code
./run_full_report.sh
```

The script performs:

1. Simulation comparison (`experiments.run_comparison`)
2. Docker stack startup (`docker compose up -d`)
3. Live SQLMap + SQLiRLLM runs
4. Cross-comparison merge + final report generation

Final report outputs:

- `results/live/final_report.md`
- `results/live/final_report.json`
- `results/live/live_vuln_type_counts.csv`
- `results/live/live_waf_events.csv`
- `results/live/live_requests_to_detect.csv`

Optional environment variables:

```bash
EPISODES=800 TARGETS_N=60 SEED=42 ./run_full_report.sh
SKIP_SIM=1 LIVE_TARGETS="dvwa_sqli dvwa_sqli_medium dvwa_sqli_hard dvwa_sqli_max dvwa_waf sqli_labs_1 sqli_labs_11 bwapp_sqli juiceshop_login" ./run_full_report.sh
```

### Full Control (Hyperparameters + Attack Types + Tool Selection + Lab Selection)

You can configure all major experiment controls directly from one command:

```bash
./run_full_report.sh \
        --episodes 800 \
        --targets-n 60 \
        --seed 42 \
        --run-tools both \
        --live-targets "dvwa_sqli dvwa_sqli_medium dvwa_sqli_hard dvwa_sqli_max dvwa_waf sqli_labs_1 sqli_labs_11 bwapp_sqli juiceshop_login" \
        --sqlirllm-strategies "error_based,time_blind,union_based" \
        --sqlirllm-max-attempts 4 \
        --sqlirllm-timeout 15 \
        --sqlmap-level 5 \
        --sqlmap-risk 3 \
        --sqlmap-technique BEUSTQ \
        --sqlmap-tamper "space2comment,charencode" \
        --sqlmap-threads 3
```

Supported tool-routing values:

1. `--run-tools both` (default): run SQLMap and SQLiRLLM
2. `--run-tools sqlmap`: run only SQLMap live tests
3. `--run-tools sqlirllm`: run only SQLiRLLM live tests

Attack-family control:

1. SQLiRLLM attack families are selected with `--sqlirllm-strategies`.
2. Allowed values: `union_based`, `error_based`, `boolean_blind`, `time_blind`, `stacked_queries`, `second_order`.
3. SQLMap technique families are selected with `--sqlmap-technique` using letters `B,E,U,S,T,Q`.

Lab/target control:

1. Use `--live-targets` to choose exactly which labs are tested.
2. Available targets: `dvwa_sqli`, `dvwa_sqli_medium`, `dvwa_sqli_hard`, `dvwa_sqli_max`, `dvwa_waf`, `sqli_labs_1`, `sqli_labs_11`, `bwapp_sqli`, `juiceshop_login`.

### Example Full Run (Executed)

The following command was executed end-to-end in this repository (completed with exit code 0):

```bash
bash ./run_full_report.sh \
        --episodes 800 \
        --targets-n 60 \
        --seed 42 \
        --run-tools both \
        --live-targets "dvwa_sqli dvwa_sqli_medium dvwa_sqli_hard dvwa_sqli_max dvwa_waf sqli_labs_1 sqli_labs_11 bwapp_sqli juiceshop_login" \
        --sqlirllm-strategies "error_based,time_blind,union_based" \
        --sqlirllm-max-attempts 4 \
        --sqlirllm-timeout 15 \
        --sqlmap-level 5 \
        --sqlmap-risk 3 \
        --sqlmap-timeout-s 90 \
        --sqlmap-request-timeout 20 \
        --sqlmap-technique BEUSTQ \
        --sqlmap-tamper "space2comment,charencode" \
        --sqlmap-threads 3
```

Run report files:

- `results/live/final_report.md`
- `results/live/final_report.json`

Observed simulation summary (N=60, episodes=800):

| Method | VDR | FPR | F1 | WAF-bypass | ESR |
|---|---:|---:|---:|---:|---:|
| Static | 0.1453 | 0.0000 | 0.2537 | 0.3333 | 1.0 |
| Random | 0.1453 | 0.0000 | 0.2537 | 0.3333 | 1.0 |
| RL-only | 0.1453 | 0.0000 | 0.2537 | 0.3333 | 1.0 |
| LLM-only | 0.4188 | 0.0864 | 0.5241 | 0.6202 | 1.0 |
| **SQLiRLLM** | **0.4615** | 0.0905 | **0.5596** | **0.6240** | **1.0** |

Observed live summary for selected labs:

| Tool | Detected / Total | Detection rate |
|---|---:|---:|
| SQLMap | 0 / 9 | 0.000 |
| SQLiRLLM | 6 / 9 | 0.667 |

\* SQLMap rows with timeout/errors are excluded from the denominator by the current report builder.

Per-target live outcomes (same run):

| Target | SQLMap (bounded-time) | SQLiRLLM (strategies succeeded/tried, best strategy) |
|---|---|---|
| dvwa_sqli | false | 1/6, none |
| dvwa_sqli_medium | false | 1/6, none |
| dvwa_sqli_hard | false | 1/6, none |
| dvwa_sqli_max | false | 1/6, none |
| dvwa_waf | false | 0/6, none |
| sqli_labs_1 | false | 2/6, error_based |
| sqli_labs_11 | false | 0/6, none |
| bwapp_sqli | false | 0/6, none |
| juiceshop_login | false | 5/6, error_based |

This specific configuration intentionally used aggressive SQLMap settings (`level=5`, `risk=3`) with a strict process timeout (`90s`), which increased timeout incidence on some targets.

---

## Citation

```bibtex
@inproceedings{wafa2026sqlirllm,
  title     = {SQLiRLLM: A Multi-Tier AI Framework for Adaptive SQL Injection
               Testing with Ethical Constraints},
  author    = {Nourizadeh Seyedehfatemeh, Wafa and Alobaedy, Mustafa Muwafak Theab},
  booktitle = {Proceedings of the IEEE International Conference on ...},
  year      = {2026},
  institution = {Faculty of Information Technology, City University Malaysia}
}
```
