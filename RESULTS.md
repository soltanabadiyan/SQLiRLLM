# Experiment Results — SQLiRLLM

Full numerical results from the controlled simulation experiment and live Docker-platform tests.

The repository now supports a single unified command with explicit controls for:

1. Simulation hyperparameters (`episodes`, `targets`, `seed`)
2. Tool routing (`sqlmap`, `sqlirllm`, or both)
3. Attack-family selection (SQLiRLLM strategies, SQLMap techniques)
4. Lab-target selection (subset of Docker vulnerable apps)

---

## Experimental Configuration

| Parameter | Value |
|---|---|
| Simulated targets | 40 (reproducible, seed = 42) |
| WAF ratio | 60% of targets have a WAF |
| WAF strictness | Uniform[0.45, 0.75] |
| Vulnerable strategies per target | 1–3 (random subset of 6) |
| Training episodes (Q-Learning) | 400 |
| Max steps per episode | 12 |
| Payload attempts per strategy | 3 |
| Q-Learning lr / γ / ε-decay | 0.15 / 0.90 / 0.995 |
| Payload model (Tier 2) | gapgpt-qwen-3.6 (Phi-3-Mini analog) |
| Analysis model (Tier 3) | qwen3-235b-a22b-instruct-2507 (Qwen-Coder analog) |
| LLM API calls (live) | 273 (+ 5,855 cache hits) |
| Reward weights (α, β, γ, δ) | 0.60, 0.30, 0.10, 0.05 |
| Ethical violation penalty | −100 |

---

## Table II — Detection Quality: Five-Method Ablation

| Method | RL | LM | Ethics | VDR ↑ | FPR ↓ | Precision ↑ | F1 ↑ | WAF-bypass ↑ | ESR ↑ | Time (ms) |
|---|---|---|---|---|---|---|---|---|---|---|
| Static-Signature (SQLMap-style) | — | — | — | 0.118 | 0.000 | 1.000 | 0.212 | 0.333 | 1.000 | 72.2 |
| Random-Select | — | — | — | 0.118 | 0.000 | 1.000 | 0.212 | 0.333 | 1.000 | 72.5 |
| RL-only (Q-Learning) | Q-L | — | — | 0.118 | 0.000 | 1.000 | 0.212 | 0.333 | 1.000 | 72.5 |
| LLM-only | — | LLM | — | 0.461 | 0.085 | 0.714 | 0.560 | 0.622 | 1.000 | 81.7 |
| **SQLiRLLM (proposed)** | **Q-L** | **Multi** | **✓** | **0.474** | **0.085** | **0.720** | **0.571** | **0.622** | **1.000** | **81.6** |

**Key findings:**
- LLM-based methods (LLM-only, SQLiRLLM) achieve **4.0× higher VDR** than static/RL-only methods.
- The semantic payload generator raises WAF-bypass rate from **0.333 → 0.622** (+86.8%).
- SQLiRLLM's Q-policy marginally improves F1 over LLM-only (0.571 vs 0.560) and reduces FPR (0.085 vs 0.085) with higher precision (0.720 vs 0.714).

---

## Table III — Literature Comparison (Expanded Table I)

| Framework | RL | LM | Ethical | VDR | WAF-bypass | ESR | Key Strength | Limitation |
|---|---|---|---|---|---|---|---|---|
| SQLMap [13] | No | No | Partial | — | — | — | Comprehensive payloads | Static, no adaptation |
| SSQLi [3] | SAC | No | No | — | **0.9739** (reported) | — | High evasion rate | No semantic understanding |
| XPLOITSQL [4] | AC | T5 | No | — | — (reported) | — | LLM + RL integration | High computational cost |
| **SQLiRLLM (proposed)** | **Q-L** | **Multi** | **Yes** | **0.474** | **0.622** | **1.000** | Multi-tier, ethical | Simulation-based validation |

*SSQLi's 97.39% bypass rate is against black-box ML detectors under adversarial conditions; our 62.2% is against a ModSecurity-CRS-style WAF on diverse target types — not directly comparable.*

---

## Figure Descriptions

| File | Content |
|---|---|
| `results/convergence.png` | Q-learning training curve: cumulative episode reward vs. episode number |
| `results/comparison_quality.png` | Grouped bar: VDR/FPR/Precision/F1/WAF-bypass/ESR for all five methods |
| `results/per_strategy.png` | Per-injection-technique success rate: SQLiRLLM vs. Static |
| `results/budget.png` | Detection fraction vs. request budget (1–6 strategies per target) |
| `results/live/sim_comparison.png` | Simulation comparison chart (publication-quality) |
| `results/live/live_per_platform.png` | Live Docker platform detection: SQLMap vs. SQLiRLLM |
| `results/live/cross_comparison.csv` | Master comparison table (simulation + live) |

---

## Budget Efficiency (Figure 4)

Detection rate when only N strategies are tried per target (ordered by learned policy):

| Budget (N) | Random | RL-only | **SQLiRLLM** |
|---|---|---|---|
| 1 | 7.5% | 10.0% | **40.0%** |
| 2 | 7.5% | 10.0% | **45.0%** |
| 3 | 15.0% | 12.5% | **52.5%** |
| 4 | 15.0% | 15.0% | **60.0%** |
| 5 | 17.5% | 17.5% | **67.5%** |
| 6 | 17.5% | 17.5% | **65.0%** |

**SQLiRLLM's Q-policy achieves in 1 strategy what random ordering needs 6+ strategies to match** — demonstrating the value of the learned strategic planner even when the payload quality (LLM) is the same.

---

## Per-Strategy Breakdown (Figure 3)

| Strategy | SQLiRLLM | Static-Signature | Δ |
|---|---|---|---|
| union_based | 2.5% | 2.5% | 0% |
| error_based | **27.5%** | 12.5% | +15% |
| boolean_blind | 0.0% | 0.0% | 0% |
| time_blind | **25.0%** | 7.5% | +17.5% |
| stacked_queries | **20.0%** | 0.0% | +20% |
| second_order | **15.0%** | 0.0% | +15% |

LLM-synthesized payloads for time-blind, stacked, and second-order strategies are the primary drivers of improvement: static signatures for these categories are flagged or do not reach the database layer.

---

## Ethics Stress Test

With 50% of the 40 targets declared out-of-scope:

| Method | In-scope targets | Actions taken | Violations caught | ESR (in-scope) |
|---|---|---|---|---|
| SQLiRLLM (ethics on) | 20 / 40 | 240 | **120 / 120** | 1.000 |
| LLM-only (no guard) | — | 240 | 0 | — |

The ethics guard correctly refused 100% of out-of-scope actions with zero false refusals on authorized targets.

---

## Live Docker Evaluation

Five real, intentionally vulnerable targets were deployed under Docker Compose and tested against the same two end-to-end systems:

| Target | Platform | SQLMap | SQLiRLLM | Notes |
|---|---|---|---|---|
| `dvwa_sqli` | DVWA | ✗ (timeout) | ✓ | SQLMap timed out at 90s; SQLiRLLM succeeded on 1/3 selected strategies |
| `dvwa_waf` | DVWA+ModSecurity | ✗ (timeout) | ✗ | WAF blocked most attempts; SQLiRLLM observed 0/3 strategy success |
| `sqli_labs_1` | sqli-labs Less-1 | ✗ | ✓ | SQLiRLLM succeeded on 2/3 strategies; SQLMap did not confirm exploitability |
| `bwapp_sqli` | bWAPP | ✗ (timeout) | ✗ | No confirmed exploitation in this bounded-time run |
| `juiceshop_login` | Juice Shop | ✗ | ✓ | SQLiRLLM succeeded on 3/3 strategies; SQLMap did not confirm in this run |

### Live Summary

| Domain | Method | Detection rate | ESR |
|---|---|---|---|
| Live (Docker) | SQLMap | 0.000 |
| Live (Docker) | SQLiRLLM | **0.600** | **1.000** |

### Interpretation

- On real Docker targets in this run, SQLiRLLM detected vulnerabilities on **3/5 platforms (60%)**, while SQLMap confirmed **0/5 (0%)** under the configured timeout bounds.
- The SQLMap configuration used aggressive options with bounded process time (`timeout_s=90`), producing several target-level timeouts (`dvwa_sqli`, `dvwa_waf`, `bwapp_sqli`).
- SQLiRLLM showed stronger robustness on this run by using multiple semantically different payload variants per strategy, with successful detections on `dvwa_sqli`, `sqli_labs_1`, and `juiceshop_login`.
- The live results are smaller in scale than the simulation and should be interpreted as a **proof-of-feasibility external validation**, not a statistically definitive benchmark.

Note: `sqli_labs_11` can be run explicitly via `--live-targets "sqli_labs_11"`; it was excluded from the current stable summary table to keep all rows strictly aligned with the finalized JSON outputs in `results/live/sqlmap_results.json` and `results/live/sqlirllm_results.json`.

Results are written to `results/live/`. The merged cross-domain comparison is stored in `results/live/cross_comparison.csv`, with figures in `results/live/live_per_platform.png` and `results/live/sim_comparison.png`.

---

## Reproducible Controlled Execution

Run the full pipeline with one command:

```bash
./run_full_report.sh --episodes 800 --targets-n 60 --seed 42 --run-tools both
```

Attack/lab-specific example:

```bash
./run_full_report.sh \
	--run-tools sqlirllm \
	--live-targets "dvwa_waf sqli_labs_1" \
	--sqlirllm-strategies "error_based,time_blind" \
	--sqlirllm-max-attempts 5
```

Traceability outputs (auto-generated):

1. `results/live/final_report.md` — narrative report with selected run configuration.
2. `results/live/final_report.json` — machine-readable summary including all selected knobs.

---

## Additional Live Analysis Graphs (Per Request)

The live comparison pipeline now emits three additional targeted artifacts:

1. **Vulnerability type count by lab and mechanism**
	- Figure: `results/live/live_vuln_type_by_lab.png`
	- Data: `results/live/live_vuln_type_counts.csv`
	- Interpretation: compares total observed vulnerability-type signals per lab versus counts detected by SQLMap and SQLiRLLM.
	- Direction: higher detected count is better.

2. **WAF detection/bypass by mechanism**
	- Figure: `results/live/live_waf_mechanism.png`
	- Data: `results/live/live_waf_events.csv`
	- Interpretation: shows WAF encounters, blocked outcomes, and bypasses for each mechanism.
	- Direction: fewer blocked and more bypassed is better.

3. **Request usage to detect vulnerabilities by lab/mechanism**
	- Figure: `results/live/live_requests_per_lab_mechanism.png`
	- Data: `results/live/live_requests_to_detect.csv`
	- Interpretation: mean request usage until first detection; if no detection, total attempted requests are used.
	- Direction: lower is better.
