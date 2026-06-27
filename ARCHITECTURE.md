# Architecture — SQLiRLLM

## Design Principles

SQLiRLLM is built around three engineering choices directly motivated by gaps in the prior art (Section II):

1. **Task decomposition over monolithic models** — Each phase of a penetration test requires different capabilities. Selecting a strategy requires interpretable, lightweight decision-making. Writing an evasive payload requires semantic depth. Interpreting a multi-kilobyte HTTP response requires analytical reasoning. Assigning all three to one model either wastes capacity or forces a quality trade-off.

2. **Right-sized models per tier** — Tier 1 uses a parameter-free tabular agent. Tier 2 uses a sub-4B LLM fine-tuned via LoRA (~0.5% of params). Tier 3 uses a larger reasoning model invoked selectively on batches. This matches computational cost to task complexity.

3. **Ethics-first design** — Authorization is not a post-hoc filter. It is a hard constraint wired into the reward function so the agent is *trained* to refuse out-of-scope actions, not just blocked at runtime.

---

## Component Map

```
sqlirllm/
│
├── config.py
│     RewardWeights     α=0.6  β=0.3  γ=0.1  δ=0.05  penalty=-100
│     QLearningParams   lr=0.15  γ=0.90  ε-decay=0.995
│     LLMConfig         payload_model / analysis_model / allow_offline_fallback
│
├── environment.py
│     WAF               signature matching + evasion-score bypass logic
│     SimulatedTarget   execute(strategy, payload) → ExecutionResponse
│     build_target_suite(n, seed, waf_ratio) → List[SimulatedTarget]
│
├── ethics.py
│     EthicsGuard       authorize(target_id, strategy) → EthicsReport
│                       safeguard_rating (ESR) property
│
├── reward.py
│     ActionSignals     detected_true_vuln / ethically_compliant / false_positive / latency_ms
│     compute_reward()  implements Eq. (1) from the paper
│
├── qlearning.py  [TIER 1]
│     QLearningAgent    select(state, explore) — ε-greedy
│                       update(s,a,r,s′)       — Q-update
│                       ranked_strategies(s)   — policy order for budget eval
│
├── llm_client.py
│     LLMClient         chat(model, system, user, temperature) → str | None
│                       SHA-256 disk cache + bounded retry + offline fallback
│
├── payload_generator.py  [TIER 2]
│     PayloadGenerator  generate(strategy, context, attempt) → payload
│                       _offline(strategy)  — obfuscated template fallback
│
├── analyzer.py  [TIER 3]
│     Analyzer          analyze(strategy, response) → AnalysisResult
│                       {vulnerable, severity, signal, used_llm}
│                       latency bucketed to 100 ms for cache efficiency
│
├── baseline.py
│     StaticBaseline    canonical_payload(strategy) / canonical_payloads(strategy)
│
├── methods.py
│     ComparisonMethod  evaluate_coverage() / evaluate_budget()
│     train_policy()    trains QLearningAgent in simulation
│     canonical_provider / fixed_order / make_random_order / make_policy_order
│
└── metrics.py
      MetricAccumulator  tp/fp/tn/fn → VDR, FPR, Precision, F1, ESR, WAF-bypass
```

---

## State Space Encoding

The Q-table key is a 4-tuple: `(framework, database, waf, phase)`.

| Dimension | Values |
|---|---|
| framework | laravel, django, express, flask, rails |
| database | mysql, postgresql, oracle, mssql, sqlite |
| waf | present, absent |
| phase | initial, refinement, exploitation, verification |

Maximum distinct states: 5 × 5 × 2 × 4 = **200**. Actual observed in experiments: **76** (sparse coverage is expected and handled by defaulting to 0).

## Action Space

| Strategy | Injection category |
|---|---|
| union_based | UNION SELECT exfiltration |
| error_based | Database error leakage |
| boolean_blind | Differential true/false responses |
| time_blind | Deliberate sleep/delay signal |
| stacked_queries | Multiple statements in one call |
| second_order | Stored-value execution on retrieval |

## Q-Update Rule

$$Q(s,a) \leftarrow Q(s,a) + \alpha \left[ r + \gamma \max_{a'} Q(s',a') - Q(s,a) \right]$$

with α = 0.15, γ = 0.90. ε decays multiplicatively (0.995 per episode) from 1.0 → 0.05.

---

## Data Flow — Live Evaluation

```
Docker stack (DVWA, bWAPP, sqli-labs, Juice Shop, WebGoat, DVWA+ModSecurity)
      │
      │  HTTP requests (ethical: authorized in-scope targets only)
      ▼
sqlirllm_runner.py
  │  probe(target, payload) → ExecutionResponse (real HTTP)
  │  analyze(strategy, response) → AnalysisResult (LLM)
  ▼
results/live/sqlirllm_results.json

sqlmap_runner.py
  │  subprocess: sqlmap -u <url> --batch --level 3 --risk 2
  ▼
results/live/sqlmap_results.json

compare.py
  │  Merges simulation summary.json + both live JSON files
  │  Derives vulnerability-type, WAF-event, and request-efficiency analytics
  ▼
results/live/cross_comparison.csv
results/live/cross_comparison.png
results/live/live_per_platform.png
results/live/live_vuln_type_by_lab.png
results/live/live_waf_mechanism.png
results/live/live_requests_per_lab_mechanism.png
```

---

## Unified Orchestration Control Plane

`run_full_report.sh` now acts as a single control plane for experiment configuration.

Exposed control groups:

1. **Simulation hyperparameters**: `--episodes`, `--targets-n`, `--seed`, `--skip-sim`
2. **Tool routing**: `--run-tools both|sqlmap|sqlirllm`
3. **Target lab scope**: `--live-targets "..."`
4. **SQLiRLLM attack families**: `--sqlirllm-strategies` + `--sqlirllm-max-attempts` + timeout
5. **SQLMap attack techniques/intensity**: `--sqlmap-technique` + `--sqlmap-level` + `--sqlmap-risk` + tamper/threads/timeouts

This allows controlled ablations such as:

1. Fixing tool and varying attack family.
2. Fixing attack family and varying target labs.
3. Running only one tool for isolated baseline diagnostics.

The selected configuration is persisted into `results/live/final_report.md` and
`results/live/final_report.json` to improve reproducibility and auditability.

---

## Caching Strategy

LLM calls are SHA-256-keyed on `(model, system_prompt, user_prompt_bucketed, temperature)` and stored under `results/cache/`. This makes experiments:
- **Reproducible** — same inputs always return the same output.
- **Cheap to re-run** — a full 400-episode experiment after cache warm-up adds zero API cost.
- **Latency-safe** — latency in the analyzer prompt is bucketed to 100 ms intervals so semantically-identical responses share a cache entry.

In the final run: **5,855 cache hits**, **273 live API calls** (95.5% cache utilization).

---

## Threat Model and Scope Limitations

- The simulation uses *in-process* targets with deterministic, ground-truth vulnerability labels. Real targets are stochastic, stateful, and may have application-level defenses beyond WAF signatures.
- The reward function uses the simulated outcome as a learning signal; in real Red-Team use, the VDR component would need a human-confirmed ground truth.
- The WAF model (signature matching + evasion-score bypass) is a research approximation of ModSecurity CRS. Real WAF bypass rates may differ.
- The 76 Q-table states learned from 40 targets / 400 episodes represent early convergence; a production deployment would benefit from a larger training corpus.
