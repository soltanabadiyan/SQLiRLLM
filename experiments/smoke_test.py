"""Quick connectivity + per-tier smoke test for the GapGPT API.

Run:  python -m experiments.smoke_test
Confirms the key works, lists a few models, and exercises Tier 2 + Tier 3 once.
"""
from __future__ import annotations

from sqlirllm.analyzer import Analyzer
from sqlirllm.config import CONFIG
from sqlirllm.environment import build_target_suite
from sqlirllm.llm_client import LLMClient
from sqlirllm.payload_generator import PayloadGenerator


def main() -> None:
    cfg = CONFIG
    print(f"Configured: {cfg.llm.is_configured}")
    print(f"Base URL  : {cfg.llm.base_url}")
    print(f"Payload   : {cfg.llm.payload_model}")
    print(f"Analysis  : {cfg.llm.analysis_model}")

    client = LLMClient(cfg.llm)

    print("\n--- Tier 2: payload generation ---")
    gen = PayloadGenerator(client, cfg.llm)
    target = build_target_suite(n=1, seed=7)[0]
    ctx = target.observable_state("initial")
    print(f"Context: {ctx}")
    payload = gen.generate("error_based", ctx)
    print(f"Payload: {payload}")
    print(f"Offline fallback used: {gen.offline_used}")

    print("\n--- Tier 3: analysis ---")
    analyzer = Analyzer(client, cfg.llm)
    response = target.execute("error_based", payload)
    result = analyzer.analyze("error_based", response)
    print(f"Execution outcome (ground truth): {response.outcome.value}")
    print(f"Analyzer verdict: vulnerable={result.vulnerable} "
          f"severity={result.severity} signal='{result.signal}' used_llm={result.used_llm}")

    print(f"\nLLM calls={client.calls} cache_hits={client.cache_hits} "
          f"avg_latency_ms={client.total_latency_ms / max(client.calls, 1):.0f}")


if __name__ == "__main__":
    main()
