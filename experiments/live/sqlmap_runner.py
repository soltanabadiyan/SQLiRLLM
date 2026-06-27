"""SQLMap runner against the Docker test stack.

Runs sqlmap against the DVWA, bWAPP, sqli-labs, and DVWA-via-WAF endpoints
with a representative set of options and captures structured results for
comparison with SQLiRLLM and the other methods.

Usage:
    python -m experiments.live.sqlmap_runner
    python -m experiments.live.sqlmap_runner --targets dvwa juiceshop
    python -m experiments.live.sqlmap_runner --level 3 --risk 2
    python -m experiments.live.sqlmap_runner --technique BEUSTQ --tamper space2comment,charencode

Requires:
    - sqlmap installed:  apt install sqlmap   (already present at /usr/bin/sqlmap)
    - Docker stack running: docker compose -f docker/docker-compose.yml up -d
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

RESULTS = Path(__file__).resolve().parent.parent.parent / "results" / "live"


# --------------------------------------------------------------------------- #
# Target definitions                                                           #
# --------------------------------------------------------------------------- #
@dataclass
class LiveTarget:
    name: str
    url: str
    data: Optional[str]          # POST body (None = GET)
    cookie: Optional[str]
    parameter: Optional[str] = None
    extra_flags: List[str] = field(default_factory=list)
    has_waf: bool = False
    platform: str = ""

    def sqlmap_args(
        self,
        level: int = 3,
        risk: int = 2,
        timeout: int = 30,
        technique: Optional[str] = None,
        tamper: Optional[str] = None,
        threads: Optional[int] = None,
    ) -> List[str]:
        cmd = [
            "sqlmap",
            "-u", self.url,
            "-p", self.parameter or "",
            "--level", str(level),
            "--risk", str(risk),
            "--timeout", str(timeout),
            "--retries", "2",
            "--batch",           # non-interactive
            "--output-dir", str(RESULTS / f"sqlmap_{self.name}"),
        ]
        cmd = [arg for arg in cmd if arg != ""]
        if self.data:
            cmd += ["--data", self.data]
        if self.cookie:
            cmd += ["--cookie", self.cookie]
        if technique:
            cmd += ["--technique", technique]
        if tamper:
            cmd += ["--tamper", tamper]
        if threads is not None:
            cmd += ["--threads", str(threads)]
        cmd += self.extra_flags
        return cmd


# Endpoints (assumes Docker stack is up with default port mapping).
TARGETS: Dict[str, LiveTarget] = {
    "dvwa_sqli": LiveTarget(
        name="dvwa_sqli",
        url="http://localhost:8090/vulnerabilities/sqli/?id=1&Submit=Submit",
        data=None,
        cookie="PHPSESSID=placeholder; security=low",
        parameter="id",
        platform="DVWA",
        extra_flags=["--dbms=mysql"],
    ),
    "dvwa_sqli_medium": LiveTarget(
        name="dvwa_sqli_medium",
        url="http://localhost:8090/vulnerabilities/sqli/",
        data="id=1&Submit=Submit",
        cookie="PHPSESSID=placeholder; security=medium",
        parameter="id",
        platform="DVWA",
        extra_flags=["--dbms=mysql"],
    ),
    "dvwa_sqli_hard": LiveTarget(
        name="dvwa_sqli_hard",
        url="http://localhost:8095/vulnerabilities/sqli/?id=1&Submit=Submit",
        data=None,
        cookie="PHPSESSID=placeholder; security=high",
        parameter="id",
        platform="DVWA (hard)",
        extra_flags=["--dbms=mysql"],
    ),
    "dvwa_sqli_max": LiveTarget(
        name="dvwa_sqli_max",
        url="http://localhost:8096/vulnerabilities/sqli/?id=1&Submit=Submit",
        data=None,
        cookie="PHPSESSID=placeholder; security=impossible",
        parameter="id",
        platform="DVWA (max/impossible)",
        extra_flags=["--dbms=mysql"],
    ),
    "dvwa_waf": LiveTarget(
        name="dvwa_waf",
        url="http://localhost:8080/vulnerabilities/sqli/?id=1&Submit=Submit",
        data=None,
        cookie="PHPSESSID=placeholder; security=low",
        parameter="id",
        platform="DVWA+ModSecurity",
        has_waf=True,
        extra_flags=["--dbms=mysql", "--tamper=space2comment,charencode"],
    ),
    "sqli_labs_1": LiveTarget(
        name="sqli_labs_1",
        url="http://localhost:8094/Less-1/?id=1",
        data=None,
        cookie=None,
        parameter="id",
        platform="sqli-labs",
        extra_flags=["--dbms=mysql"],
    ),
    "sqli_labs_11": LiveTarget(
        name="sqli_labs_11",
        url="http://localhost:8094/Less-11/",
        data="uname=admin&passwd=admin&submit=Submit",
        cookie=None,
        parameter="uname",
        platform="sqli-labs",
        extra_flags=["--dbms=mysql"],
    ),
    "bwapp_sqli": LiveTarget(
        name="bwapp_sqli",
        url="http://localhost:8091/sqli_1.php?title=iron+man&action=search",
        data=None,
        cookie="PHPSESSID=placeholder; security_level=0",
        parameter="title",
        platform="bWAPP",
        extra_flags=["--dbms=mysql"],
    ),
    "juiceshop_login": LiveTarget(
        name="juiceshop_login",
        url="http://localhost:8092/rest/user/login",
        data='{"email":"test@test.com","password":"test"}',
        cookie=None,
        parameter="email",
        platform="Juice Shop",
        extra_flags=["--dbms=sqlite", "--content-type=application/json"],
    ),
}


# --------------------------------------------------------------------------- #
# Session cookie helpers                                                       #
# --------------------------------------------------------------------------- #
def _get_dvwa_session(base_url: str, level: str = "low") -> Optional[str]:
    """Obtain a DVWA PHPSESSID by logging in via curl."""
    try:
        login_url = f"{base_url.rstrip('/')}/login.php"
        login = subprocess.run(
            ["curl", "-s", "-c", "-", "-b", "", login_url],
            capture_output=True, text=True, timeout=15,
        )
        token_m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)", login.stdout)
        token = token_m.group(1) if token_m else ""
        m = re.search(r"PHPSESSID\s+(\S+)", login.stdout)
        sid = m.group(1) if m else "placeholder"
        post = subprocess.run(
            [
                "curl", "-s", "-i", "-b", f"PHPSESSID={sid}", "-c", "-",
                "-d", f"username=admin&password=password&Login=Login&user_token={token}",
                login_url,
            ],
            capture_output=True, text=True, timeout=15,
        )
        post_cookie = re.search(r"PHPSESSID\s+(\S+)", post.stdout)
        final_sid = post_cookie.group(1) if post_cookie else sid
        return f"PHPSESSID={final_sid}; security={level}"
    except Exception:
        return None


def _prepare_sqli_labs() -> None:
    """Initialize/reset sqli-labs database so direct targets are reachable."""
    try:
        subprocess.run(
            ["curl", "-s", "http://localhost:8094/sql-connections/setup-db.php"],
            capture_output=True, text=True, timeout=30,
        )
    except Exception:
        return


def _prepare_bwapp() -> None:
    """Ensure bWAPP installation has been executed."""
    try:
        subprocess.run(
            ["curl", "-s", "http://localhost:8091/install.php?install=yes"],
            capture_output=True, text=True, timeout=30,
        )
    except Exception:
        return


# --------------------------------------------------------------------------- #
# Execution and result parsing                                                 #
# --------------------------------------------------------------------------- #
@dataclass
class SQLMapResult:
    target_name: str
    platform: str
    has_waf: bool
    vulnerable: bool
    injection_types: List[str]
    db_banner: Optional[str]
    tables_found: int
    duration_s: float
    returncode: int
    request_count_estimate: Optional[int] = None
    error: Optional[str] = None


def run_sqlmap(
    target: LiveTarget,
    level: int = 3,
    risk: int = 2,
    timeout_s: int = 180,
    request_timeout: int = 30,
    technique: Optional[str] = None,
    tamper: Optional[str] = None,
    threads: Optional[int] = None,
) -> SQLMapResult:
    """Execute sqlmap and parse its output into a structured result."""
    RESULTS.mkdir(parents=True, exist_ok=True)

    # Try to get a real session for DVWA targets.
    if "dvwa" in target.name:
        if "medium" in target.name:
            level_str = "medium"
        elif "hard" in target.name:
            level_str = "high"
        elif "max" in target.name:
            level_str = "impossible"
        else:
            level_str = "low"
        base_url = target.url.split("/vulnerabilities/")[0]
        cookie = _get_dvwa_session(base_url, level_str)
        if cookie:
            target.cookie = cookie
    elif "sqli_labs" in target.name:
        _prepare_sqli_labs()
    elif "bwapp" in target.name:
        _prepare_bwapp()

    cmd = target.sqlmap_args(
        level=level,
        risk=risk,
        timeout=request_timeout,
        technique=technique,
        tamper=tamper,
        threads=threads,
    )
    print(f"  [sqlmap] {target.name}  ({target.platform}, waf={target.has_waf})")

    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s,
        )
        duration = time.perf_counter() - t0
        out = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired:
        return SQLMapResult(
            target.name, target.platform, target.has_waf, False, [], None, 0,
            timeout_s, -1, error="timeout",
        )
    except Exception as exc:
        return SQLMapResult(
            target.name, target.platform, target.has_waf, False, [], None, 0,
            0.0, -1, error=str(exc),
        )

    # Parse key indicators from sqlmap stdout.
    injection_types = re.findall(r"Type:\s+([^\n]+)", out)
    banner_m = re.search(r"back-end DBMS:\s+([^\n]+)", out)
    banner = banner_m.group(1).strip() if banner_m else None
    tables = len(re.findall(r"^\+[-+]+\+$", out, re.M))
    vulnerable = bool(
        re.search(r"is vulnerable|sqlmap identified", out, re.I)
        or injection_types
        or banner
    )

    req_count = None
    req_patterns = [
        r"HTTP\(S\) requests\s*:\s*(\d+)",
        r"HTTP requests\s*:\s*(\d+)",
        r"performed\s+(\d+)\s+queries",
        r"performed\s+(\d+)\s+requests",
    ]
    for pat in req_patterns:
        m = re.search(pat, out, re.I)
        if m:
            try:
                req_count = int(m.group(1))
                break
            except (TypeError, ValueError):
                pass

    return SQLMapResult(
        target_name=target.name,
        platform=target.platform,
        has_waf=target.has_waf,
        vulnerable=vulnerable,
        injection_types=[t.strip() for t in injection_types],
        db_banner=banner,
        tables_found=tables,
        duration_s=round(duration, 1),
        returncode=proc.returncode,
        request_count_estimate=req_count,
    )


# --------------------------------------------------------------------------- #
# Main                                                                         #
# --------------------------------------------------------------------------- #
def run(
    target_names: List[str],
    level: int,
    risk: int,
    timeout_s: int = 180,
    request_timeout: int = 30,
    technique: Optional[str] = None,
    tamper: Optional[str] = None,
    threads: Optional[int] = None,
) -> List[Dict]:
    if technique and not re.fullmatch(r"[BEUSTQ]+", technique.upper()):
        raise ValueError("--technique must be a combination of B,E,U,S,T,Q (e.g. BEUSTQ)")
    print(
        f"  [sqlmap] level={level} risk={risk} timeout_s={timeout_s} "
        f"request_timeout={request_timeout} technique={technique or 'default'} "
        f"tamper={tamper or 'target-default'} threads={threads or 'default'}"
    )
    results = []
    for name in target_names:
        t = TARGETS.get(name)
        if t is None:
            print(f"  [warn] unknown target '{name}', skipping")
            continue
        r = run_sqlmap(
            t,
            level=level,
            risk=risk,
            timeout_s=timeout_s,
            request_timeout=request_timeout,
            technique=technique.upper() if technique else None,
            tamper=tamper,
            threads=threads,
        )
        d = {
            "tool": "SQLMap",
            "target": r.target_name,
            "platform": r.platform,
            "has_waf": r.has_waf,
            "vulnerable_detected": r.vulnerable,
            "injection_types": r.injection_types,
            "db_banner": r.db_banner,
            "tables_found": r.tables_found,
            "duration_s": r.duration_s,
            "request_count_estimate": r.request_count_estimate,
            "error": r.error,
        }
        results.append(d)
        print(f"    -> vulnerable={r.vulnerable} types={r.injection_types} "
              f"banner={r.banner if hasattr(r,'banner') else r.db_banner} "
              f"time={r.duration_s}s error={r.error}")

    out_path = RESULTS / "sqlmap_results.json"
    out_path.write_text(json.dumps(results, indent=2))
    print(f"\n  SQLMap results -> {out_path}")
    return results


def main() -> None:
    p = argparse.ArgumentParser(description="SQLMap live-target runner.")
    p.add_argument("--targets", nargs="+", default=list(TARGETS.keys()),
                   choices=list(TARGETS.keys()), metavar="TARGET")
    p.add_argument("--level", type=int, default=3)
    p.add_argument("--risk", type=int, default=2)
    p.add_argument("--timeout-s", type=int, default=180,
                   help="Global timeout in seconds for each sqlmap process.")
    p.add_argument("--request-timeout", type=int, default=30,
                   help="sqlmap per-request HTTP timeout in seconds (--timeout).")
    p.add_argument("--technique", type=str, default=None,
                   help="SQLMap technique letters: B,E,U,S,T,Q (example: BEUSTQ).")
    p.add_argument("--tamper", type=str, default=None,
                   help="Optional sqlmap tamper chain, e.g., space2comment,charencode.")
    p.add_argument("--threads", type=int, default=None,
                   help="Optional sqlmap worker threads.")
    args = p.parse_args()
    print(f"Running SQLMap against: {args.targets}")
    run(
        args.targets,
        args.level,
        args.risk,
        timeout_s=args.timeout_s,
        request_timeout=args.request_timeout,
        technique=args.technique,
        tamper=args.tamper,
        threads=args.threads,
    )


if __name__ == "__main__":
    main()
