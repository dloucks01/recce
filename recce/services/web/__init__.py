"""Web-facing service enumeration + deep checks (stdlib only).

Identifies every HTTP/HTTPS endpoint recce found - on ANY port, not just 80/443 -
fingerprints its tech stack, and runs a bounded set of high-signal checks: exposed
VCS/config files (.git/.env), server-status / Spring actuator, directory listing,
dangerous HTTP methods, weak cookie flags, and (via probes) the security-header / TLS
analysis. Everything positive becomes a Vuln, so web findings flow into the
Vulnerabilities / Verification / Exploitation sheets like anything else. Heavier
scanning is bridged to the Kali tools (whatweb / nikto / nuclei / gobuster / wpscan /
sslscan). Airgapped, stdlib only.
"""

from __future__ import annotations

import base64
import difflib
import hashlib
import hmac
import http.client
import json
import re
import socket
import ssl
import time
from urllib.parse import quote, urlencode, urljoin, urlparse

from ...core.models import Host, Port, Vuln
from .. import probes
from ...core import proxy

# Re-export split submodules so `from recce.services.web import X` keeps working.
from .http import *  # noqa: F401,F403
from .wordlists import *  # noqa: F401,F403
from .loot import *  # noqa: F401,F403
from .auth import *  # noqa: F401,F403
from .deserial import *  # noqa: F401,F403
from .crawl import *  # noqa: F401,F403
from .checks import *  # noqa: F401,F403
from .discover import *  # noqa: F401,F403

# --- GOBUSTER & WEB SPIDERING WORDLISTS ---
# Curated for high-fidelity findings in airgapped pentests (no external sources).
# Prioritized by attack surface: admin/config → info disclosure → RCE/lateral.
# --- DOMAIN SPIDERING (DNS/VHOST ENUMERATION) ---
# --- fingerprinting -------------------------------------------------------------
# body/header signatures -> technology label.
# --- secret extraction (redacted) ----------------------------------------------
# --- plaintext credential loot from exposed config/secret files ----------------
# Unlike a DB hash, these are cleartext and directly sprayable, so we lift them into
# the credential store (via the profile) to feed the spray chain. Read-only: the file
# was already fetched for the finding; we just parse what leaked.
# Framework debug pages / consoles: an exposed debugger is RCE or a full-config leak.
# XXE: POST an external-entity XML body to likely XML endpoints; a hit returns the
# file content, which only appears if the parser resolved the entity (zero-FP).
# --- Spring Boot Actuator deep-dive --------------------------------------------
# Only probed when the base /actuator responds, so it costs nothing elsewhere.
# --- backup / source-file exposure ---------------------------------------------
# --- opt-in default-credential probe (bounded, lockout-aware) -------------------
# Form / JSON login apps that HTTP-Basic can't reach. Each descriptor names the login
# endpoint, how to serialise the credentials, and a success predicate. The whole probe
# is bounded (one attempt per documented default) and non-destructive - just a login.
# (id, tech-label from fingerprint, path, content-type, body-template, success, creds)
# --- generic form auto-login (feed harvested creds into an authenticated scan) ---
# --- high-signal exposure paths (GET, confirmed only on positive content) -------
# (path, severity, script_id, title, cwes, remediation, confirm(status, body))
# Cookie names that indicate a session / auth / anti-CSRF token (hardening matters most).
# Subdomain-takeover fingerprints: a dangling CNAME to a third-party service whose
# resource is unclaimed serves one of these distinctive error pages -> claimable.
# --- JWT weakness detection ------------------------------------------------------
# Passive: read the token from the response and flag the algorithm. Active: forge an
# alg:none variant (same claims + a harmless marker) and REPLAY it against the same
# path, comparing the response to the authenticated and anonymous baselines - a match
# to the authenticated view proves the server accepts unsigned, forgeable tokens.
# name=eyJ... inside a Set-Cookie so we can replay the token in its real cookie.
# Common HMAC secrets to try against an HS256/384/512 JWT (offline, instant). The
# short list catches the overwhelmingly common "weak/default secret" case; a real
# engagement extends it with a wordlist (jwt_tool / hashcat -m 16500).
# --- RS256 -> HS256 algorithm confusion (sign with the PUBLIC key as the HMAC secret) ---
# --- SSTI / reflected-input quick check -----------------------------------------
# Serialized-object signatures that show up in client-controllable data (cookies /
# hidden form fields). Each is an insecure-deserialization attack surface (ysoserial /
# PHP object injection / ViewState) - the marker alone is unambiguous.
# ext -> (server-computed marker payload template, engine label). Each echoes a tag +
# a COMPUTED value so a verbatim source echo can never false-positive as execution.
# --- client-side JS secret scraping ---------------------------------------------
# --- WordPress plugin / version enum (wpscan-lite) ------------------------------
# --- authenticated crawler ------------------------------------------------------
# attribute values may be quoted or bare, so accept both.
# Field types / names we never fuzz (submit buttons, secrets, anti-CSRF tokens).
# --- injection transport (shared by reflection/SSTI + SQLi) ---------------------
# --- reflection / SSTI (canary) -------------------------------------------------

# Second-stage SSTI discriminators: which engine, and its exact RCE payload. Each probe
# uses a marker the plain literal can't reproduce (string×int repetition, etc.).
# --- SQL injection (error / boolean / opt-in time), non-destructive payloads -----
# All payloads live inside a SELECT/WHERE context (quote-break + AND/OR sleep) - no
# stacked DROP/UPDATE/DELETE, so a probe only reads, never modifies.
# '§' is replaced with the sleep duration at probe time.
# --- OS command injection -------------------------------------------------------
# Output-based proof uses shell arithmetic ($((a*b))) so the confirming marker
# (cmdi<product>) can ONLY appear if a shell evaluated our input - plain reflection of
# the literal payload can't produce the computed number, so it's a zero-FP signal.
# --- open redirect --------------------------------------------------------------
# --- generic path traversal / local file read ----------------------------------
# Only worth traversing params that plausibly name a file/path (keeps the budget + FP low).
# SSRF: parameters that plausibly carry a URL/host the server will fetch.
# (payload, response-marker, what-it-proves). Extended cloud metadata + file:// disclosure.
# SSTI: parameters that could reflect/execute template code
# A form is NOT auto-submitted when its action verb OR one of its fields signals a real
# side effect (state change / transaction / content post / file upload). Submitting such
# a form with junk values could delete data, place an order, send mail, invite users,
# etc. Login/search/filter/generic forms (where injection actually lives) stay fuzzable.
# --- content / directory discovery ---------------------------------------------
# A curated, bounded wordlist of high-signal paths NOT already covered by _PATHS /
# _BACKUPS / the actuator+wordpress deep-dives. Kept small (fast + airgap-embeddable);
# the goal is to surface attack surface (admin panels, API docs, dev/debug, listings),
# not to be a megalist brute-forcer.
# Paths that, if they return 200, are a finding in their own right (not just surface).
# --- virtual-host enumeration ---------------------------------------------------
def scan_endpoint(ip: str, port: Port, active: bool = True,
                  auth: dict | None = None, creds: bool = False,
                  host_hint: str = "", upload_shell: bool = False,
                  smuggle: bool = False) -> tuple[dict, list[Vuln]]:
    """Deep, non-intrusive scan of one web endpoint. Returns (profile, [Vuln]).
    `auth` (Cookie/Authorization headers) runs the scan as an authenticated user;
    `creds` opts into a tiny, lockout-aware default-credential probe. `upload_shell`
    and `smuggle` are explicit opt-ins for the two side-effecting active proofs
    (benign webshell upload+fetch; CL.TE/TE.CL desync timing probe)."""
    findings: list[Vuln] = []
    base = url_for(ip, port)
    # Root fetch: fingerprint + directory listing + cookie flags.
    root = _fetch(ip, port, "/", auth=auth)
    status = root[0] if root else None
    headers = root[1] if root else {}
    body = root[2] if root else ""
    fp = fingerprint(headers, body) if root else {"tech": [], "title": ""}
    # Enrich the port's product/version from the web fingerprint when nmap left it
    # blank, so it flows into the CVE mapping + Services-by-Product pivot.
    if root and not port.product:
        prod, ver = product_version(headers, body)
        if prod:
            port.product = prod
            port.version = port.version or ver
            port.detect_source = port.detect_source or "web"
    profile = {"ip": ip, "port": port.portid, "scheme": scheme_for(port),
               "url": base, "status": status,
               "server": headers.get("server", ""), "tech": fp["tech"],
               "title": fp["title"]}
    # Security headers + TLS (reuse the existing stdlib probes).
    findings.extend(probes.http_findings(ip, port))
    if probes._is_tls(port):
        findings.extend(probes.tls_findings(ip, port))
    # JWT weaknesses read from the root response. Passively we flag the algorithm;
    # actively we forge an alg:none token and replay it to prove acceptance.
    if root:
        findings.extend(_scan_jwts(ip, port, headers, body, active=active))
        findings.extend(_scan_deserial(ip, port, headers, body))
    # The active HTTP checks only make sense if the port actually spoke HTTP -
    # skip them for a TLS-only non-HTTP port (LDAPS/IMAPS) so we don't waste a
    # dozen dead requests there (its TLS findings above still count).
    if not active or root is None:
        profile["findings"] = len(findings)
        return profile, findings
    # Directory listing on the root.
    if root and status == 200 and re.search(r"<title>Index of /|Directory listing for", body, re.I):
        findings.append(_mk(ip, port, "web-dirlisting", "medium",
                            "Directory listing enabled", ["CWE-548"],
                            f"GET {profile['url']}/ returned an auto-index page.",
                            "Disable automatic directory indexing (Options -Indexes)."))
    # Cookie hardening (per Set-Cookie): HttpOnly / Secure / SameSite / prefix / scope.
    findings.extend(_cookie_findings(ip, port, headers.get("set-cookie", "")))
    findings.extend(_security_headers(ip, port, headers))
    findings.extend(_csp_findings(ip, port, headers))
    _tko = _takeover_service(body)
    if _tko:
        findings.append(_takeover_finding(ip, port, base, host_hint, _tko))
    # Dangerous HTTP methods. When PUT is advertised AND active, we don't just
    # trust the Allow header - we prove it: PUT a marker, GET it back, DELETE it.
    opt = _fetch(ip, port, "/", method="OPTIONS", auth=auth)
    if opt and opt[1].get("allow"):
        allowed = {m.strip().upper() for m in opt[1]["allow"].split(",")}
        bad = sorted(allowed & _DANGEROUS_METHODS)
        if bad:
            put_proof = _prove_put(ip, port, auth) if ("PUT" in bad and active) else None
            if put_proof and put_proof[0]:
                findings.append(_mk(ip, port, "web-methods", "high",
                    "Arbitrary file write via HTTP PUT (proven)", ["CWE-434", "CWE-650"],
                    put_proof[1], "Disable WebDAV/PUT write; restrict the allowed methods.",
                    confidence="confirmed"))
                others = [m for m in bad if m != "PUT"]
                if others:
                    findings.append(_mk(ip, port, "web-methods", "medium",
                        f"Dangerous HTTP methods advertised: {', '.join(others)}",
                        ["CWE-650"], f"OPTIONS / -> Allow: {opt[1]['allow']}",
                        "Disable unless required.", confidence="potential"))
            else:
                note = f"OPTIONS / -> Allow: {opt[1]['allow']}"
                conf = "confirmed" if active else "potential"
                if put_proof and not put_proof[0]:      # actively tested, PUT rejected
                    note += f"; {put_proof[1]}"
                    conf = "potential"
                sev = "high" if "PUT" in bad else "medium"
                findings.append(_mk(ip, port, "web-methods", sev,
                    f"Dangerous HTTP methods enabled: {', '.join(bad)}", ["CWE-650"],
                    note, "Disable PUT/DELETE/TRACE/CONNECT unless required.",
                    confidence=conf))
    # CORS: reflected-arbitrary-Origin and null-Origin acceptance, both only weaponizable
    # when credentials are allowed (a browser attaches the victim's cookies).
    probe_origin = "https://recce.example"
    seen_cors = False
    cors = _fetch(ip, port, "/", auth={**(auth or {}), "Origin": probe_origin})
    if cors:
        ch = cors[1]
        acao = ch.get("access-control-allow-origin", "")
        acac = ch.get("access-control-allow-credentials", "").lower()
        if acao == probe_origin and acac == "true":
            seen_cors = True
            findings.append(_mk(ip, port, "web-cors", "high",
                                "CORS reflects arbitrary Origin with credentials", ["CWE-942"],
                                f"Origin: {probe_origin} -> Access-Control-Allow-Origin: {acao}, "
                                "Allow-Credentials: true (any site can read authenticated responses).",
                                "Echo only an allow-list of trusted origins; never reflect + credentials."))
    if not seen_cors:                         # null Origin: reachable from a sandboxed iframe
        nc = _fetch(ip, port, "/", auth={**(auth or {}), "Origin": "null"})
        if nc:
            nh = nc[1]
            if nh.get("access-control-allow-origin", "") == "null" and \
                    nh.get("access-control-allow-credentials", "").lower() == "true":
                findings.append(_mk(ip, port, "web-cors", "high",
                    "CORS allows the null Origin with credentials", ["CWE-942"],
                    "Origin: null -> Access-Control-Allow-Origin: null, Allow-Credentials: true "
                    "(a sandboxed iframe / data: document sends 'Origin: null' and can then read "
                    "authenticated responses).",
                    "Never allow-list the null origin; echo only trusted origins."))
    # Web cache poisoning: unkeyed header reflected into a cacheable response.
    findings.extend(_scan_cache_poison(ip, port, auth))
    # File-upload surface (lead always; benign webshell proof only under --upload-shell).
    findings.extend(_scan_upload(ip, port, base, body, auth, prove=upload_shell))
    # HTTP request smuggling (CL.TE/TE.CL desync) - opt-in only; can disturb shared proxies.
    if smuggle:
        findings.extend(_scan_smuggle(ip, port))

    # Deep auth/injection detection (read-only).
    # _check_ssti / _check_blind_sqli removed: they emit "high" from a single-shot
    # substring match with no baseline (ssti fired on any body containing "49";
    # blind_sqli fired on any 3-second network hiccup) - _scan_reflection covers
    # SSTI with unique canaries and _scan_sqli covers SQLi with real payloads.
    findings.extend(_check_session_fixation(ip, port, auth))
    findings.extend(_check_oauth_redirect(ip, port, auth))
    findings.extend(_check_prototype_pollution(ip, port, auth))
    findings.extend(_check_ldap_injection(ip, port, auth))
    findings.extend(_check_header_injection(ip, port, auth))
    findings.extend(_check_method_override(ip, port, auth))
    findings.extend(_check_error_stack_trace(ip, port, base, auth))
    findings.extend(_check_null_byte_injection(ip, port, base, auth))
    findings.extend(_check_dom_xss(ip, port, body or "", auth))
    findings.extend(_check_type_confusion(ip, port, base, auth))
    findings.extend(_check_rate_limits(ip, port, base, auth))
    findings.extend(_check_bot_detection_bypass(ip, port, base, auth))
    findings.extend(_check_admin_panels(ip, port, base, auth))
    # Concurrency: race condition detection (expensive, optional)
    if active:
        findings.extend(_check_race_condition(ip, port, base, auth))
    # Form auth brute: try weak creds against login forms (if creds enabled)
    if creds and body:
        for form_str in _FORM_RE.findall(body):
            form = _parse_form(form_str, "/")
            if form.get("password"):
                common_creds = [("admin", "admin"), ("admin", "password"), ("test", "test"), ("guest", "guest")]
                findings.extend(_brute_login_form(ip, port, form, base, auth, common_creds))
    # API key extraction from responses
    findings.extend(_extract_api_keys(ip, port, body or ""))
    # Wordlist-based fuzzing (active mode only; uses curated entries to avoid noise)
    if active:
        findings.extend(_brute_wordlist_dirs(ip, port, base, auth, limit=15))
        findings.extend(_fuzz_parameters(ip, port, base, auth, limit=8))
        findings.extend(_fuzz_headers_wordlist(ip, port, auth, limit=8))
        findings.extend(_fuzz_cms_if_detected(ip, port, base, fp, auth))
    # GraphQL: introspection, plus query batching (brute-force/DoS amplifier) and
    # field-suggestion schema leak when introspection is off.
    gql = '{"query":"query{__schema{queryType{name}}}"}'
    for gp in ("graphql", "api/graphql", "v1/graphql", "query"):
        r = _fetch(ip, port, "/" + gp, method="POST", body=gql, auth=auth)
        if not r or r[0] not in (200, 400):
            continue
        base_gql = f"{profile['url']}/{gp}"
        if r[0] == 200 and ("__schema" in r[2] or '"queryType"' in r[2]):
            findings.append(_mk(ip, port, "web-graphql", "medium",
                                "GraphQL introspection enabled", ["CWE-200"],
                                f"POST {base_gql} (__schema query) returned the schema.",
                                "Disable GraphQL introspection in production."))
        else:
            # Introspection blocked/failed: does the error leak field names ("Did you mean")?
            probe = ('{"query":"query{__typenamee}"}')
            sug = _fetch(ip, port, "/" + gp, method="POST", body=probe, auth=auth)
            if sug and re.search(r"did you mean|didyoumean", sug[2], re.I):
                findings.append(_mk(ip, port, "web-graphql", "low",
                    "GraphQL field-suggestion schema leak", ["CWE-200"],
                    f"POST {base_gql} with an invalid field returned a 'Did you mean' "
                    "suggestion - the schema can be reconstructed field by field even with "
                    "introspection disabled.",
                    "Disable did-you-mean suggestions (production error masking)."))
        # Batching: does it execute an array of queries in one request?
        batch = '[{"query":"query{__typename}"},{"query":"query{__typename}"}]'
        br = _fetch(ip, port, "/" + gp, method="POST", body=batch, auth=auth)
        if br and br[0] == 200 and br[2].count('"__typename"') >= 2:
            findings.append(_mk(ip, port, "web-graphql-batch", "medium",
                "GraphQL query batching enabled", ["CWE-799"],
                f"POST {base_gql} with a 2-query array returned 2 results in one request - "
                "batching amplifies credential brute-force and rate-limit bypass (one HTTP "
                "request = N login/OTP attempts).",
                "Cap or disable array/aliased query batching; rate-limit per operation."))
        break
    # High-signal exposure paths.
    seen_sid: set[str] = set()
    looted_creds: list = []
    for path, sev, sid, title, cwes, fix, confirm in _PATHS:
        r = _fetch(ip, port, "/" + path, auth=auth)
        if not r:
            continue
        st, _hd, bd = r
        try:
            if confirm(st, bd):
                if sid in seen_sid:
                    continue
                seen_sid.add(sid)
                detail = (f"GET {base}/{path} -> HTTP {st} "
                          f"(content matched the {title.split('(')[0].strip()} signature).")
                # For secret-bearing files, show WHAT leaked (redacted).
                if sid in ("web-dotenv", "web-aws", "web-htpasswd"):
                    sec = _leaked_secrets(bd)
                    if sec:
                        detail += "  leaked: " + "; ".join(sec)
                creds_here = _web_credentials(sid, bd, ip, getattr(port, "portid", port))
                if creds_here:
                    looted_creds.extend(creds_here)
                    detail += (f"  CAPTURED {len(creds_here)} cleartext credential(s) "
                               "-> credential store (sprayable): "
                               + ", ".join(c.label for c in creds_here))
                findings.append(_mk(ip, port, sid, sev, title, cwes, detail, fix))
        except Exception:  # noqa: BLE001 - a bad body never breaks the sweep
            continue
    # Exposed .git -> reconstruct the source tree + mine it for secrets/credentials.
    if active and "web-git" in seen_sid:
        looted_creds.extend(_scan_git_dump(ip, port, auth, findings))
    # Deep dives (each self-gates so they cost nothing when absent).
    findings.extend(_scan_actuator(ip, port, base, auth))
    findings.extend(_scan_debug(ip, port, base, auth))
    if active:
        findings.extend(_scan_nosql(ip, port, base, body, auth))
        findings.extend(_scan_xxe(ip, port, base, auth))
    findings.extend(_scan_backups(ip, port, base, auth))
    findings.extend(_scan_reflection(ip, port, base, auth))
    findings.extend(_scan_js(ip, port, base, body, auth))
    if active:
        sm_findings, sm_creds = _scan_sourcemaps(ip, port, base, body, auth)
        findings.extend(sm_findings)
        looted_creds.extend(sm_creds)
    if any("wordpress" in t.lower() for t in fp["tech"]):
        findings.extend(_scan_wordpress(ip, port, base, body, auth))
    if creds:
        findings.extend(_basic_auth_defaults(ip, port, base,
                                             ["/", "/manager/html", "/admin", "/console",
                                              "/api/whoami", "/api/overview"]))
        findings.extend(_form_login_defaults(ip, port, base, fp["tech"]))
    # Content/directory discovery + virtual-host enumeration (active pass).
    findings.extend(_content_discovery(ip, port, base, auth))
    vh_findings, vhosts = _discover_vhosts(ip, port, base, host_hint, auth)
    findings.extend(vh_findings)
    if vhosts:
        profile["vhosts"] = vhosts
    profile["findings"] = len(findings)
    profile["credentials"] = looted_creds
    return profile, findings


def scan_host(host: Host, active: bool = True, auth: dict | None = None,
              creds: bool = False, upload_shell: bool = False,
              smuggle: bool = False) -> list[dict]:
    """Scan every web endpoint on a host, appending deduped Vulns. Returns the web
    endpoint profiles (for the Web sheet)."""
    existing = {v.key for v in host.vulns}
    profiles: list[dict] = []
    for port in host.open_ports:
        if not is_web(port):
            continue
        profile, findings = scan_endpoint(host.ip, port, active=active, auth=auth, creds=creds,
                                          host_hint=host.hostname or "",
                                          upload_shell=upload_shell, smuggle=smuggle)
        for v in findings:
            if v.key in existing:
                continue
            existing.add(v.key)
            host.vulns.append(v)
        profiles.append(profile)
    return profiles


# --- categorization + Kali bridge ----------------------------------------------

def web_endpoints(hosts: list[Host]) -> list[dict]:
    """Every web endpoint across all hosts (from stored data - no network), for the
    Web sheet: url, server/tech (nmap), and how many web findings it carries."""
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_web(p):
                continue
            wv = [v for v in h.vulns if v.port == p.portid and v.source == "web"]
            tech = " ".join(t for t in (p.product, p.version, p.extrainfo) if t)
            out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                        "url": url_for(h.ip, p), "scheme": scheme_for(p),
                        "tech": tech or p.service or "http", "findings": len(wv),
                        "commands": bridge_commands(url_for(h.ip, p), tech, p)})
    return out


def bridge_commands(url: str, tech: str, port: Port) -> str:
    """The exact Kali deep-scan commands for an endpoint, tailored to its stack."""
    host_port = url.split("://", 1)[-1]
    cmds = [f"whatweb -a3 {url}",
            f"nuclei -u {url}",
            f"nikto -h {url}",
            f"gobuster dir -u {url} -w /usr/share/wordlists/dirb/common.txt -x php,txt,bak",
            # SQLi: crawl the site and test every form/parameter it finds (recce doesn't
            # reimplement a SQLi engine - it bridges to sqlmap, in-philosophy).
            f"sqlmap -u {url} --batch --crawl=2 --forms --level=3 --risk=2 --threads=4 --dbs"]
    low = f"{tech} {url}".lower()
    if "wordpress" in low:
        cmds.append(f"wpscan --url {url} --enumerate p,t,u")
    if "tomcat" in low or ":8080" in url:
        cmds.append(f"nxc http {host_port.split(':')[0]} -M tomcat  # or hydra manager default creds")
    if probes._is_tls(port):
        cmds.append(f"sslscan {host_port}")
    return "  ;  ".join(cmds)
