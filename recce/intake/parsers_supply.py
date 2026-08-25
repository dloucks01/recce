"""IP3: content-discovery + container/SBOM importers.

* ffuf     — JSON (`ffuf -o out.json`)
* gobuster — JSON (`gobuster ... --format json`) OR the classic text output
* trivy    — JSON (`trivy image/fs/config -f json`)
* grype    — JSON (`grype -o json`)

Content-discovery hits fold as low/medium web-endpoint findings (interesting
paths = surface). Container/SBOM vuln scanners fold each CVE as a real
finding on the target host — we take the target from `--server` or `-t`
lines when present, else use a synthetic "container-image" host so the
findings land somewhere the operator can see.
"""
from __future__ import annotations

import json
import re

from ..models import Vuln


def _safe_json(text: str):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _split_host_port(url: str, default_port: int | None = None):
    m = re.match(r"^(?:https?://)?([^/:\s]+)(?::(\d+))?", url or "", re.I)
    if not m:
        return "", default_port
    host = m.group(1)
    port = int(m.group(2)) if m.group(2) else default_port
    if not port:
        if (url or "").lower().startswith("https://"):
            port = 443
        elif (url or "").lower().startswith("http://"):
            port = 80
    return host, port


# ---- ffuf --------------------------------------------------------------------
# ffuf JSON: {"config":{...}, "results":[{"input":{"FUZZ":"admin"},"url":"...",
#             "status":200,"length":1234,"words":..., ...}]}
# We surface interesting status codes (200/301/302/401/403) as content-
# discovery findings; 404/500 are noise.
_FFUF_INTERESTING = {200, 201, 204, 301, 302, 401, 403}


def parse_ffuf(text: str) -> list[Vuln]:
    d = _safe_json(text)
    if not isinstance(d, dict):
        return []
    results = d.get("results") or []
    if not results:
        return []
    base = (d.get("config") or {}).get("url") or (results[0].get("url") or "")
    ip, port = _split_host_port(base, 80)
    if not ip:
        return []
    # Group by status so the Findings tab shows one row per status class per host
    by_status: dict = {}
    for r in results:
        st = r.get("status") or 0
        if st not in _FFUF_INTERESTING:
            continue
        url = r.get("url") or ""
        by_status.setdefault(st, []).append(url)
    out: list[Vuln] = []
    for st, urls in by_status.items():
        sev = "medium" if st in (401, 403) else "low"    # auth-boundary is more interesting
        out.append(Vuln(
            ip=ip, port=port, protocol="tcp",
            script_id=f"ffuf-{st}",
            state="finding",
            title=f"Content discovery: {len(urls)} URL(s) returning {st}",
            output="\n".join(urls[:30])[:3000],
            severity=sev, source="ffuf", confidence="confirmed"))
    return out


# ---- gobuster ----------------------------------------------------------------
# gobuster --format json emits one JSON object per line
# Text format: /admin (Status: 301) [Size: 178] [--> /admin/]
_GB_TEXT_RE = re.compile(r"^(/\S+)\s+\(Status:\s*(\d+)\)", re.M)


def parse_gobuster(text: str) -> list[Vuln]:
    body = text.lstrip()
    entries = []
    if body.startswith("{"):
        for line in body.splitlines():
            line = line.strip()
            if not line: continue
            obj = _safe_json(line)
            if isinstance(obj, dict):
                entries.append(obj)
    else:
        # Text output — no target header, so we can't ID the host from output alone.
        # Best-effort: use a synthetic host "web-discovery" for now; the operator
        # can reassign in the UI. TODO: sniff CLI arg headers when gobuster leaves
        # them (older versions do).
        for path, status in _GB_TEXT_RE.findall(text):
            entries.append({"path": path, "status": int(status)})
    if not entries:
        return []
    by_status: dict = {}
    ip = "web-discovery"    # placeholder — text output loses the target
    port = 80
    # If JSON entries have a `url`, use that host for grouping
    for e in entries:
        st = e.get("status") or 0
        if st not in {200, 301, 302, 401, 403}:
            continue
        url_or_path = e.get("url") or e.get("path") or ""
        host_from_json, port_from_json = _split_host_port(url_or_path, 80)
        if host_from_json:
            ip, port = host_from_json, port_from_json
        by_status.setdefault(st, []).append(url_or_path)
    out: list[Vuln] = []
    for st, urls in by_status.items():
        sev = "medium" if st in (401, 403) else "low"
        out.append(Vuln(
            ip=ip, port=port, protocol="tcp",
            script_id=f"gobuster-{st}", state="finding",
            title=f"Content discovery: {len(urls)} path(s) returning {st}",
            output="\n".join(urls[:30])[:3000],
            severity=sev, source="gobuster", confidence="confirmed"))
    return out


# ---- Trivy -------------------------------------------------------------------
# Trivy JSON top-level: {"ArtifactName": "img:tag", "Results":[{"Target":"...",
# "Vulnerabilities":[{"VulnerabilityID":"CVE-...","Severity":"HIGH", ...}]}]}
_TRIVY_SEV = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
              "LOW": "low", "UNKNOWN": "info"}


def parse_trivy(text: str) -> list[Vuln]:
    d = _safe_json(text)
    if not isinstance(d, dict):
        return []
    artifact = d.get("ArtifactName") or d.get("ArtifactType") or "container-image"
    # Container images don't have IPs — use a synthetic "container:<name>" host
    # so findings land somewhere the operator can drill into.
    ip = f"container:{artifact}"[:100]
    out: list[Vuln] = []
    for res in d.get("Results") or []:
        target = res.get("Target") or ""
        for v in res.get("Vulnerabilities") or []:
            cve = v.get("VulnerabilityID") or ""
            sev = _TRIVY_SEV.get((v.get("Severity") or "").upper(), "info")
            pkg = v.get("PkgName") or ""
            ver = v.get("InstalledVersion") or ""
            fix = v.get("FixedVersion") or ""
            title = v.get("Title") or f"{pkg} {ver}: {cve}"
            out.append(Vuln(
                ip=ip, port=None, protocol="tcp",
                script_id=f"trivy-{cve}", state="finding",
                title=title[:120],
                output=f"target={target}\npkg={pkg} {ver}\nfix={fix}\n\n{v.get('Description','')}"[:3000],
                severity=sev, ids=[cve] if cve else [],
                source="trivy",
                remediation=(f"upgrade {pkg} to {fix}" if fix else "") or "",
                confidence="confirmed"))
    # Also fold misconfiguration + secret results (config / IaC scans)
    for res in d.get("Results") or []:
        for m in res.get("Misconfigurations") or []:
            title = m.get("Title") or m.get("ID") or "misconfig"
            sev = _TRIVY_SEV.get((m.get("Severity") or "").upper(), "info")
            out.append(Vuln(
                ip=ip, port=None, protocol="tcp",
                script_id=f"trivy-cfg-{m.get('ID','')}", state="finding",
                title=title[:120],
                output=(m.get("Description") or "")[:2000],
                severity=sev, source="trivy-config",
                remediation=(m.get("Resolution") or "")[:2000],
                confidence="confirmed"))
        for s in res.get("Secrets") or []:
            out.append(Vuln(
                ip=ip, port=None, protocol="tcp",
                script_id=f"trivy-secret-{s.get('RuleID','')}", state="finding",
                title=f"Secret leaked: {s.get('Title', s.get('RuleID','?'))}",
                output=f"category={s.get('Category','')}\nmatch={s.get('Match','')[:200]}"[:2000],
                severity="high", source="trivy-secret",
                cwes=["CWE-798"], confidence="confirmed"))
    return out


# ---- Grype -------------------------------------------------------------------
# Grype JSON: {"matches":[{"vulnerability":{"id":"CVE-...","severity":"High"},
#              "artifact":{"name":"pkg","version":"1.2.3"}, ...}], "source":{...}}
_GRYPE_SEV = {"critical": "critical", "high": "high", "medium": "medium",
              "low": "low", "negligible": "info", "unknown": "info"}


def parse_grype(text: str) -> list[Vuln]:
    d = _safe_json(text)
    if not isinstance(d, dict):
        return []
    source_target = ""
    src = d.get("source") or {}
    if isinstance(src, dict):
        source_target = (src.get("target") or {}).get("userInput") if isinstance(src.get("target"), dict) else str(src.get("target",""))
        source_target = source_target or src.get("type","")
    ip = f"container:{source_target or 'sbom'}"[:100]
    out: list[Vuln] = []
    for m in d.get("matches") or []:
        v = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        cve = v.get("id") or ""
        sev = _GRYPE_SEV.get((v.get("severity") or "").lower(), "info")
        pkg = art.get("name") or ""
        ver = art.get("version") or ""
        fix_versions = (v.get("fix") or {}).get("versions") or []
        fix = fix_versions[0] if fix_versions else ""
        out.append(Vuln(
            ip=ip, port=None, protocol="tcp",
            script_id=f"grype-{cve}", state="finding",
            title=f"{pkg} {ver}: {cve}"[:120],
            output=(v.get("description") or "")[:2000],
            severity=sev, ids=[cve] if cve else [],
            source="grype",
            remediation=(f"upgrade {pkg} to {fix}" if fix else "") or "",
            confidence="confirmed"))
    return out


PARSERS = {
    "ffuf": parse_ffuf,
    "gobuster": parse_gobuster,
    "trivy": parse_trivy,
    "grype": parse_grype,
}
