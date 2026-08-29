"""IPP / CUPS (631/tcp): printer attributes + CVE-2024-47176 exposure check.

CUPS was reported in 2024 to accept an attacker-crafted `Get-Printer-Attributes`
that could add a malicious printer and lead to RCE via the FoomaticRIPCommandLine
filter (CVE-2024-47176 / CVE-2024-47076 / CVE-2024-47175 / CVE-2024-47177). The
one bit a scanner can safely check without invoking anything: is cups-browsed
answering on 631/udp, and is the IPP endpoint on 631/tcp reachable and
identifying itself?

Also useful pre-exploit: which printers are shared, what jobs are queued (job
titles often carry the filename), what URIs the server hands out — all
unauthenticated on many deployments.

One HTTP POST per query, stdlib http.client + struct. Wire format: RFC 8010
(IPP encoding).
"""
from __future__ import annotations

import http.client
import re
import socket
import struct

from ..core.models import Host, Port


_DEFAULT_PORT = 631
_TIMEOUT = 4.0

# IPP status codes we care about (RFC 8011 §5.1). Anything in 0x0000-0x00FF is
# "successful-*", anything 0x0400-0x04FF is "client-error-*" (including 0x0401
# not-authenticated / 0x0403 forbidden), 0x0500-0x05FF is "server-error-*".
_IPP_STATUS_OK = 0x0000
_IPP_STATUS_NOT_AUTH = 0x0401
_IPP_STATUS_FORBIDDEN = 0x0403


def is_ipp(port: Port) -> bool:
    svc = (port.service or "").lower()
    return port.portid == 631 or "ipp" in svc or "cups" in svc


# --- IPP wire ---------------------------------------------------------------

def _ipp_get_printers() -> bytes:
    """CUPS-Get-Printers (0x4002) — unauthenticated printer listing."""
    version = struct.pack("!BB", 1, 1)
    op = struct.pack("!H", 0x4002)
    rid = struct.pack("!I", 1)
    # operation-attributes-tag(0x01), attributes-charset, natural-language, then end-of-attrs(0x03)
    body = (b"\x01"
            + b"\x47" + struct.pack("!H", 18) + b"attributes-charset" + struct.pack("!H", 5) + b"utf-8"
            + b"\x48" + struct.pack("!H", 27) + b"attributes-natural-language" + struct.pack("!H", 5) + b"en-us"
            + b"\x03")
    return version + op + rid + body


def _ipp_post(ip: str, port: int, body: bytes, timeout: float,
              tls: bool = False, path: str = "/") -> tuple[int, bytes, str]:
    """Send an IPP request and return (http_status, body, server_header).

    `path` defaults to "/" (the Get-Printers endpoint on CUPS). RFC 8011
    §4.2.5 endpoints commonly live at /ipp/print or /printers/<name>; the
    caller passes those in when probing Get-Printer-Attributes."""
    conn = None
    try:
        if tls:
            import ssl
            ctx = ssl._create_unverified_context()      # noqa: S323 - printers are self-signed by default
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request("POST", path, body=body,
                     headers={"Content-Type": "application/ipp",
                              "User-Agent": "recce-ipp/1.0"})
        r = conn.getresponse()
        return r.status, r.read(65536), r.getheader("Server") or ""
    except (OSError, http.client.HTTPException, socket.timeout):
        return 0, b"", ""
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


# --- IPP status-code parser (RFC 8011 §5.1) ---------------------------------

def _ipp_status_code(body: bytes) -> int | None:
    """Return the 2-byte IPP status code at offset 2-3 of a response body.

    RFC 8010 §3.1.1 fixes the response header layout as version(2) status(2)
    request-id(4). Returns None when the body is too short to carry a code
    (network dropped, non-IPP response, tunnelled 200-with-empty-body)."""
    if not body or len(body) < 4:
        return None
    try:
        return struct.unpack_from("!H", body, 2)[0]
    except struct.error:
        return None


def _ipp_status_label(code: int | None) -> str:
    """Human-readable label for an IPP status code (RFC 8011 §5.1 families)."""
    if code is None:
        return "no-status"
    if code == _IPP_STATUS_OK:
        return "successful-ok"
    if code == _IPP_STATUS_NOT_AUTH:
        return "client-error-not-authenticated"
    if code == _IPP_STATUS_FORBIDDEN:
        return "client-error-forbidden"
    if 0x0000 <= code <= 0x00FF:
        return f"successful (0x{code:04x})"
    if 0x0400 <= code <= 0x04FF:
        return f"client-error (0x{code:04x})"
    if 0x0500 <= code <= 0x05FF:
        return f"server-error (0x{code:04x})"
    return f"0x{code:04x}"


# --- Get-Printer-Attributes (op 0x000B, RFC 8011 §4.2.5) --------------------

def _ipp_get_printer_attributes(printer_uri: str) -> bytes:
    """Build a benign Get-Printer-Attributes request.

    RFC 8011 §4.2.5: op 0x000B, MUST carry printer-uri. This is the actual
    attacker primitive in the CVE-2024-47176 chain (a crafted variant of
    this op is what cups-browsed accepts to add a rogue printer). recce
    sends a plain, valid request — no injection payload — so the response
    is the ingress-reachability signal on its own.
    """
    version = struct.pack("!BB", 1, 1)
    op = struct.pack("!H", 0x000B)
    rid = struct.pack("!I", 3)
    uri = printer_uri.encode("utf-8", "replace")
    body = (b"\x01"
            + b"\x47" + struct.pack("!H", 18) + b"attributes-charset"
            + struct.pack("!H", 5) + b"utf-8"
            + b"\x48" + struct.pack("!H", 27) + b"attributes-natural-language"
            + struct.pack("!H", 5) + b"en-us"
            + b"\x45" + struct.pack("!H", 11) + b"printer-uri"
            + struct.pack("!H", len(uri)) + uri
            + b"\x03")
    return version + op + rid + body


def get_printer_attributes(ip: str, port: int, printer_uri: str,
                           timeout: float = _TIMEOUT, tls: bool = False,
                           path: str = "/") -> dict:
    """POST a Get-Printer-Attributes op at `path` and return a small
    reachability summary. Detection-only — no exploit payload."""
    body = _ipp_get_printer_attributes(printer_uri)
    status, resp, server = _ipp_post(ip, port, body, timeout, tls=tls, path=path)
    code = _ipp_status_code(resp)
    return {
        "http_status": status,
        "server": server,
        "ipp_status": code,
        "ipp_status_label": _ipp_status_label(code),
        # A successful-ok answer means the ingress endpoint is live AND
        # returns printer attributes to an unauthenticated caller. That is
        # what upgrades the CVE-2024-47176 finding from "reachable CUPS" to
        # "verified ingress path".
        "ingress_verified": bool(status) and code == _IPP_STATUS_OK,
        "attrs": _walk_ipp_attributes(resp) if status else [],
    }


# --- CUPS version gate for the 2024-09 foomatic-rip chain -------------------

# Distro-repackaged CUPS builds that carry the security update even though the
# upstream version is < 2.4.9. Same suffix pattern as the sibling cups_lpd
# module — kept in-file so ipp.py stays self-contained (no shared-file edit).
_DISTRO_FIXED_SUFFIX_RE = re.compile(
    r"(ubuntu[\d.]+\.\d+|op\d+-\d+|deb\d+u\d+|el\d+|~bpo\d+)", re.I)


def _cups_version_vulnerable(version: str,
                             server_header: str = "") -> tuple[bool, str]:
    """Version-gate the CVE-2024-47176 finding.

    Returns (vulnerable, why). Rules (upstream release matrix):
      * upstream >= 2.4.9 -> NOT vulnerable ("fixed").
      * upstream <  2.4.9 -> vulnerable, UNLESS the Server header carries a
        distro-repackaged suffix (Ubuntu SRU, RHEL op-suffix, Debian security
        update, backports) — then downgrade to "distro-backported".
      * empty/unparseable version -> default vulnerable (safer for a scanner
        that must not silently patch away a real exposure)."""
    if not version:
        return True, "no version parsed - default to vulnerable"
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
    if not m:
        return True, f"unparseable version {version!r}"
    tup = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    if tup >= (2, 4, 9):
        return False, f"upstream {version} >= 2.4.9 (fixed)"
    if _DISTRO_FIXED_SUFFIX_RE.search(server_header or version):
        return False, f"distro-backported ({server_header or version})"
    return True, f"upstream {version} < 2.4.9 and no distro-fix marker"


def _walk_ipp_attributes(body: bytes) -> list[dict]:
    """Best-effort parse of the IPP attribute section — pull out printer-name
    and printer-uri-supported entries. Not a full parser; stops on anything it
    doesn't recognise. Enough for a scanner."""
    if len(body) < 9:
        return []
    i = 8               # version(2) + status(2) + request-id(4)
    printers: list[dict] = []
    cur: dict = {}
    while i < len(body):
        tag = body[i]
        i += 1
        if tag == 0x03:                              # end-of-attributes
            if cur:
                printers.append(cur)
            break
        if tag in (0x00, 0x01, 0x02, 0x04, 0x05, 0x06, 0x07):
            # start of a new attribute group
            if cur:
                printers.append(cur)
                cur = {}
            continue
        if tag < 0x08:
            break
        if i + 2 > len(body):
            break
        name_len = struct.unpack_from("!H", body, i)[0]
        i += 2
        name = body[i:i + name_len].decode("ascii", "replace")
        i += name_len
        if i + 2 > len(body):
            break
        val_len = struct.unpack_from("!H", body, i)[0]
        i += 2
        val = body[i:i + val_len]
        i += val_len
        try:
            text = val.decode("utf-8", "replace")
        except UnicodeDecodeError:
            text = val.hex()
        if name:
            cur[name] = text
    if cur and cur not in printers:
        printers.append(cur)
    return printers


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    out: dict = {"reachable": False}
    used_tls = False
    status, body, server = _ipp_post(ip, port, _ipp_get_printers(), timeout)
    if not status:
        # Try TLS as a fallback (631 often ends up on https on some appliances)
        status, body, server = _ipp_post(ip, port, _ipp_get_printers(), timeout, tls=True)
        if not status:
            return out
        used_tls = True
    out["reachable"] = True
    out["http_status"] = status
    out["server"] = server
    # CUPS advertises itself in the Server header; the 2024-47176 chain applies
    # to CUPS specifically (foomatic filter path).
    lower = server.lower()
    out["is_cups"] = "cups" in lower
    if out["is_cups"]:
        # Extract the numeric portion of e.g. "CUPS/2.4.7 (Ubuntu)"
        for tok in server.split():
            if tok.upper().startswith("CUPS/"):
                out["cups_version"] = tok[5:].strip("()")
                break
    if body.startswith(b"\x01") or body[:2] in (b"\x01\x00", b"\x01\x01", b"\x02\x00"):
        out["printers"] = _walk_ipp_attributes(body)
        # RFC 8011 §5.1 status parse — distinguishes an unauth successful-ok
        # from a 200-with-auth-required (0x0401) or forbidden (0x0403).
        code = _ipp_status_code(body)
        if code is not None:
            out["ipp_status"] = code
            out["ipp_status_label"] = _ipp_status_label(code)
    # Version-gate the CVE-2024-47176 finding at probe time so downstream
    # consumers (findings + reporting) share one truth. Additive — leaves
    # existing keys untouched when is_cups is False or version is missing.
    if out.get("is_cups"):
        vuln, why = _cups_version_vulnerable(out.get("cups_version") or "",
                                             server or "")
        out["foomatic_vulnerable"] = vuln
        out["foomatic_gate_reason"] = why
        # Best-effort Get-Printer-Attributes ingress verification. Pick the
        # first printer URI the Get-Printers response gave us; if that op
        # returned nothing usable, hit the CUPS default admin path "/"
        # (harmless — same endpoint we already spoke to).
        uri = ""
        for pr in out.get("printers") or []:
            uri = pr.get("printer-uri-supported") or ""
            if uri:
                break
        if not uri:
            uri = f"ipp://{ip}:{port}/"
        try:
            gpa = get_printer_attributes(ip, port, uri, timeout=timeout,
                                         tls=used_tls)
        except OSError:
            gpa = {}
        # Store under a distinct key so callers with the older shape are
        # unaffected. `ingress_verified=True` means the printer answered a
        # Get-Printer-Attributes successful-ok without credentials — the
        # RFC 8011 §4.2.5 path the 2024 chain enters through.
        if gpa:
            out["get_printer_attrs"] = gpa
            out["ingress_verified"] = bool(gpa.get("ingress_verified"))
    return out


def ipp_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_ipp(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": tool, "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_ipp(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"

            printers = pr.get("printers") or []
            if printers:
                names = ", ".join(
                    p.get("printer-name") or p.get("printer-uri-supported", "?")
                    for p in printers[:8])
                out.append(_finding(
                    "medium",
                    "CUPS/IPP printer list readable unauthenticated", tgt,
                    f"IPP CUPS-Get-Printers returned {len(printers)} printer(s): "
                    f"{names}. Printer share names, job titles and URIs often "
                    f"leak filenames, department structure, and internal hostnames.",
                    "ipptool",
                    f"ipptool -tv ipp://{h.ip}:{p.portid}/printers/ "
                    f"CUPS-Get-Printers.test",
                    "Restrict IPP to trusted networks; disable cups-browsed if "
                    "not required; require authentication on the /admin path.",
                    ["CWE-200"], kind="ipp_printers"))

            if pr.get("is_cups"):
                version = pr.get("cups_version") or "unknown"
                # Version-gate the finding. `foomatic_vulnerable` is set by
                # probe(); for hand-built pr dicts (older callers, tests) the
                # gate is recomputed here so behaviour is stable either way.
                if "foomatic_vulnerable" in pr:
                    vulnerable = bool(pr["foomatic_vulnerable"])
                    why = pr.get("foomatic_gate_reason", "")
                else:
                    vulnerable, why = _cups_version_vulnerable(
                        pr.get("cups_version") or "", pr.get("server") or "")
                # Ingress-verified: a benign Get-Printer-Attributes returned
                # successful-ok. That upgrades the finding from "reachable
                # CUPS" to "verified ingress path" (still detection-only).
                ingress = bool(pr.get("ingress_verified"))
                if vulnerable:
                    ingress_note = ("Get-Printer-Attributes ingress endpoint "
                                    "answered successful-ok unauthenticated — "
                                    "ingress path verified. "
                                    if ingress else
                                    "recce did NOT invoke the exploit path; ")
                    out.append(_finding(
                        "high",
                        "CUPS reachable — check for CVE-2024-47176 chain", tgt,
                        f"CUPS {version} is answering IPP on {tgt}. The Sept-2024 "
                        f"chain (CVE-2024-47176 + -47076 + -47175 + -47177) lets a "
                        f"crafted Get-Printer-Attributes add a printer whose "
                        f"foomatic filter executes attacker commands the next time "
                        f"a print job runs. {ingress_note}"
                        f"Version gate: {why}. A fixed CUPS "
                        f"(2.4.9+ / Ubuntu 24.04.1) is not vulnerable.",
                        "review + vendor patch matrix",
                        f"curl -sS -o /dev/null -w '%{{http_code}}\\n' -X POST "
                        f"-H 'Content-Type: application/ipp' --data-binary @/dev/null "
                        f"http://{h.ip}:{p.portid}/     # confirm the reachability",
                        "Update CUPS; disable cups-browsed if not needed (systemctl "
                        "disable cups-browsed); firewall 631/udp and restrict 631/tcp.",
                        ["CWE-77", "CWE-306"], kind="ipp_cups"))
                else:
                    # Patched build. Emit an informational entry instead of
                    # the high-severity finding so scoring is not FP-heavy on
                    # Ubuntu 24.04.1 / RHEL op-backport hosts. Stable slug.
                    out.append(_finding(
                        "info",
                        "CUPS reachable but past the 2024-09 fixed line", tgt,
                        f"CUPS {version} on {tgt} is past the fixed line for "
                        f"the CVE-2024-47176 foomatic-rip chain ({why}). Keep "
                        f"cups-browsed and 631 exposure restricted — this "
                        f"specific chain is patched but the class of attack "
                        f"is unchanged.",
                        "review",
                        f"curl -sSI http://{h.ip}:{p.portid}/   # confirm "
                        f"the Server header still names CUPS/{version}",
                        "Keep patching cadence; segregate print servers.",
                        [], kind="ipp_cups_patched"))
    return out


def runbook(ip: str, port: int = _DEFAULT_PORT) -> list[dict]:
    return [
        {"phase": "enumerate", "tool": "ipptool",
         "command": f"ipptool -tv ipp://{ip}:{port}/ CUPS-Get-Printers.test",
         "why": "unauth printer list + URIs — job titles disclose filenames"},
        {"phase": "enumerate", "tool": "curl",
         "command": f"curl -i http://{ip}:{port}/printers/",
         "why": "the CUPS web UI is often unauthenticated for reads"},
        {"phase": "exploit", "tool": "review",
         "command": "# CVE-2024-47176 chain (foomatic filter): CUPS < 2.4.9 patched "
                    "line. Do NOT invoke on a live system without ROE.",
         "why": "the 2024 CUPS RCE chain; a scanner should flag, not fire"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from . import svccommon
    return svccommon.findings_to_vulns(fs, "ipp", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = ipp_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["is_cups"] = pr.get("is_cups", False)
                t["printers"] = len(pr.get("printers") or [])
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
