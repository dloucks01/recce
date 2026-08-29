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
import socket
import struct

from ..core.models import Host, Port


_DEFAULT_PORT = 631
_TIMEOUT = 4.0


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
              tls: bool = False) -> tuple[int, bytes, str]:
    """Send an IPP request and return (http_status, body, server_header)."""
    conn = None
    try:
        if tls:
            import ssl
            ctx = ssl._create_unverified_context()      # noqa: S323 - printers are self-signed by default
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request("POST", "/", body=body,
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
    status, body, server = _ipp_post(ip, port, _ipp_get_printers(), timeout)
    if not status:
        # Try TLS as a fallback (631 often ends up on https on some appliances)
        status, body, server = _ipp_post(ip, port, _ipp_get_printers(), timeout, tls=True)
        if not status:
            return out
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
                out.append(_finding(
                    "high",
                    "CUPS reachable — check for CVE-2024-47176 chain", tgt,
                    f"CUPS {version} is answering IPP on {tgt}. The Sept-2024 "
                    f"chain (CVE-2024-47176 + -47076 + -47175 + -47177) lets a "
                    f"crafted Get-Printer-Attributes add a printer whose "
                    f"foomatic filter executes attacker commands the next time "
                    f"a print job runs. recce did NOT invoke that path; a fixed "
                    f"CUPS (2.4.9+ / Ubuntu 24.04.1) is not vulnerable.",
                    "review + vendor patch matrix",
                    f"curl -sS -o /dev/null -w '%{{http_code}}\\n' -X POST "
                    f"-H 'Content-Type: application/ipp' --data-binary @/dev/null "
                    f"http://{h.ip}:{p.portid}/     # confirm the reachability",
                    "Update CUPS; disable cups-browsed if not needed (systemctl "
                    "disable cups-browsed); firewall 631/udp and restrict 631/tcp.",
                    ["CWE-77", "CWE-306"], kind="ipp_cups"))
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
