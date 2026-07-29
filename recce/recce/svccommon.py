"""Shared helpers for the deep-service modules (smb / ftp / docker / kubernetes /
mssql). They all convert their finding-dicts into Vuln objects the same way,
differing only in the source label, the script_id prefix and the default port -
so that one conversion lives here instead of in five near-identical copies.
"""

from __future__ import annotations

from .models import Evidence, Vuln


def findings_to_vulns(fs: list[dict], source: str, default_port: int,
                      prefix: str | None = None) -> dict:
    """Convert service finding-dicts -> {ip: [Vuln]} (source=<source>), so they feed
    the main severity totals / Vulnerabilities sheet / writeups.

    Each finding's `target` is 'ip' or 'ip:port'; its narrative + command are folded
    into the Vuln output. `prefix` defaults to `source` (kubernetes uses 'k8s').
    """
    prefix = prefix or source
    by_ip: dict[str, list] = {}
    for f in fs:
        parts = f["target"].split(":")
        ip = parts[0]
        port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else default_port
        out_text = f.get("detail", "")
        if f.get("narrative"):
            out_text += f"\n\nWhat this enables:\n{f['narrative']}"
        if f.get("command"):
            out_text += f"\n\nProve / next step:\n{f['command']}"
        by_ip.setdefault(ip, []).append(Vuln(
            ip=ip, port=port, protocol="tcp",
            script_id=f"{prefix}:{f['title'][:40]}", state="finding", title=f["title"],
            severity=f["severity"], source=source, confidence="confirmed",
            cwes=list(f.get("cwes") or ["CWE-284"]),
            output=out_text.strip(), remediation=f.get("remediation", ""),
            # The deep-service modules actively speak the protocol to produce these, so
            # they are live corroborations the verifier can confirm on.
            evidence=[Evidence(kind="live-probe", positive=True, detail=f["title"][:120])]))
    return by_ip
