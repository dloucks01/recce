"""Helper functions for webui (data formatting, conversion, etc)."""
from __future__ import annotations

import re
from .schemas import CommandFlag, CommandDef


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def cmd(label: str, group: str, targets: str = "optional", profile: bool = False,
        creds: bool = False, lhost: bool = False, flags: list[CommandFlag] | None = None) -> CommandDef:
    """Create a command definition."""
    return CommandDef(
        label=label,
        group=group,
        targets=targets,
        profile=profile,
        creds=creds,
        lhost=lhost,
        flags=flags or []
    )


def flag(name: str, flag_str: str, label: str, active: bool = False) -> CommandFlag:
    """Create a command flag."""
    return CommandFlag(name=name, flag=flag_str, label=label, active=active)


def tier(v) -> str:
    """Severity tier ordering (critical > high > medium > low > info)."""
    return str(_SEV_ORDER.get(v, 999))


def finding_dict(vuln, reviewed: bool = False, notes: str = "") -> dict:
    """Convert a Vuln to a dict for JSON response."""
    return {
        "id": f"{vuln.ip}:{vuln.port}:{vuln.script_id}",
        "ip": vuln.ip,
        "port": vuln.port,
        "title": vuln.title,
        "severity": vuln.severity,
        "output": vuln.output,
        "confidence": vuln.confidence,
        "cwes": vuln.cwes,
        "reviewed": reviewed,
        "notes": notes,
    }


def host_key(ip: str) -> str:
    """Derive a consistent dict key for a host."""
    return ip.replace(":", "_")


def host_dict(h, reviewed: bool = False, notes: str = "") -> dict:
    """Convert a Host to a dict for JSON response."""
    return {
        "ip": h.ip,
        "hostname": h.hostname or "",
        "ports": h.ports,
        "os": h.os or "",
        "reviewed": reviewed,
        "notes": notes,
    }


def import_signatures(content: str, filename: str = "") -> list[str]:
    """Extract signatures from import content (CVEs, hashes, IPs, etc)."""
    sigs = []
    # CVE-XXXX-XXXXX
    sigs.extend(re.findall(r"CVE-\d{4}-\d{4,}", content))
    # CVSS scores
    sigs.extend(re.findall(r"CVSS[:\s]*[\d.]+", content))
    # CWE-XXX
    sigs.extend(re.findall(r"CWE-\d+", content))
    # IP addresses
    sigs.extend(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", content))
    # Domains
    sigs.extend(re.findall(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", content, re.I))
    # Hashes (MD5, SHA1, SHA256)
    sigs.extend(re.findall(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", content, re.I))
    return list(set(sigs))  # Deduplicate


def detect_import_kind(content: str, filename: str = "") -> str:
    """Detect import kind from content/filename."""
    lower_content = content.lower()
    lower_filename = filename.lower()

    if "nmap" in lower_content or ".nmap" in lower_filename or ".xml" in lower_filename:
        return "nmap"
    if "shodan" in lower_content or "shodan" in lower_filename:
        return "shodan"
    if "recce" in lower_content or "recce" in lower_filename:
        return "recce"
    if "masscan" in lower_content or ".gnmap" in lower_filename:
        return "masscan"
    if any(x in lower_content for x in ["ip", "port", "service", "version"]):
        return "csv"
    if "{" in content or "[" in content:
        return "json"

    return "unknown"


def import_preview(kind: str, content: str, raw_bytes: bytes = b"") -> dict:
    """Generate preview for an import."""
    if kind == "nmap":
        # Count hosts/ports from nmap output
        host_count = len(re.findall(r"Nmap scan report for", content))
        port_count = len(re.findall(r"\d+/tcp", content))
        return {
            "kind": "nmap",
            "count": host_count,
            "summary": f"{host_count} hosts, ~{port_count} open ports",
            "items": []
        }

    if kind == "csv":
        lines = content.split("\n")[:10]
        return {
            "kind": "csv",
            "count": len(content.split("\n")),
            "summary": f"{len(lines)} rows",
            "items": lines
        }

    if kind == "json":
        try:
            import json
            data = json.loads(content)
            count = len(data) if isinstance(data, list) else 1
            return {
                "kind": "json",
                "count": count,
                "summary": f"{count} items",
                "items": data[:5] if isinstance(data, list) else [data]
            }
        except:
            pass

    return {
        "kind": kind,
        "count": len(content.split("\n")),
        "summary": f"{len(content)} bytes",
        "items": []
    }
