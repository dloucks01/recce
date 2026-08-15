"""MITRE ATT&CK technique mapping for recce findings, actions, and attack paths.

Clients (and good reports) want findings tied to ATT&CK techniques, not just CVEs/CWEs.
recce already had the *tactic* scaffolding implicitly - attackpath's kill-chain stages
and the Act archetypes are ATT&CK tactics by another name - but no technique IDs. This
module adds the mapping: a finding / action -> (tactic, technique id, technique name),
plus an engagement-wide coverage summary for the report.

The mapping is a curated, offline table (airgap-safe, no ATT&CK API). It is deliberately
conservative: a finding maps to the single most specific technique recce can justify,
or to nothing (better silent than a wrong T-code in a client deliverable).
"""
from __future__ import annotations

from dataclasses import dataclass

# --- ATT&CK Enterprise tactics (the columns of the matrix) -----------------------
TACTICS = {
    "Reconnaissance": "TA0043",
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege Escalation": "TA0004",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Collection": "TA0009",
    "Command and Control": "TA0011",
    "Impact": "TA0040",
}


@dataclass(frozen=True)
class Technique:
    id: str            # e.g. "T1558.003"
    name: str          # e.g. "Kerberoasting"
    tactic: str        # e.g. "Credential Access"

    @property
    def tactic_id(self) -> str:
        return TACTICS.get(self.tactic, "")

    @property
    def url(self) -> str:
        base = self.id.replace(".", "/")
        return f"https://attack.mitre.org/techniques/{base}/"

    def label(self) -> str:
        return f"{self.id} {self.name} ({self.tactic})"


def _t(id_, name, tactic) -> Technique:
    return Technique(id_, name, tactic)


# --- finding -> technique rules (most specific FIRST; first match wins) -----------
# Each rule: (needle substrings matched against "script_id title", Technique). Kept
# offline and conservative - see module docstring.
_RULES: list[tuple[tuple[str, ...], Technique]] = [
    # Credential Access - AD
    (("kerberoast", "getuserspns", "krb5tgs"), _t("T1558.003", "Kerberoasting", "Credential Access")),
    (("asrep", "as-rep", "getnpusers", "krb5asrep"), _t("T1558.004", "AS-REP Roasting", "Credential Access")),
    (("llmnr", "nbt-ns", "nbns", "smb relay", "ntlm relay", "smb signing not required",
      "smb-security-mode"), _t("T1557.001", "LLMNR/NBT-NS Poisoning and SMB Relay", "Credential Access")),
    (("dcsync", "secretsdump", "ntds", "drsuapi"), _t("T1003.006", "OS Credential Dumping: DCSync", "Credential Access")),
    (("gpp", "cpassword", "groups.xml"), _t("T1552.006", "Unsecured Credentials: Group Policy Preferences", "Credential Access")),
    # Credential Access - unsecured creds / stores
    (("web-git", "gitconfig", "dotenv", ".env", "web-aws", ".aws", "unattend",
      "secret-file", "id_rsa", "private key", "htpasswd"),
     _t("T1552.001", "Unsecured Credentials: Credentials In Files", "Credential Access")),
    (("pg_shadow", "mysql.user", "authentication_string", "password hash"),
     _t("T1555", "Credentials from Password Stores", "Credential Access")),
    (("telnet", "cleartext", "ftp ", "http basic over http", "cleartext management"),
     _t("T1040", "Network Sniffing", "Credential Access")),
    # Discovery / Collection - shares, directory, SNMP. These come BEFORE the generic
    # Valid Accounts rule so a specific "null session shares" finding maps to share
    # discovery, not to the broad T1078.
    (("smb-enum-shares", "network share", "null/guest session", "null session",
      "readable share", "smb shares", "showmount", "nfs export", "world-export",
      "no_root_squash"),
     _t("T1135", "Network Share Discovery", "Discovery")),
    (("ldap-anon", "ldap allows anonymous", "anonymous bind", "rootdse",
      "account discovery", "enum users", "user enumeration"),
     _t("T1087.002", "Account Discovery: Domain Account", "Discovery")),
    (("snmp-info", "snmp public", "mib", "sysdescr"),
     _t("T1602.001", "Data from Configuration Repository: SNMP (MIB Dump)", "Collection")),
    (("axfr", "zone transfer", "dns-nsid"), _t("T1590.002", "Gather Victim Network Information: DNS", "Reconnaissance")),
    # Valid Accounts (default / no-auth logins) - AFTER the specific Discovery rules.
    (("default cred", "default-cred", "default password", "default community",
      "public community", "snmp default"),
     _t("T1078.001", "Valid Accounts: Default Accounts", "Initial Access")),
    (("trust authentication", "trust-auth", "empty password", "empty-password",
      "no password required", "unauth", "without authentication", "anonymous access"),
     _t("T1078", "Valid Accounts", "Initial Access")),
    # Privilege Escalation (local)
    (("privesc", "privilege escalation", "suid", "sudo", "seimpersonate",
      "alwaysinstallelevated", "writable service", "dll hijack", "unquoted service"),
     _t("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation")),
    (("zerologon", "cve-2020-1472", "petitpotam", "printnightmare", "samaccountname",
      "nopac"), _t("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation")),
    # Lateral Movement - exploitation of remote services (network RCE)
    (("eternalblue", "ms17-010", "bluekeep", "cve-2019-0708", "smbghost", "cve-2020-0796",
      "exploitation of remote"),
     _t("T1210", "Exploitation of Remote Services", "Lateral Movement")),
    # Initial Access - public-facing app exploitation (web)
    (("log4shell", "log4j", "sql injection", "sqli", "deserial", "path traversal",
      "arbitrary file", "unauthenticated rce", "unauth rce", "rce", "remote code execution",
      "ssrf", "xxe", "webshell", "actuator"),
     _t("T1190", "Exploit Public-Facing Application", "Initial Access")),
    (("heartbleed", "cve-2014-0160"), _t("T1190", "Exploit Public-Facing Application", "Initial Access")),
]

# --- Act archetype -> technique (for the action plan) ----------------------------
_ARCHETYPE = {
    "loot": _t("T1552", "Unsecured Credentials", "Credential Access"),
    "crack": _t("T1110.002", "Brute Force: Password Cracking", "Credential Access"),
    "spray": _t("T1110.003", "Brute Force: Password Spraying", "Credential Access"),
    "exploit": _t("T1190", "Exploit Public-Facing Application", "Initial Access"),
    "escalate": _t("T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
    "pivot": _t("T1090", "Proxy", "Command and Control"),
    "ad-path": _t("T1003.006", "OS Credential Dumping: DCSync", "Credential Access"),
}

# --- attackpath kill-chain stage -> tactic ---------------------------------------
_STAGE_TACTIC = {
    "Initial Access": "Initial Access",
    "Privilege Escalation": "Privilege Escalation",
    "Credential Access": "Credential Access",
    "Lateral Movement": "Lateral Movement",
    "Domain Dominance": "Impact",
}


def technique_for(vuln) -> Technique | None:
    """The single most specific ATT&CK technique for a finding, or None."""
    text = f"{getattr(vuln, 'script_id', '')} {getattr(vuln, 'title', '')}".lower()
    for needles, tech in _RULES:
        if any(n in text for n in needles):
            return tech
    return None


def technique_for_text(text: str) -> Technique | None:
    lower = (text or "").lower()
    for needles, tech in _RULES:
        if any(n in lower for n in needles):
            return tech
    return None


def technique_for_archetype(archetype: str) -> Technique | None:
    return _ARCHETYPE.get(archetype)


def stage_tactic(stage: str) -> tuple[str, str]:
    """(tactic name, tactic id) for an attackpath stage."""
    name = _STAGE_TACTIC.get(stage, stage)
    return name, TACTICS.get(name, "")


def coverage(hosts) -> dict:
    """Engagement-wide ATT&CK coverage: techniques observed, grouped by tactic, with the
    hosts each was seen on. For the report's ATT&CK section."""
    seen: dict[str, dict] = {}       # technique id -> {technique, hosts:set}
    for h in hosts:
        for v in getattr(h, "vulns", []):
            tech = technique_for(v)
            if not tech:
                continue
            rec = seen.setdefault(tech.id, {"technique": tech, "hosts": set()})
            rec["hosts"].add(h.ip)
    by_tactic: dict[str, list] = {}
    for rec in seen.values():
        tech = rec["technique"]
        by_tactic.setdefault(tech.tactic, []).append(
            {"id": tech.id, "name": tech.name, "url": tech.url,
             "hosts": sorted(rec["hosts"])})
    # order tactics along the kill chain
    order = list(TACTICS)
    ordered = {t: sorted(by_tactic[t], key=lambda x: x["id"])
               for t in order if t in by_tactic}
    return {"by_tactic": ordered,
            "technique_count": len(seen),
            "tactic_count": len(ordered)}
