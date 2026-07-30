"""Normalized data model for enumeration results.

Everything the scanners and parsers produce is coerced into these dataclasses so
the reporting layer never has to care which tool produced the data.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict, fields
from typing import Any


@dataclass
class Script:
    """Output of a single NSE script run against a host or port."""

    id: str
    output: str = ""
    # Structured <elem>/<table> data when nmap provides it.
    elements: dict[str, Any] = field(default_factory=dict)


@dataclass
class Evidence:
    """A single structured observation backing (or disproving) a finding.

    This is what lets the verifier reason about a finding WITHOUT re-parsing free-text
    output: `kind` says how it was observed and `positive` says whether it supports or
    refutes the finding. A negative observation (a patched banner, an NSE 'NOT
    VULNERABLE', an auth-required response) is a first-class refutation, not a special
    string-grep case. See docs/ARCHITECTURE.md §3.2.
    """

    kind: str            # nse | live-probe | version-range | on-target | config-observed
    detail: str = ""     # what was observed (short, human-readable)
    positive: bool = True  # True supports the finding; False disproves it


@dataclass
class Port:
    portid: int
    protocol: str = "tcp"
    state: str = "open"
    reason: str = ""
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    ostype: str = ""
    cpe: list[str] = field(default_factory=list)
    scripts: list[Script] = field(default_factory=list)
    vuln_scanned: bool = False   # tool progress: a vuln pass has run on this port
    servicefp: str = ""          # nmap's raw probe bytes when it couldn't match a signature
    detect_source: str = ""      # how the service label was set: nmap / inferred / banner / local
    banner: str = ""             # raw banner/response text captured by our own probe
    binary: str = ""             # backing executable path (from on-target enum: /proc/<pid>/exe, svc ImagePath)

    @property
    def service_banner(self) -> str:
        """Human-friendly 'product version (extrainfo)' string."""
        parts = [p for p in (self.product, self.version) if p]
        banner = " ".join(parts)
        if self.extrainfo:
            banner = f"{banner} ({self.extrainfo})" if banner else self.extrainfo
        return banner

    @property
    def product_version_key(self) -> str:
        """Stable grouping key: 'product|version' (falls back to service name)."""
        prod = self.product or self.service or "unknown"
        return f"{prod}|{self.version}".strip("|")


@dataclass
class Vuln:
    ip: str
    port: int | None
    protocol: str
    script_id: str
    state: str = ""          # e.g. VULNERABLE, LIKELY VULNERABLE
    title: str = ""
    output: str = ""
    severity: str = "info"   # critical/high/medium/low/info (best-effort)
    ids: list[str] = field(default_factory=list)   # CVE / BID references
    cwes: list[str] = field(default_factory=list)  # CWE weakness references
    source: str = "nse"      # nse | version-db | probe | config
    remediation: str = ""    # how to fix (offline knowledge base)
    confidence: str = ""     # confirmed | likely | potential
    # Quality of Detection (0-100): how RELIABLE the detection method is, orthogonal
    # to severity (which is how bad it is if real). Set once, from the detection
    # method, by recce.qod.annotate(). See docs/ARCHITECTURE.md §3.1. 0 = not yet
    # scored (older store / not annotated).
    qod: int = 0
    qod_type: str = ""       # the named tier, e.g. remote_banner / active_vuln
    # Structured observations backing (or refuting) this finding - the verifier reads
    # these instead of re-parsing `output`. See models.Evidence.
    evidence: list[Evidence] = field(default_factory=list)

    @property
    def key(self) -> str:
        # Include the title so multiple findings on one port (e.g. several
        # version-db matches) don't collide and get deduped away.
        return f"{self.ip}:{self.port}:{self.script_id}:{self.title[:60]}"


@dataclass
class Exploit:
    """A candidate exploit for a service, from an offline DB (searchsploit)."""

    ip: str
    port: int | None
    product: str = ""
    version: str = ""
    edb_id: str = ""
    title: str = ""
    type: str = ""       # remote / local / webapps / dos
    path: str = ""       # local path in exploitdb
    date: str = ""
    cves: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.ip}:{self.port}:{self.edb_id}"


@dataclass
class Credential:
    """A captured/observed credential to stack and spray. Sources: manual capture
    (secretsdump, gpp-decrypt, cracked hashes), AD accounts with a recovered
    secret, default/blank service logins, autologon/stored creds from loot."""

    username: str = ""
    secret: str = ""             # cleartext password, NT hash, or key path
    kind: str = "password"       # password | nthash | ssh-key | blank
    domain: str = ""             # AD domain, or "" for a local account
    source: str = "manual"       # manual / secretsdump / gpp / default / autologon / ad
    origin_ip: str = ""          # host it was captured on
    notes: str = ""

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Credential":
        return cls(**data)

    @property
    def label(self) -> str:
        u = f"{self.domain}\\{self.username}" if self.domain else self.username
        return u or "(anonymous)"

    def dedupe_key(self) -> str:
        return f"{self.domain.lower()}\\{self.username.lower()}|{self.kind}|{self.secret}"


@dataclass
class Account:
    """A user / account / share / domain fact discovered during AD enrichment."""

    ip: str
    source: str          # smb-enum-users, ldap, netexec, ...
    kind: str = "user"   # user / group / share / domain / computer / spn / trust
    name: str = ""
    domain: str = ""
    rid: str = ""
    detail: str = ""
    # Flexible AD attributes: uac flags, spn, memberof, description, os,
    # enabled, admincount, kerberoastable, asrep_roastable, delegation, ...
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class Domain:
    """Domain-level facts assembled from NSE output and/or LDAP enumeration."""

    name: str = ""                 # DNS domain, e.g. corp.local
    netbios: str = ""              # e.g. CORP
    forest: str = ""
    dc_ips: list[str] = field(default_factory=list)
    functional_level: str = ""
    naming_context: str = ""
    machine_account_quota: str = ""
    anonymous_bind: bool = False
    password_policy: dict[str, Any] = field(default_factory=dict)
    trusts: list[dict[str, Any]] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Domain":
        return cls(**data)


@dataclass
class Host:
    ip: str
    subnet: str = ""
    state: str = "up"
    up_reason: str = ""            # nmap status reason: echo-reply / syn-ack / arp-
                                   # response = a real reply (proof of life); "user-set"
                                   # = the -Pn blanket assume-up, which is NOT proof
    hostnames: list[str] = field(default_factory=list)
    mac: str = ""
    vendor: str = ""
    os_name: str = ""
    os_family: str = ""
    os_accuracy: int = 0
    distance: int = 0
    ports: list[Port] = field(default_factory=list)
    vulns: list[Vuln] = field(default_factory=list)
    accounts: list[Account] = field(default_factory=list)
    exploits: list["Exploit"] = field(default_factory=list)
    host_scripts: list[Script] = field(default_factory=list)  # host-level NSE output
    # On-target enum findings folded in via `ingest` (recce-enum.sh/.ps1 [!] lines).
    local_findings: list[dict[str, Any]] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)   # e.g. Domain Controller
    ntlm: dict[str, Any] = field(default_factory=dict)  # domain/fqdn/os from NTLM
    smb_signing: str = ""                            # required / not required / unknown
    defenses: list[str] = field(default_factory=list)  # AV/EDR + posture (from recce-enum)
    # Observed network topology from an on-target enum (its own interfaces/routes/ARP/
    # established connections) — ground truth for host-to-host reachability, folded in
    # via `ingest`. Keys: interfaces[], routes[], neighbors[], peers[].
    topology: dict[str, Any] = field(default_factory=dict)
    incomplete_scan: bool = False  # the port sweep was truncated (host-timeout) -
                                   # the open-port list is PARTIAL, not authoritative
    enumerated: bool = False       # tool progress: service enumeration has run
    db_scanned: bool = False       # the `db` phase ran against this host
    privesc_checked: bool = False  # the `privesc` phase ran against this host
    cred_enumerated: bool = False  # the `credenum` phase ran against this host
    access_gained: bool = False    # recce confirmed a foothold here (valid creds /
                                   # local admin / unauth RCE), or the operator
                                   # recorded one via `recce access`
    access_detail: str = ""        # how access was gained (short, for the report)
    last_scanned: str = ""
    reviewed: bool = False
    notes: str = ""

    @property
    def hostname(self) -> str:
        return self.hostnames[0] if self.hostnames else ""

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == "open"]

    # nmap status reasons that mean the host genuinely REPLIED (proof of life).
    # "user-set" is the -Pn blanket assume-up and does NOT count. "" / "unknown" /
    # "no-response" are non-committal. Everything else is an actual packet back.
    _NOT_A_REPLY = ("", "user-set", "unknown", "no-response", "unknown-response")

    @property
    def is_up(self) -> bool:
        """Positive, defensible proof the host is up. Deliberately conservative in
        one direction only: it must NEVER treat a live host as down (a missed host
        is a hole in the assessment), so ANY concrete sign of life makes it up, and
        only a host with zero evidence at all is treated as not-confirmed-up.

        Signals, any one of which is proof:
          * an open port                 - unambiguous, the host answered a probe
          * a finding / script / account - a service or NSE script got a response
          * a real nmap discovery reply  - echo-reply / syn-ack / arp-response, or
                                           a UDP-fallback reply (NOT the -Pn "user-
                                           set" assume-up, which is not a response)
          * DNS / ARP / OS evidence      - it answered a name/MAC/fingerprint probe

        `enumerated` is deliberately NOT a signal: the pipeline sets it on every host
        it runs the enum phase against, including a dead -Pn IP that answered nothing,
        so it means "we tried", not "it replied".
        """
        if self.open_ports:
            return True
        if (self.vulns or self.host_scripts
                or self.local_findings or self.accounts):
            return True
        if self.up_reason and self.up_reason not in self._NOT_A_REPLY:
            return True
        if self.hostnames or self.mac or self.os_name:
            return True
        return False

    @property
    def status(self) -> str:
        """Auto tool-progress status (distinct from the human Reviewed flag)."""
        if not self.enumerated:
            return "discovered"
        op = self.open_ports
        if not op:
            return "enumerated (no open ports)"
        scanned = sum(1 for p in op if p.vuln_scanned)
        if scanned == 0:
            return "enumerated"
        if scanned == len(op):
            return "vuln-scanned"
        return f"vuln-scanned {scanned}/{len(op)}"

    @property
    def os_guess(self) -> str:
        if self.os_name:
            return f"{self.os_name} ({self.os_accuracy}%)" if self.os_accuracy else self.os_name
        return ""

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Host":
        # Filter each row to the dataclass's known fields so a results.sqlite written by
        # a different recce version (a renamed/removed field) loads instead of raising
        # TypeError and aborting the whole phase.
        def _keep(kls, row):
            allowed = {f.name for f in fields(kls)}
            return {k: v for k, v in row.items() if k in allowed}
        ports = [
            Port(**{**_keep(Port, p),
                    "scripts": [Script(**_keep(Script, s)) for s in p.get("scripts", [])]})
            for p in data.get("ports", [])
        ]
        vulns = [
            Vuln(**{**_keep(Vuln, v),
                    "evidence": [Evidence(**_keep(Evidence, e)) for e in v.get("evidence", [])]})
            for v in data.get("vulns", [])
        ]
        accounts = [Account(**_keep(Account, a)) for a in data.get("accounts", [])]
        exploits = [Exploit(**_keep(Exploit, e)) for e in data.get("exploits", [])]
        host_scripts = [Script(**_keep(Script, s)) for s in data.get("host_scripts", [])]
        core = _keep(cls, {
            k: v
            for k, v in data.items()
            if k not in ("ports", "vulns", "accounts", "exploits", "host_scripts")
        })
        return cls(ports=ports, vulns=vulns, accounts=accounts, exploits=exploits,
                   host_scripts=host_scripts, **core)
