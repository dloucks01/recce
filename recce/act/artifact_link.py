"""Auto-link a captured artifact to a finding on the same host.

Async-C2 P2. When a shell downloads a file, or a beacon returns an
artifact via /beacon/result, we want that artifact to show up in the
finding drawer next to the KEV/EPSS chip — turning "someone pulled
`/etc/shadow`" into visible proof against the world-readable-shadow
finding automatically, without the operator having to hand-link.

The correlation is intentionally conservative: it links ONLY when a
keyword bridge fires between the task command / artifact path and the
finding's script_id / title. No fuzzy matching, no ML. If nothing
matches, `link_artifact` returns an empty string and the artifact
stays orphaned — which is fine, the operator can still see it under
the host's Artifacts view.

Stdlib-only; no dependencies. Called at the two artifact-capture
sites: /api/sessions/{id}/download and /beacon/result."""
from __future__ import annotations


# Bridge table: (needle in command or path) -> (keywords to match against
# finding.script_id / finding.title / finding.output). The mapping is
# small on purpose — every entry earns its place by being a well-known
# sensitive artefact that a pentest would demonstrably link to a specific
# finding class. Grow it only when field usage justifies each new row.
_HINTS: dict[str, tuple[str, ...]] = {
    # unix credential stores
    "/etc/shadow":     ("shadow", "unshadow", "world_readable", "cred"),
    "/etc/passwd":     ("passwd", "world_readable"),
    "/etc/gshadow":    ("shadow", "gshadow", "cred"),
    "/etc/sudoers":    ("sudoers", "sudo_misconf"),
    # ssh material
    "id_rsa":          ("ssh_key", "world_readable", "key_expos"),
    "id_ecdsa":        ("ssh_key", "world_readable"),
    "id_ed25519":      ("ssh_key", "world_readable"),
    "authorized_keys": ("ssh_key", "authorized_keys"),
    ".ssh/config":     ("ssh_client_conf",),
    # cloud & app creds
    ".aws/credentials": ("aws_creds", "cloud_creds"),
    ".azure":          ("azure_creds", "cloud_creds"),
    "wp-config":       ("wordpress", "wp_config", "cred_disclosure"),
    ".env":            ("env_disclosure", "env_file", "world_readable"),
    "web.config":      ("iis", "web_config"),
    "web-inf/web.xml": ("java_web_conf",),
    # windows / AD dumps
    "ntds.dit":        ("ntds", "ad_dump"),
    "sam.hive":        ("sam", "hive"),
    "system.hive":     ("sam", "hive", "lsa"),
    "secretsdump":     ("sam", "lsa", "ntds"),
    "mimikatz":        ("lsass", "cred_dump", "lsa"),
    "hashdump":        ("sam", "ntds"),
    # kerberos
    "krbtgt":          ("kerberos", "golden"),
    "keytab":          ("keytab", "kerberos"),
    # database
    "backup.sql":      ("db_dump", "backup_disclosure"),
    ".mdb":            ("access_db",),
    ".pgpass":         ("pg_pass", "cred_disclosure"),
    # web app files
    ".git/config":     ("git_exposed", "gitdump"),
    ".htpasswd":       ("htpasswd", "cred_disclosure"),
    # bmc / infra
    "ipmi":            ("ipmi_hash", "ipmi_cipher"),
}


def _match_keywords(command: str, path: str) -> tuple[str, ...]:
    """Every keyword-set whose needle is in the lowered command OR path.
    Multiple hits union (e.g. 'cat /etc/shadow' hits both 'shadow' and
    'passwd' keyword banks — the union makes the finding search fair)."""
    hay = f" {(command or '').lower()} {(path or '').lower()} "
    keywords: list[str] = []
    for needle, kws in _HINTS.items():
        if needle in hay:
            keywords.extend(kws)
    # de-dupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for k in keywords:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return tuple(out)


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def link_artifact(store, host_ip: str, command: str, path: str) -> str:
    """Return the `finding.key` an artifact captured from host `host_ip`
    correlates to, or "" if no bridge fires. Chooses the highest-severity
    match on hits; ties break by KEV, then EPSS, then first-seen order.

    Never raises: a missing host, empty vuln list, or a store error all
    return "" so the artifact still gets indexed."""
    try:
        keywords = _match_keywords(command, path)
        if not keywords:
            return ""
        host = store.get_host(host_ip)
        if host is None:
            return ""
        vulns = list(getattr(host, "vulns", None) or [])
        if not vulns:
            return ""
        # Score each vuln by (any keyword hits) → sort by severity, KEV,
        # EPSS, then original order.
        matches: list[tuple[int, int, float, int, object]] = []
        for i, v in enumerate(vulns):
            hay = " ".join((
                (getattr(v, "script_id", "") or "").lower(),
                (getattr(v, "title", "") or "").lower(),
                (getattr(v, "output", "") or "").lower()[:2000],
            ))
            if not any(k in hay for k in keywords):
                continue
            sev = _SEV_RANK.get((getattr(v, "severity", "info") or "info").lower(), 0)
            kev = 1 if getattr(v, "kev", False) else 0
            epss = float(getattr(v, "epss", 0.0) or 0.0)
            matches.append((sev, kev, epss, -i, v))
        if not matches:
            return ""
        matches.sort(reverse=True)     # highest sev first; tie-break KEV/EPSS
        winner = matches[0][4]
        try:
            return winner.key
        except AttributeError:
            return ""
    except Exception:  # noqa: BLE001 — auto-link must never fail the capture
        return ""
