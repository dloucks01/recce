"""External wordlist loader — shared by every scanner that accepts a
`--wordlist FILE` flag.

Design: bundled Python-literal lists inside each probe module stay the
default; the tester's own wordlist AUGMENTS (not replaces) those defaults
so nothing regresses. The loader is stdlib-only and never fetches from a
URL — the file has to exist on the box, airgap-safe by construction.

## Formats accepted

* One value per line. Blank lines dropped. Lines starting with `#` are
  comments and dropped.
* For credential lists (postgres, mssql), each line is either
  `username:password` or `password` alone (paired with a default user
  the caller supplies).
* For path lists (HTTP), each line is a path starting with `/`. Lines
  without a leading `/` are auto-prefixed.

## Bundled wordlists

recce ships a small curated set of best-in-class wordlists under
`recce/data/wordlists/`. The WebUI presents these as a dropdown; the CLI
accepts them via the `bundled:<name>` syntax on --wordlist (e.g.
`--wordlist bundled:paths-quickhits`). `list_bundled()` enumerates them
by kind; `resolve_wordlist()` turns any user-supplied value (bundled name
or plain path) into an absolute file path.

## Env-var fallback

`RECCE_HTTP_WORDLIST` env var: if set to a file path OR a `bundled:<name>`
identifier, the HTTP path enum uses it even when no CLI --wordlist flag
is passed. Useful during enum (where the CLI flag can't reach the deep
probe layer).
"""
from __future__ import annotations

import os
from pathlib import Path


# Package-relative wordlist directory. Uses __file__ rather than
# importlib.resources so the same path works whether recce is installed as
# a wheel, in editable dev mode, or executed straight from the repo.
_BUNDLED_DIR = Path(__file__).parent / "data" / "wordlists"


# Registry describing each shipped wordlist — the WebUI reads this to
# populate its dropdown. `kind` groups the list by what it's for; the
# frontend filters by kind so the postgres scan-card only shows credential
# lists, not path lists. `blurb` is one short sentence describing scope.
BUNDLED_WORDLISTS: list[dict] = [
    # --- HTTP paths --------------------------------------------------------
    {"name": "paths-quickhits", "kind": "paths",
     "blurb": "~175 highest-signal HTTP paths (VCS, .env, actuator, admin "
              "panels, cloud metadata). Runs in seconds — start here."},
    {"name": "paths-common", "kind": "paths",
     "blurb": "~290 common paths (dirbuster shape, scoped to entries that "
              "actually hit on modern apps + framework admin routes)."},
    {"name": "paths-api", "kind": "paths",
     "blurb": "~185 API-focused paths (OpenAPI/GraphQL/SOAP, gateways, "
              "spec advertisements, common REST endpoints)."},
    {"name": "paths-secrets", "kind": "paths",
     "blurb": "~160 secret file names (.env variants, credentials.*, "
              "private keys, terraform state, CI/CD tokens, DB dumps)."},
    {"name": "paths-lfi", "kind": "paths",
     "blurb": "~70 LFI / path-traversal payloads (../etc/passwd variants, "
              "PHP wrappers, URL-encoded traversal, null-byte tricks)."},
    {"name": "paths-cgi", "kind": "paths",
     "blurb": "~95 /cgi-bin/ paths (Shellshock era + IoT/printer/router "
              "admin CGIs still shipping on embedded devices)."},
    {"name": "paths-cloud", "kind": "paths",
     "blurb": "~100 cloud metadata + SDK config paths (AWS IMDS, GCP, "
              "Azure, DO, OCI + .aws/.docker/.kube/gcloud/terraform)."},
    {"name": "paths-wordpress", "kind": "paths",
     "blurb": "~95 WordPress admin + plugin + REST API (wp-json user "
              "enum) + install/backup artefacts."},
    {"name": "paths-tomcat-java", "kind": "paths",
     "blurb": "~125 Java-stack paths (Tomcat manager, JBoss, WebLogic, "
              "Jenkins, Spring Actuator, Struts, Jolokia)."},
    # --- credentials -------------------------------------------------------
    {"name": "creds-defaults", "kind": "creds",
     "blurb": "~100 most-successful default cred pairs across web apps, "
              "devices, DBs, and infra tooling. `user:password` format."},
    {"name": "creds-web-appliances", "kind": "creds",
     "blurb": "~105 router / printer / IPMI / NAS web-admin defaults "
              "(Cisco, HP iLO, Dell iDRAC, Ubiquiti, Synology, Hikvision)."},
    {"name": "creds-ssh", "kind": "creds",
     "blurb": "~100 SSH defaults + IoT device passwords (Mirai-class + "
              "distro-specific: pi/kali/ubuntu/ec2-user)."},
    {"name": "creds-snmp", "kind": "creds",
     "blurb": "~85 SNMP community strings (public/private + vendor "
              "defaults: Cisco/HP/Ricoh/APC/UPS). Community-only, no user."},
    {"name": "creds-mssql", "kind": "creds",
     "blurb": "~40 sa passwords from common Docker images (Microsoft, "
              "Bitnami) + wild recurring defaults."},
    {"name": "creds-mysql", "kind": "creds",
     "blurb": "~35 MySQL / MariaDB defaults (root/blank first, then "
              "Bitnami / Debian / Ubuntu / docker-quick-start conventions)."},
    {"name": "creds-postgres", "kind": "creds",
     "blurb": "~25 postgres role/password defaults from Docker quick-start "
              "recipes and Debian/Ubuntu package installs."},
    {"name": "creds-mongodb", "kind": "creds",
     "blurb": "~25 default admin credentials for MongoDB quick-start + "
              "Bitnami + Atlas starter-tier examples."},
    {"name": "creds-redis", "kind": "creds",
     "blurb": "~20 Redis requirepass values (foobared, redis, changeme "
              "class) + ACL user pairs for 6.x."},
    # --- usernames ---------------------------------------------------------
    {"name": "users-common", "kind": "users",
     "blurb": "~115 accounts every environment tends to have. Feeds SMTP "
              "enum + Kerberos AS-REP roast + weak-cred sweeps."},
    {"name": "users-linux", "kind": "users",
     "blurb": "~120 standard Linux system users + distro-specific "
              "(pi/kali/ubuntu/ec2-user/oracle) + service DB accounts."},
    {"name": "users-windows-ad", "kind": "users",
     "blurb": "~170 Windows / AD built-in + high-value (Administrator, "
              "krbtgt, sqlservice, exchsvc, SCCM, ADSync)."},
    {"name": "users-service-accounts", "kind": "users",
     "blurb": "~135 svc_/sql_/db_/backup_/scan_/report_ prefixed service "
              "account names for AD Kerberoast + LDAP enum."},
    {"name": "users-smtp", "kind": "users",
     "blurb": "~80 SMTP mailbox-enumeration usernames (root, postmaster, "
              "team/dept aliases) — signal-rich for VRFY/EXPN."},
    # --- subdomains --------------------------------------------------------
    {"name": "subdomains-common", "kind": "subdomains",
     "blurb": "~300 subdomain prefixes for vhost enum + DNS brute — "
              "Assetnote/SecLists highest-hit names, largest-signal first."},
]


def list_bundled(kind: str | None = None) -> list[dict]:
    """Return the bundled wordlist registry entries. Each entry adds a
    `path` (absolute on disk) and `line_count` at read time so the
    frontend can show the size next to the dropdown label. If `kind` is
    given (paths / creds / users), only lists of that kind are returned."""
    out: list[dict] = []
    for entry in BUNDLED_WORDLISTS:
        if kind and entry["kind"] != kind:
            continue
        path = _BUNDLED_DIR / f"{entry['name']}.txt"
        item = dict(entry)
        item["path"] = str(path)
        item["available"] = path.exists()
        item["line_count"] = _count_entries(path) if path.exists() else 0
        out.append(item)
    return out


def _count_entries(path: Path) -> int:
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            return sum(1 for ln in fh
                       if ln.strip() and not ln.strip().startswith("#"))
    except OSError:
        return 0


def resolve_wordlist(value: str | None) -> str | None:
    """Turn a --wordlist value into an absolute file path. Accepts:
    - None or "" → returns None (no wordlist requested)
    - `bundled:<name>` → resolves to `recce/data/wordlists/<name>.txt`
      when the name is in BUNDLED_WORDLISTS; returns None (with a
      warning printed) when the name is unknown so a typo doesn't
      silently degrade to "no wordlist" and confuse the operator
    - any other value → returned as-is (treated as a filesystem path)
    """
    if not value:
        return None
    if value.startswith("bundled:"):
        name = value[len("bundled:"):].strip()
        for entry in BUNDLED_WORDLISTS:
            if entry["name"] == name:
                path = _BUNDLED_DIR / f"{name}.txt"
                if path.exists():
                    return str(path)
                print(f"[!] bundled wordlist {name!r} is registered but "
                      f"missing on disk ({path}) — falling back to defaults")
                return None
        print(f"[!] unknown bundled wordlist {name!r}; "
              f"available: {[e['name'] for e in BUNDLED_WORDLISTS]}")
        return None
    return value


def load_wordlist(path: str | None, *, prefix_slash: bool = False) -> list[str]:
    """Read `path`, one value per line. Empty lines + `#` comments dropped.
    If `path` is None or empty, returns [] silently — caller merges with
    its own defaults. Returns [] and prints a warning on read failure
    rather than raising (a bad wordlist must never abort a scan).

    Accepts either a filesystem path OR a `bundled:<name>` identifier —
    the latter resolves to `recce/data/wordlists/<name>.txt`.

    prefix_slash: for HTTP path lists — lines without a leading '/' get
    one prepended (so a dirbuster-style `admin` becomes `/admin`)."""
    resolved = resolve_wordlist(path)
    if not resolved:
        return []
    try:
        with open(resolved, encoding="utf-8", errors="replace") as fh:
            lines = [ln.strip() for ln in fh]
    except OSError as e:
        print(f"[!] wordlist {resolved!r} not readable ({e}) — using bundled defaults")
        return []
    out: list[str] = []
    seen: set[str] = set()
    for ln in lines:
        if not ln or ln.startswith("#"):
            continue
        if prefix_slash and not ln.startswith("/"):
            ln = "/" + ln
        if ln in seen:
            continue
        seen.add(ln)
        out.append(ln)
    return out


def load_cred_wordlist(path: str | None,
                       default_user: str = "admin") -> list[tuple[str, str]]:
    """Read `path` as a credential wordlist. Each line is either
    `user:password` or `password`. Lines without a `:` pair with
    `default_user` (typical for password-only lists like rockyou.txt-style
    files). Blank lines + `#` comments dropped. Returns [] on read
    failure without raising."""
    lines = load_wordlist(path)
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for ln in lines:
        if ":" in ln:
            u, p = ln.split(":", 1)
            u = u.strip()
            pair = (u, p)
        else:
            pair = (default_user, ln)
        if pair in seen:
            continue
        seen.add(pair)
        out.append(pair)
    return out
