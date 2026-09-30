"""Auto-loot service — scrape credentials out of arbitrary pasted text.

Recce already has strong per-format parsers (secretsdump, kerberoast,
GPP, .env, netexec, etc.) reachable through the intake/importers path.
This service adds a lighter-weight fallback: scan any text with a set of
regex-based recognisers, so an operator can dump the raw output of any
tool into a text box and have recce fold the credentials into the store.

Recognisers, in order:
- secretsdump NTLM/cleartext rows (user:rid:lm:nt::: and user:CLEARTEXT:pw)
- environment/.env-style KEY=VALUE lines with obvious secret names
- basic user:pass and user:nthash lines (broad match; false-positive-tolerant)

Every extracted credential carries a distinct `source` so the operator can
see where it came from and audit later. Duplicates (same username + secret +
kind) are skipped so re-runs are idempotent.
"""
from __future__ import annotations

import re
from typing import Iterable

from ...core.models import Credential
from ...core.store import Store
from ...creds import credenum


# --- individual scrapers -----------------------------------------------------

def _scrape_secretsdump(text: str) -> Iterable[dict]:
    """Delegate to the existing secretsdump parser — the canonical implementation."""
    for row in credenum.parse_secretsdump(text):
        if row.get("history"):
            continue  # stale rotated hashes must not be sprayed as current
        secret = row.get("secret") or row.get("nt") or ""
        if not secret:
            continue
        yield {
            "username": row.get("name", ""),
            "secret": secret,
            "kind": row.get("kind", "nthash"),
            "source": "auto-loot:secretsdump",
        }


# Keys that scream "this is a password" — kept narrow to avoid scraping every
# KEY=VAL line in a config. Value must be non-placeholder.
_SECRET_KEY_NAMES = "|".join([
    r"(?:DB|DATABASE|MYSQL|POSTGRES|PG|MSSQL|MONGO|REDIS)_PASS(?:WORD)?",
    r"(?:APP|API|SECRET|AUTH|SESSION|JWT|ENCRYPTION|TOKEN)_KEY",
    r"(?:AWS|GCP|AZURE)_(?:SECRET|ACCESS)_KEY(?:_ID)?",
    r"(?:SLACK|GITHUB|GITLAB|SENDGRID|STRIPE|TWILIO)_TOKEN",
    r"(?:ADMIN|ROOT|USER|USERNAME)_(?:PASS|PASSWORD)",
    r"PASSWORD", r"PASSWD",
    r"SECRET_KEY", r"API_KEY", r"ACCESS_TOKEN",
    r"HTTP_BASIC_AUTH", r"SMTP_PASSWORD",
])
_ENV_KEY = re.compile(
    r"(?im)^(?P<key>" + _SECRET_KEY_NAMES + r")"
    r"\s*[=:]\s*(?P<q>[\"']?)(?P<secret>[^\"'\n\r]+?)(?P=q)"
    r"\s*(?:$|#|;)",
)
_PLACEHOLDERS = {"", "*", "***", "****", "*****", "changeme", "change-me",
                 "replace_me", "your_password_here", "xxxxx", "todo",
                 "password", "secret", "example", "test"}


def _scrape_env(text: str) -> Iterable[dict]:
    for m in _ENV_KEY.finditer(text):
        secret = m.group("secret").strip()
        if len(secret) < 6:
            continue
        if secret.lower() in _PLACEHOLDERS:
            continue
        yield {
            "username": m.group("key").upper(),  # the key IS the identity here
            "secret": secret,
            "kind": "password",
            "source": "auto-loot:env",
        }


_USER_PASS = re.compile(
    r"^\s*(?P<user>[A-Za-z0-9._\-]{2,64})\s*:\s*(?P<secret>[!-~]{4,128})\s*$",
    re.MULTILINE,
)
_NTHASH = re.compile(r"\b[a-fA-F0-9]{32}\b")
_LMHASH = _NTHASH  # same shape; kept separate for readability


def _scrape_user_pass(text: str) -> Iterable[dict]:
    """Broad user:pass / user:hash lines. Filters out obvious noise."""
    for m in _USER_PASS.finditer(text):
        user = m.group("user")
        secret = m.group("secret")
        # Skip lines that look like URLs, timestamps, config keys.
        if "://" in user or user.lower() in _PLACEHOLDERS:
            continue
        if secret.count(":") >= 2:
            continue  # probably an ipv6 or a timestamp
        # If the secret is a 32-hex string, call it an nthash.
        kind = "nthash" if _NTHASH.fullmatch(secret) else "password"
        yield {
            "username": user,
            "secret": secret,
            "kind": kind,
            "source": "auto-loot:user:pass",
        }


_SCRAPERS = (_scrape_secretsdump, _scrape_env, _scrape_user_pass)


def extract(text: str) -> list[dict]:
    """Run every scraper and dedupe. Order matters: secretsdump first so its
    canonical rows win over the broad user:pass fallback."""
    seen: set[tuple] = set()
    out: list[dict] = []
    for fn in _SCRAPERS:
        for row in fn(text):
            key = (row["username"].lower(), row["secret"], row["kind"])
            if key in seen:
                continue
            seen.add(key)
            out.append(row)
    return out


# --- public service entry point ---------------------------------------------

def extract_and_persist(db_path: str, text: str, origin_ip: str = "",
                        note: str = "") -> dict:
    """Extract credentials from `text` and add each new one to the store.
    Returns a summary the route hands back to the caller."""
    found = extract(text)
    added: list[dict] = []
    skipped = 0
    with Store(db_path) as st:
        existing = {(c.username.lower(), c.secret, c.kind) for c in st.all_credentials()}
        for row in found:
            key = (row["username"].lower(), row["secret"], row["kind"])
            if key in existing:
                skipped += 1
                continue
            c = Credential(
                username=row["username"], secret=row["secret"],
                kind=row["kind"], source=row["source"],
                origin_ip=origin_ip, notes=note,
            )
            st.add_credential(c)
            existing.add(key)
            added.append({
                "username": c.username, "kind": c.kind, "source": c.source,
                "secret_preview": c.secret[:4] + "…" if len(c.secret) > 6 else c.secret,
            })
    return {"found": len(found), "added": len(added), "skipped_dupes": skipped,
            "credentials": added}
