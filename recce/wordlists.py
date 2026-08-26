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

## Env-var fallback

`RECCE_HTTP_WORDLIST` env var: if set to a file path, the HTTP path enum
uses it even when no CLI --wordlist flag is passed. Useful during enum
(where the CLI flag can't reach the deep probe layer).
"""
from __future__ import annotations

import os


def load_wordlist(path: str | None, *, prefix_slash: bool = False) -> list[str]:
    """Read `path`, one value per line. Empty lines + `#` comments dropped.
    If `path` is None or empty, returns [] silently — caller merges with
    its own defaults. Returns [] and prints a warning on read failure
    rather than raising (a bad wordlist must never abort a scan).

    prefix_slash: for HTTP path lists — lines without a leading '/' get
    one prepended (so a dirbuster-style `admin` becomes `/admin`)."""
    if not path:
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = [ln.strip() for ln in fh]
    except OSError as e:
        print(f"[!] wordlist {path!r} not readable ({e}) — using bundled defaults")
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
