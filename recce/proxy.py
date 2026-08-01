"""Proxy / pivot awareness — make recce proxy-SAFE and proxy-HONEST when the operator
scans an internal segment through a SOCKS / HTTP-CONNECT pivot.

recce does not move the packets itself: the operator's `proxychains4` (or a transparent
tunnel like ligolo/sshuttle) already does that — proxychains LD_PRELOAD-hooks libc
`connect()`, which every stdlib probe recce makes bottoms out in. This module's whole job is
to make recce *aware* it's proxied so it never:

  * scans from the operator's REAL ip via a raw-packet scan (SYN / masscan / ICMP) that
    silently bypasses the proxy — an OPSEC failure, and
  * reports a misleading clean result for UDP traffic (SNMP, SQL Browser) that couldn't
    traverse a TCP proxy — a false negative, the top principle.

Two ways recce becomes proxy-aware:
  1. `--proxy socks5h://host:port` — recce writes a throwaway proxychains conf and RE-EXECS
     itself under proxychains4 so its whole process tree (python probes + tool children) is
     tunneled, then runs in safe/honest mode.
  2. auto-detect — if recce is already running under proxychains (LD_PRELOAD), it turns on
     safe/honest mode with no re-exec, so `proxychains4 recce snmp` can't misfire either.

See docs/PROXY-PIVOT.md. Stdlib only.
"""

from __future__ import annotations

import os
import shutil
import socket
import sys
from urllib.parse import urlparse

# Process-global proxy state, set once at startup (the cli._DEFER_REPORTS idiom). None =>
# no proxy => every path behaves byte-for-byte as it always has.
_PROXY: dict | None = None

# proxychains puts its lib on LD_PRELOAD for the process it launches; we also set our own
# sentinel before re-exec so the launched child knows not to re-exec a second time.
_REEXEC_SENTINEL = "RECCE_PROXIED"

# --proxy schemes we accept (proxychains4 speaks all of these).
_SCHEMES = {"socks5", "socks5h", "socks4a", "socks4", "http"}


class ProxyError(Exception):
    """A bad --proxy URL, or an unreachable / unusable proxy."""


# --- config -------------------------------------------------------------------

def parse(url: str) -> dict:
    """Parse a --proxy URL into a config dict; raise ProxyError on a bad value."""
    u = urlparse(url)
    scheme = (u.scheme or "").lower()
    if scheme not in _SCHEMES:
        raise ProxyError(f"unsupported scheme {u.scheme!r} "
                         "(use socks5h / socks5 / socks4a / http)")
    if not u.hostname or not u.port:
        raise ProxyError(f"proxy needs host:port, got {url!r}")
    return {"scheme": scheme, "host": u.hostname, "port": u.port,
            "user": u.username or "", "password": u.password or "",
            "raw": url, "detected": False}


def configure(url: str | None) -> dict | None:
    """Set the process proxy from a --proxy URL (or clear it when url is falsy)."""
    global _PROXY
    _PROXY = parse(url) if url else None
    return _PROXY


def configure_detected() -> dict:
    """Turn on safe/honest mode without a URL, for a run already wrapped in proxychains
    (LD_PRELOAD). Transport is already handled; we just need to be aware of it."""
    global _PROXY
    _PROXY = {"scheme": "proxychains", "host": "", "port": 0, "user": "",
              "password": "", "raw": "proxychains (LD_PRELOAD)", "detected": True}
    return _PROXY


def reset() -> None:
    """Test helper: drop back to the direct (no-proxy) state."""
    global _PROXY
    _PROXY = None


def is_active() -> bool:
    return _PROXY is not None


def config() -> dict | None:
    return _PROXY


def describe() -> str:
    """Short human string for banners/logs — never includes credentials."""
    if not _PROXY:
        return "direct (no proxy)"
    if _PROXY.get("detected"):
        return "proxychains (detected)"
    return f"{_PROXY['scheme']}://{_PROXY['host']}:{_PROXY['port']}"


def banner_line() -> str:
    """The one-line PROXY banner shown on commands and in the report header."""
    if not _PROXY:
        return ""
    return (f"[PROXY] {describe()} - connect-scan mode (-sT -Pn); masscan + UDP "
            "disabled (they can't traverse the proxy)")


def already_proxied() -> bool:
    """True when recce is ALREADY running under proxychains (our own re-exec, or the
    operator wrapped us) - so we must not re-exec again, and can auto-enable safe mode."""
    if os.environ.get(_REEXEC_SENTINEL) == "1":
        return True
    return "proxychains" in os.environ.get("LD_PRELOAD", "").lower()


# --- proxychains transport (the re-exec model) --------------------------------

def proxychains_bin() -> str:
    """Path to proxychains4 / proxychains, or '' if neither is installed."""
    return shutil.which("proxychains4") or shutil.which("proxychains") or ""


def _pc_proxy_line(cfg: dict) -> str:
    # proxychains ProxyList entry: socks5 / socks4 / http. socks5h -> socks5 (proxy_dns
    # gives the remote-DNS behaviour); socks4a -> socks4.
    kind = {"socks5h": "socks5", "socks5": "socks5", "socks4a": "socks4",
            "socks4": "socks4", "http": "http"}[cfg["scheme"]]
    line = f"{kind} {cfg['host']} {cfg['port']}"
    if cfg["user"]:
        line += f" {cfg['user']} {cfg['password']}"
    return line


def write_proxychains_conf(cfg: dict, path: str) -> str:
    """Write a throwaway proxychains conf for `cfg` at `path`; return the path.
    proxy_dns => internal names (dc.corp.local, kerberos realms) resolve on the pivot,
    not locally — no DNS leak, and names only the pivot can see still resolve."""
    conf = ("# generated by recce --proxy; safe to delete\n"
            "strict_chain\n"
            "quiet_mode\n"
            "proxy_dns\n"
            "tcp_read_time_out 15000\n"
            "tcp_connect_time_out 8000\n"
            "[ProxyList]\n"
            f"{_pc_proxy_line(cfg)}\n")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(conf)
    return path


def reachable(cfg: dict, timeout: float = 6.0) -> bool:
    """TCP-connect to the proxy endpoint itself — fail fast on a dead tunnel rather than
    launch a whole engagement against nothing."""
    try:
        with socket.create_connection((cfg["host"], cfg["port"]), timeout=timeout):
            return True
    except OSError:
        return False


def reexec_argv(conf_path: str, pc_bin: str) -> list[str]:
    """The argv to relaunch this exact recce invocation under proxychains. Split out so it
    can be unit-tested without actually exec'ing."""
    return [pc_bin, "-f", conf_path, sys.executable, "-m", "recce", *sys.argv[1:]]


def reexec_under_proxychains(conf_path: str) -> None:
    """Relaunch recce under proxychains4 so ALL traffic (python probes + tool children)
    tunnels. Replaces this process; only returns if exec fails."""
    pc = proxychains_bin()
    env = dict(os.environ)
    env[_REEXEC_SENTINEL] = "1"
    os.execvpe(pc, reexec_argv(conf_path, pc), env)
