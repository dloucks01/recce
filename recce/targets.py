"""Target parsing and subnet expansion.

Accepts CIDRs, ranges, single IPs, hostnames, and @files. A file line may be a bare
target OR an `IP hostname` pair (space-, tab- or comma-separated, `hosts`-file style) -
the hostname is captured so an authoritative IP+name list flows straight into the
report. Keeps a mapping of each host back to the subnet it belongs to for grouping.
"""

from __future__ import annotations

import ipaddress
import os
import re


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# Refuse to materialise a network bigger than this (a /16). A /8 is 16M addresses and
# an IPv6 /64 is astronomical - expanding either would exhaust memory before any scan.
_MAX_EXPAND = 65536


def _expand_token(token: str) -> list[str]:
    token = token.strip()
    if not token or token.startswith("#"):
        return []
    # CIDR (e.g. 10.0.0.0/24) -> all usable hosts.
    if "/" in token:
        net = ipaddress.ip_network(token, strict=False)
        if net.num_addresses > _MAX_EXPAND:
            raise ValueError(
                f"{token} expands to {net.num_addresses} addresses (max {_MAX_EXPAND}); "
                "split it into smaller subnets (e.g. /16 or narrower)")
        if net.num_addresses <= 2:
            return [str(h) for h in net]  # /31, /32
        return [str(h) for h in net.hosts()]
    # Dash range in the last octet: 10.0.0.10-40. Only a genuine numeric range - a
    # hyphenated hostname (mail-1.corp.example) or a typo (10.0.0.10-) must fall through
    # to be treated as a single target, not crash the whole scope with a ValueError.
    if "-" in token and token.count(".") == 3:
        base, _, tail = token.rpartition(".")
        lo_s, _, hi_s = tail.partition("-")
        if lo_s.isdigit() and hi_s.isdigit() and all(o.isdigit() for o in base.split(".")):
            lo, hi = int(lo_s), int(hi_s)
            if lo <= hi:
                octets = list(range(lo, hi + 1))
                # Drop the /24 network (.0) and broadcast (.255) when the range spans
                # them but has other hosts too - a range like 10.0.0.0-254 means "the
                # subnet", not "scan the network address". A range that is ONLY .0 or
                # .255 is left alone (respect an explicit single-address request).
                if len(octets) > 1:
                    octets = [o for o in octets if o not in (0, 255)]
                return [f"{base}.{o}" for o in octets]
    return [token]  # single IP or hostname


def _subnet_of(ip: str) -> str:
    """Best-effort /24 label for grouping (falls back to the raw value)."""
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    except ValueError:
        return "unresolved"


def _split_ip_hostname(line: str) -> tuple[str, str]:
    """A file line -> (target_token, hostname). An `IP hostname` / `IP,hostname` /
    `IP<tab>hostname` line yields the trailing name ONLY when the target is a single IP
    (a name for a CIDR/range is meaningless). Everything else -> (line, "")."""
    parts = re.split(r"[\s,]+", line.strip())
    if len(parts) >= 2 and _is_ip(parts[0]):
        name = next((p for p in parts[1:] if p and not _is_ip(p) and "/" not in p), "")
        return parts[0], name
    return line, ""


def load_targets(tokens: list[str]) -> tuple[list[str], dict[str, str], dict[str, str]]:
    """Return (ordered unique hosts, {host: subnet_label}, {ip: hostname}).

    A token beginning with '@' is treated as a path to a target file, whose lines may
    be bare targets or `IP hostname` pairs (the name is captured into the third map).
    """
    hosts: list[str] = []
    seen: set[str] = set()
    subnet_map: dict[str, str] = {}
    hostname_map: dict[str, str] = {}

    def add(raw_token: str, subnet_hint: str = "", hostname: str = "") -> None:
        expanded = _expand_token(raw_token)
        for host in expanded:
            if host not in seen:
                seen.add(host)
                hosts.append(host)
                subnet_map[host] = subnet_hint or _subnet_of(host)
            # Only attach a name to a single-IP target (not a CIDR/range expansion).
            if hostname and len(expanded) == 1 and host not in hostname_map:
                hostname_map[host] = hostname

    for token in tokens:
        if token.startswith("@"):
            path = token[1:]
            if not os.path.exists(path):
                raise FileNotFoundError(f"Target file not found: {path}")
            with open(path) as fh:
                for line in fh:
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue
                    target, hostname = _split_ip_hostname(line)
                    # If the file line is itself a CIDR, use it as the subnet label.
                    hint = target if "/" in target else ""
                    add(target, hint, hostname)
        else:
            hint = token if "/" in token else ""
            add(token, hint)

    return hosts, subnet_map, hostname_map


def ip_matcher(tokens: list[str]):
    """Build a predicate(ip)->bool from IP / range / CIDR / @file tokens.

    Used by the post-enum phases (vulns/db/privesc) to select stored hosts by a
    single IP, several IPs, or whole subnets. Empty tokens => match everything.
    """
    flat: list[str] = []
    for t in tokens or []:
        t = t.strip()
        if not t:
            continue
        if t.startswith("@") and os.path.exists(t[1:]):
            with open(t[1:]) as fh:
                flat += [ln.split("#", 1)[0].strip() for ln in fh if ln.strip()]
        else:
            flat.append(t)
    if not flat:
        return lambda ip: True

    nets: list = []
    ips: set[str] = set()
    for t in flat:
        if "/" in t:
            try:
                nets.append(ipaddress.ip_network(t, strict=False))
            except ValueError:
                pass
        elif "-" in t and t.count(".") == 3:
            ips.update(_expand_token(t))
        else:
            ips.add(t)

    def match(ip: str) -> bool:
        if ip in ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in nets)

    return match


def expand_excludes(excludes: list[str]) -> set[str]:
    """Expand exclusion tokens (IPs / ranges / CIDRs / @files) into a flat IP set.
    A token beginning with '@' is a file of exclusions, one per line (# comments ok,
    and an `IP hostname` line contributes just the IP)."""
    out: set[str] = set()
    for token in excludes or []:
        token = token.strip()
        if not token:
            continue
        if token.startswith("@"):
            path = token[1:]
            if not os.path.exists(path):
                raise FileNotFoundError(f"Exclusion file not found: {path}")
            with open(path) as fh:
                for line in fh:
                    line = line.split("#", 1)[0].strip()
                    if line:
                        target, _ = _split_ip_hostname(line)
                        out.update(_expand_token(target))
        else:
            out.update(_expand_token(token))
    return out


def apply_exclusions(hosts: list[str], excludes: list[str]) -> list[str]:
    """Remove any hosts covered by the exclusion tokens (IPs / ranges / CIDRs / @file)."""
    if not excludes:
        return hosts
    excluded = expand_excludes(excludes)
    return [h for h in hosts if h not in excluded]
