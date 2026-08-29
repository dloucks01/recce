"""Cross-service "NTLM relay target" reader and emitter.

Fifth cross-service surface after `known_users`/`known_hostnames`/
`known_hashes`/`known_domains`. Same shape but degenerate: this one is a
FILTER, not a union — but the wire pattern is identical (every SMB probe
already writes `Host.smb_signing`; this reader is what turns that into
an attack payload).

The wire: given all engagement hosts, emit an ntlmrelayx-compatible
target file listing every host that:

  * has SMB open (445 or 139)
  * has SMB signing NOT required (the whole point — signing REQUIRED
    blocks relay of coerced NTLM authentications at the SMB server)
  * is NOT a Domain Controller (a DC that reports "not required" is
    almost always enforced-by-GPO in practice; a rare misconfiguration
    keeps DCs relayable but the routine case is that a relay attempt
    against a DC either fails or authenticates a session that immediately
    gets rejected)

Consumers today: none — recce's `ad.relay_targets()` already returns
the filtered Host list but there is no ntlmrelayx-ready file, so the
operator hand-builds it every engagement. This reader closes that gap.

Output format is one host per line, protocol-prefixed
(`smb://10.0.0.10`) so a single file can drive multiple relay
protocols later without a rewrite. impacket's ntlmrelayx accepts both
`ip` and `proto://ip` in its `-tf` file per its docs.
"""
from __future__ import annotations

import os

from .models import Host


_RELAY_SMB_PORTS = (445, 139)


def _is_dc(host: Host) -> bool:
    return "Domain Controller" in getattr(host, "roles", None) or []


def _has_open_port(host: Host, ports: tuple[int, ...]) -> bool:
    return any(p.portid in ports and p.state == "open"
               for p in getattr(host, "ports", None) or [])


def smb_relay_candidates(hosts: list[Host]) -> list[Host]:
    """Hosts where an SMB relay will actually complete a session.

    Requires all of: 445 or 139 open, `smb_signing == "not required"`,
    and NOT tagged as a DC. Signing set to `"unknown"` is excluded —
    the operator can override with `include_unknown=True` on the file
    writer if they want to try.
    """
    return [h for h in hosts
            if h.smb_signing == "not required"
            and _has_open_port(h, _RELAY_SMB_PORTS)
            and not _is_dc(h)]


def relay_target_lines(hosts: list[Host], *,
                       protocol: str = "smb",
                       include_unknown: bool = False,
                       include_dcs: bool = False) -> list[str]:
    """One line per relayable host, in ntlmrelayx `-tf` file format.

    `include_unknown=True` folds in hosts with `smb_signing == "unknown"`
    (the SMB probe never got a response on that host) — off by default
    because they inflate the target list with false positives.
    `include_dcs=True` folds in DCs — off by default, see module docstring.
    """
    picked: list[str] = []
    for h in hosts:
        if not _has_open_port(h, _RELAY_SMB_PORTS):
            continue
        sig = (h.smb_signing or "").strip().lower()
        if sig == "not required":
            pass
        elif include_unknown and sig in ("", "unknown"):
            pass
        else:
            continue
        if _is_dc(h) and not include_dcs:
            continue
        picked.append(f"{protocol}://{h.ip}")
    return picked


def write_relay_targets(hosts: list[Host], out_path: str, *,
                        protocol: str = "smb",
                        include_unknown: bool = False,
                        include_dcs: bool = False) -> dict:
    """Emit the `-tf` file. Returns summary usable in a CLI print line.

    Returns:
      {"path":              str,      # absolute, so the CLI line is copy-paste
       "count":             int,      # lines written
       "skipped_dcs":       int,      # DCs excluded (relay unlikely to complete)
       "skipped_signed":    int,      # hosts where signing is required
       "skipped_unknown":   int,      # hosts with unknown signing posture
       "protocol":          str}      # scheme prefix used for every line

    File is created 0o600 because the list of "hosts you can relay to"
    is a live attack payload and shouldn't be world-readable if the run
    happens on a shared box.
    """
    lines = relay_target_lines(hosts, protocol=protocol,
                               include_unknown=include_unknown,
                               include_dcs=include_dcs)
    skipped_dcs = sum(1 for h in hosts
                      if _is_dc(h) and _has_open_port(h, _RELAY_SMB_PORTS)
                      and (h.smb_signing or "").strip().lower() == "not required")
    skipped_signed = sum(1 for h in hosts
                         if _has_open_port(h, _RELAY_SMB_PORTS)
                         and (h.smb_signing or "").strip().lower() == "required")
    skipped_unknown = sum(1 for h in hosts
                          if _has_open_port(h, _RELAY_SMB_PORTS)
                          and (h.smb_signing or "").strip().lower()
                          in ("", "unknown")
                          and not include_unknown)
    if lines:
        os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".",
                    exist_ok=True)
        fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            for ln in lines:
                fh.write(ln + "\n")
    else:
        # Nothing to write, but tell the caller the intended path so the
        # CLI can say "no relay targets" against a stable location.
        pass
    return {"path": os.path.abspath(out_path),
            "count": len(lines),
            "skipped_dcs": skipped_dcs,
            "skipped_signed": skipped_signed,
            "skipped_unknown": skipped_unknown,
            "protocol": protocol}
