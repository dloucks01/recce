"""Operator workflow — the guidance layer (docs/WORKFLOW.md).

W1: the next-best-action engine. A pure function over the datastore's existing state
(per-host progress flags + open ports + captured creds) that returns the ranked, most
valuable things to do next — so the tester always knows where they are and the single best
next move, instead of memorising which of 40+ subcommands comes next.

Consumed by `recce next`, echoed at the end of the core commands, and shown in `status`.
Read-only; suggests, never acts.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import db as _db
from . import web as _web

_SMB_WINRM = {139, 445, 5985, 5986}


@dataclass
class Action:
    priority: int    # lower = more valuable right now
    label: str       # what's outstanding ("6 web host(s)")
    command: str     # the exact command to run
    why: str         # one line: why it's worth doing


def _up(hosts):
    return [h for h in hosts if getattr(h, "is_up", True)]


def next_actions(hosts, credentials=None, output_dir: str = "engagement") -> list[Action]:
    """Ranked next steps for this engagement, from current state. Empty only when there is
    genuinely nothing left but to read the report."""
    o = output_dir
    up = _up(hosts)
    acts: list[Action] = []

    if not up:
        return [Action(0, "no hosts scanned yet", f"recce run <targets> -o {o}",
                       "discover, enumerate and vuln-scan the scope in one pass")]

    unscanned = [h for h in up
                 if any(p.state == "open" and not p.vuln_scanned for p in h.open_ports)]
    if unscanned:
        acts.append(Action(10, f"{len(unscanned)} host(s) not vuln-scanned",
                           f"recce vulns -o {o}", "run the vuln + service NSE pass"))

    foot = [h for h in up if getattr(h, "access_gained", False)
            and not getattr(h, "privesc_checked", False)]
    if foot:
        acts.append(Action(12, f"{len(foot)} foothold(s) not priv-esc checked",
                           f"recce privesc -o {o}", "map local priv-esc paths on hosts you own"))

    if credentials:
        acts.append(Action(15, f"{len(credentials)} credential(s) captured",
                           f"recce credsweep -o {o}",
                           "spray the captured creds across the scope for reuse"))

    dbhosts = [h for h in up if not getattr(h, "db_scanned", False)
               and any(_db.engine_for(p) for p in h.open_ports)]
    if dbhosts:
        acts.append(Action(20, f"{len(dbhosts)} database host(s) not enumerated",
                           f"recce db -o {o}", "enumerate the exposed database services"))

    webhosts = [h for h in up if any(_web.is_web(p) for p in h.open_ports)]
    if webhosts:
        acts.append(Action(30, f"{len(webhosts)} web host(s)", f"recce web -o {o}",
                           "screenshot + find login panels / exposed apps"))

    smb = [h for h in up if not getattr(h, "cred_enumerated", False)
           and any(p.portid in _SMB_WINRM for p in h.open_ports)]
    if smb:
        acts.append(Action(40, f"{len(smb)} SMB/WinRM host(s) — if you have creds",
                           f"recce credenum -u USER -p PASS -o {o}",
                           "authenticated SMB/AD enum: shares, users, local-admin reach"))

    findings = sum(len(h.vulns) for h in up)
    if findings:
        acts.append(Action(90, f"{findings} finding(s) collected", f"recce report -o {o}",
                           "regenerate the workbook / write-ups"))
        acts.append(Action(95, "capture the top findings", f"recce writeup <id|CVE|ip> -o {o}",
                           "generate a client-ready write-up with proof"))
    else:
        acts.append(Action(99, "review coverage", f"recce status -o {o}",
                           "see what's left across the scope"))

    acts.sort(key=lambda a: a.priority)
    return acts


def format_next(actions: list[Action], top: int = 1) -> list[str]:
    """Render the top action(s) as tester-facing lines."""
    return [f"-> Next: {a.command}   # {a.why}" for a in actions[:top]]
