"""Shared driver for the sequential per-target probe loops in the deep-service
modules.

Every deep module (redis / elasticsearch / rsync / nfs / mongodb / snmp / kerberos /
...) walks its targets one at a time on raw sockets. Left bare, a large target list
with slow or filtered hosts (a /24 with no SNMP, thousands of AS-REP attempts) runs
for many minutes with no output — indistinguishable from a hang — and a Ctrl-C or
crash loses everything probed so far.

`iter_probe` wraps that loop with three properties, all opt-in and behaviour-
preserving when unused:

  * **budget** — an optional wall-clock cap (seconds). Once exceeded the loop stops
    and the caller keeps whatever completed (partial results, not a crash).
  * **progress** — a callback fired before each probe, so the CLI can show
    "[i/N] ip:port …" and the operator can see it working.
  * **Ctrl-C safety** — a KeyboardInterrupt raised during a probe stops the loop and
    yields what already completed, so the caller can still persist partial results.

The stop reason and completed count are reported back through the `state` dict.
"""
from __future__ import annotations

import time


def iter_probe(targets, probe_one, *, budget=None, progress=None, state=None):
    """Yield (target, result) for each target, calling probe_one(target).

    - `budget`: wall-clock seconds; stop early (partial) once exceeded (None = no cap).
    - `progress`: optional callback(done_index, total, target) fired before each probe.
    - `state`: optional dict; on return it carries
        state["stopped"] in (None, "budget", "interrupt")   # why the loop ended
        state["done"]    = number of targets actually probed
        state["total"]   = number of targets requested

    A KeyboardInterrupt during a probe stops the loop cleanly and yields whatever
    completed before it. Exceptions raised by `progress` are swallowed (progress must
    never break a scan).
    """
    st = state if state is not None else {}
    total = len(targets)
    st["stopped"] = None
    st["done"] = 0
    st["total"] = total
    start = time.monotonic()
    for i, t in enumerate(targets, 1):
        if budget is not None and time.monotonic() - start > budget:
            st["stopped"] = "budget"
            return
        if progress is not None:
            try:
                progress(i, total, t)
            except Exception:
                pass
        try:
            r = probe_one(t)
        except KeyboardInterrupt:
            st["stopped"] = "interrupt"
            return
        st["done"] = i
        yield t, r
