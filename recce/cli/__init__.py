"""Command-line entrypoint for recce.

Subcommands (see `recce -h` for the full, authoritative list):
  Scan/enumerate  enum, scan, vulns, db, privesc, credenum, services
  Import/ingest   import (nmap -oX/-oG/-oN), ingest (on-target loot)
  Post-exploit    exploitplan, attackpath, creds, deploy (mass local-enum)
  Report/track    report, status, review, writeups, writeup
  Utility         demo (bundled sample, no network), doctor (self-test)
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
import tempfile
import time
from concurrent.futures import CancelledError, ThreadPoolExecutor, as_completed

from .. import ad
from .. import exploits
from .. import parser as np
from .. import scanner
from .helpers import *  # noqa: F401,F403 — private-helper re-export
from .parser import (  # noqa: F401 — some re-exported for callers
    build_arg_parser, _print_quickstart, _setup_proxy,
)
from ._scan import *  # noqa: F401,F403
from ._act import *  # noqa: F401,F403
from ._creds import *  # noqa: F401,F403
from ._report import *  # noqa: F401,F403
from ._intake import *  # noqa: F401,F403
from ._services import *  # noqa: F401,F403
from ._db import *  # noqa: F401,F403
from ._ad import *  # noqa: F401,F403
from ._meta import *  # noqa: F401,F403
from .. import tracking as tr
from ..models import Host
from ..report_excel import read_workbook_edits, update_workbook
from ..report_markdown import build_csv, build_markdown
from ..store import Store, StoreError
from ..targets import expand_excludes, explicit_targets, ip_matcher, load_targets

# Canonical severity ordering for sorting findings worst-first (shared by every
# finding-fold path: the deep-service commands and the AD/bloodhound merge).
# The host-timeout auto-retry (a slow truncated host gets one more, longer pass)
# doubles the host-timeout - but capped, so it can't turn a 20-minute default into a
# 40-minute-per-host runaway on a dead/very-slow target. A small timeout still gets a
# real bump up to this floor; a host-timeout already >= this never grows on retry.
# A fast sweep that returns fewer than this many open ports on a non-reliable pass is
# treated as possibly under-reported (a lossy firewall silently dropping SYNs) and gets
# The credential-free deep pass: recce's own stdlib probes. Order is foothold-ish -
# web + protocol posture first, then the heavier service dives. Each no-ops cleanly
# when the datastore has no matching host.
# The authenticated pass: the modules that DO something new once you have creds -
# the netexec/impacket phase plus the authenticated facets of the deep modules. The
# unauth-only modules (web/snmp/mongodb/redis/elasticsearch/rsync/nfs/kerberos/docker/
# k8s) are intentionally absent; you run `sweep` for those. Each handler here keys its
# authenticated path off args.username.
# --- demo command ----------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if getattr(args, "command", None) is None:
        # Bare `recce` (no subcommand): a friendly quickstart beats an argparse error.
        return _print_quickstart()
    _rc = _setup_proxy(args)
    if _rc is not None:
        return _rc
    try:
        return args.func(args)
    except KeyboardInterrupt:
        # A scan phase catches this internally to save partial results; this is the
        # backstop for any command that doesn't, so Ctrl-C is never an ugly crash.
        print("\n[!] Interrupted. Results collected so far were saved; re-run "
              "(with --resume on a scan) to continue.")
        return 130
    except Exception as e:  # noqa: BLE001 - top-level safety net for field use
        # Never dump a raw traceback at a tester mid-engagement. Per-host scan work
        # is already persisted crash-safe, so their data survives; give a clean
        # message and a way to get the details for a bug report.
        print(f"\n[x] recce hit an unexpected error: {type(e).__name__}: {e}")
        if os.environ.get("RECCE_DEBUG"):
            import traceback
            traceback.print_exc()
        else:
            print("    Any data collected so far is saved. Re-run to continue; "
                  "set RECCE_DEBUG=1 to see the full traceback for a bug report.")
        return 1
    finally:
        # Hand the engagement folder back to the sudo-invoking operator on every exit
        # path (success, Ctrl-C, or crash) so a sudo run never leaves them locked out of
        # outputs. _relax_perms restores ownership + OWNER-ONLY perms (dirs 0700, files
        # 0600) - never group/world-readable, since the tree holds captured creds/hashes.
        out_dir = getattr(args, "output_dir", None)
        if out_dir:
            _relax_perms(out_dir)
