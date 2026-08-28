"""Shared helpers extracted from tests/test_workflow.py during its split."""

"""High-fidelity integration tests: the whole workflow end-to-end, with a hard
focus on correctness of the spreadsheet - that the RIGHT fields land on the RIGHT
IP row, that per-IP tracking never bleeds across hosts, and that re-scans/updates
preserve everything.

These drive the real parser -> store -> workbook writer -> read-back -> report
paths (no nmap needed) against the bundled sample scan, whose four hosts each
have a distinct fingerprint:

    10.0.10.10  dc01.corp.local  Windows Server 2019  88,389,445,3389  ms17-010
    10.0.10.25  ws01.corp.local  Windows 10 21H2      135,445,3389     (no vulns)
    10.0.20.5   web01            Linux 5.4            22,80,443        4 vulns
    10.0.20.6   web02            Linux 5.4            22,80,21,3306    ftp-anon
"""

import contextlib
import io
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from recce import ad
from recce.core import parser
from recce.report.formats import xlsx
from recce.core import tracking as tr
from recce.core.models import Host, Port, Vuln
from recce.report.excel import (build_workbook, read_key_order,
                                 read_workbook_edits, read_workbook_tracking,
                                 update_workbook, STATUS_WIP, STATUS_TODO)
from recce.core.store import Store
from recce.core.targets import _subnet_of

SAMPLE = os.path.join(os.path.dirname(parser.__file__), "sample_scan.xml")

# Ground-truth facts, keyed by IP, for cross-checking the spreadsheet.
FACTS = {
    "10.0.10.10": {"host": "dc01.corp.local", "os": "Windows Server 2019",
                   "ports": [88, 389, 445, 3389], "nvulns": 1},
    "10.0.10.25": {"host": "ws01.corp.local", "os": "Windows 10",
                   "ports": [135, 445, 3389], "nvulns": 0},
    "10.0.20.5": {"host": "web01", "os": "Linux",
                  "ports": [22, 80, 443], "nvulns": 4},
    "10.0.20.6": {"host": "web02", "os": "Linux",
                  "ports": [21, 22, 80, 3306], "nvulns": 1},
}


def sample_hosts():
    hosts = parser.parse_nmap_xml(SAMPLE)
    for h in hosts:
        h.subnet = _subnet_of(h.ip)
        h.enumerated = True
    ad.analyze_hosts(hosts)
    return hosts


def header_index(rows, *must_have):
    """Row index of the real column-header row (the first row that holds every
    token in must_have). A legend/note line can precede the header, so we locate
    it instead of assuming row 0."""
    for i, r in enumerate(rows):
        if all(tok in r for tok in must_have):
            return i
    return 0


def rows_by_ip(sheets, title):
    """Return (header, {ip: [row-as-dict, ...]}) for a sheet with an IP column.

    Skips collapsible group-header band rows (they carry a label in the IP column
    but no Key), so callers only see real data rows keyed by a bare IP."""
    rows = sheets[title]
    hidx = header_index(rows, "IP")
    hdr = rows[hidx]
    ipc = hdr.index("IP")
    kidx = hdr.index("Key") if "Key" in hdr else None
    out: dict = {}
    for r in rows[hidx + 1:]:
        if kidx is not None and (len(r) <= kidx or not r[kidx]):
            continue                       # group-header band row - not data
        if len(r) > ipc and r[ipc]:
            out.setdefault(str(r[ipc]), []).append(dict(zip(hdr, r)))
    return hdr, out




# Sample ingest payloads used by test_workflow_ingest.py + test_workflow.py


_LOOT_LINUX = """\
recce-enum  host=web01  user=www-data  Mon Jul 20 12:00:00 UTC 2026

==== System & kernel ====
    Linux web01 5.4.0-42-generic
[!] Old kernel (5.4.0) - run a local-exploit suggester offline

==== Sudo ====
[!] NOPASSWD sudo entries present -> check GTFOBins for the allowed binaries
[!] sudo grants (ALL) ALL -> full root

==== SUID / SGID / capabilities ====
[!] SUID /usr/bin/find - GTFOBins escalation candidate

==== How to exploit (reference for the [!] findings above) ====
  Sudo: NOPASSWD / (ALL) ALL
      sudo <binary> ; see GTFOBins
[!] THIS LINE MUST NOT BE INGESTED (it lives in the how-to section)

==== Writable files & PATH hijack ====
[!] /etc/shadow is READABLE by www-data -> crack hashes
"""


_LOOT_WIN = """\
recce-enum  host=DBSRV01  user=svc_sql  07/20/2026 12:00:00

==== current context ====
[!] Token holds SeImpersonate -> SYSTEM via Potato (GodPotato/PrintSpoofer)

==== AlwaysInstallElevated ====
[!] AlwaysInstallElevated is set (HKLM+HKCU) -> install a malicious MSI as SYSTEM
"""



_GNMAP = ("# Nmap 7.94 scan initiated\n"
          "Host: 10.0.20.6 (web02)\tStatus: Up\n"
          "Host: 10.0.20.6 (web02)\tPorts: 21/open/tcp//ftp//vsftpd 2.3.4/, "
          "22/open/tcp//ssh//OpenSSH 7.4/, 80/open/tcp//http//Apache httpd 2.4.49/"
          "\tIgnored State: closed (997)\n"
          "Host: 10.0.20.6 (web02)\tOS: Linux 5.4\n")
