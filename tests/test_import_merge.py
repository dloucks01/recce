"""The manual-nmap fallback: `recce import` merges an external nmap scan into an
engagement with NO duplication, and unions in ports recce's own sweep missed.

This is the safety net for "recce didn't find the ports" - run nmap by hand, import
the output, keep going. These tests pin the two guarantees the operator relies on:
re-import is idempotent (no dupes), and a manual scan that finds a high port recce
missed adds it to the existing host without disturbing what's already there.
"""
from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path

from recce import cli
from recce.cli import _open_paths
from recce.core.store import Store


def _nmap_xml(ip: str, ports: list[tuple[int, str, str]]) -> str:
    rows = "".join(
        f'<port protocol="tcp" portid="{pid}"><state state="open" reason="syn-ack"/>'
        f'<service name="{svc}" product="{prod}"/></port>'
        for pid, svc, prod in ports)
    return (
        '<?xml version="1.0"?>\n<nmaprun scanner="nmap">\n'
        f'<host><status state="up" reason="syn-ack"/>'
        f'<address addr="{ip}" addrtype="ipv4"/>'
        f'<ports>{rows}</ports></host>\n</nmaprun>\n')


def _args(files, out_dir):
    return argparse.Namespace(files=files, output_dir=out_dir, title="Import Test",
                              enum_only=True, searchsploit=False)


class ImportMergeTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(self.d, ignore_errors=True))

    def _write(self, name, xml):
        p = Path(self.d) / name
        p.write_text(xml)
        return str(p)

    def _open_ports(self, ip):
        st = Store(_open_paths(self.d)["db"])
        try:
            h = st.get_host(ip)
            return sorted(p.portid for p in h.open_ports) if h else []
        finally:
            st.close()

    def test_reimport_is_idempotent_no_dupes(self):
        f = self._write("scan.xml", _nmap_xml("10.9.9.9", [(80, "http", "nginx"),
                                                            (22, "ssh", "OpenSSH")]))
        self.assertEqual(cli.cmd_import(_args([f], self.d)), 0)
        first = self._open_ports("10.9.9.9")
        self.assertEqual(first, [22, 80])
        # import the exact same file again -> must be a no-op, not doubled
        self.assertEqual(cli.cmd_import(_args([f], self.d)), 0)
        self.assertEqual(self._open_ports("10.9.9.9"), [22, 80])
        # and the ports themselves aren't duplicated in the record
        st = Store(_open_paths(self.d)["db"])
        try:
            h = st.get_host("10.9.9.9")
            keys = [(p.protocol, p.portid) for p in h.ports]
            self.assertEqual(len(keys), len(set(keys)), "ports duplicated on re-import")
            vkeys = [v.key for v in h.vulns]
            self.assertEqual(len(vkeys), len(set(vkeys)), "vulns duplicated on re-import")
        finally:
            st.close()

    def test_manual_scan_unions_a_missed_high_port(self):
        # recce's own sweep only saw 80; a manual `nmap -p-` found a service on a high port.
        recce_scan = self._write("recce.xml", _nmap_xml("10.9.9.9", [(80, "http", "nginx")]))
        self.assertEqual(cli.cmd_import(_args([recce_scan], self.d)), 0)
        manual = self._write("manual.xml", _nmap_xml("10.9.9.9", [(80, "http", "nginx"),
                                                                  (48291, "unknown", "")]))
        self.assertEqual(cli.cmd_import(_args([manual], self.d)), 0)
        # the high port is unioned in; the original stays; no duplication
        self.assertEqual(self._open_ports("10.9.9.9"), [80, 48291])

    def test_import_adds_a_brand_new_host(self):
        a = self._write("a.xml", _nmap_xml("10.9.9.9", [(80, "http", "nginx")]))
        self.assertEqual(cli.cmd_import(_args([a], self.d)), 0)
        b = self._write("b.xml", _nmap_xml("10.9.9.10", [(445, "microsoft-ds", "Samba")]))
        self.assertEqual(cli.cmd_import(_args([b], self.d)), 0)
        st = Store(_open_paths(self.d)["db"])
        try:
            self.assertEqual(len(st.all_hosts()), 2)
        finally:
            st.close()


if __name__ == "__main__":
    unittest.main()


class ConcurrentUpsert(unittest.TestCase):
    """upsert_host must be atomic: concurrent writers to the SAME host can't clobber
    each other's merge (the read-merge-write runs under BEGIN IMMEDIATE). Without it,
    ~all-but-one of N simultaneous same-host updates were lost."""

    def test_concurrent_same_host_upserts_lose_nothing(self):
        import threading
        from recce.core.models import Host, Port
        eng = tempfile.mkdtemp()
        db = _open_paths(eng)["db"]
        Store(db).close()
        N = 40
        gate = threading.Barrier(N)

        def add(port):
            st = Store(db)
            try:
                gate.wait()                       # release together -> maximise overlap
                st.upsert_host(Host(ip="10.0.0.5", state="up",
                                    ports=[Port(portid=port, protocol="tcp", state="open")]))
            finally:
                st.close()
        threads = [threading.Thread(target=add, args=(1000 + i,)) for i in range(N)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        st = Store(db)
        try:
            ports = {p.portid for p in st.get_host("10.0.0.5").open_ports}
        finally:
            st.close()
        self.assertEqual(len(ports), N, f"lost {N - len(ports)} of {N} concurrent upserts")
