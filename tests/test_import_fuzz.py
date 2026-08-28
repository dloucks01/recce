"""Import robustness / fuzz: a malformed, truncated, or mis-encoded file (a scan killed
mid-write, a mangled copy-paste, the wrong file entirely) must NEVER crash the import — the
parser returns [] and the endpoint returns a clean result, so one bad file can't take down
the shared workbench. Deterministic (seeded), always runs.
"""
from __future__ import annotations

import base64
import os
import random
import tempfile
import unittest

from recce.creds import credenum as ce
from recce.intake import importers as im
from recce.core.store import Store

# Realistic-ish seeds for each parser (kept short; the point is the mutations).
SEEDS = {
    "nessus": '<NessusClientData_v2><Report><ReportHost name="1.2.3.4"><HostProperties>'
              '<tag name="host-ip">1.2.3.4</tag></HostProperties><ReportItem severity="4" '
              'pluginID="9" pluginName="x" port="80"><cve>CVE-2021-1</cve></ReportItem>'
              '</ReportHost></Report></NessusClientData_v2>',
    "openvas": '<report><results><result><host>1.2.3.4</host><port>80/tcp</port>'
               '<threat>High</threat><nvt><name>x</name><refs><ref type="cve" id="CVE-2021-1"/>'
               '</refs></nvt></result></results></report>',
    "nuclei": '{"template-id":"x","info":{"name":"n","severity":"high"},"host":"http://1.2.3.4"}\n',
    "testssl": '[{"id":"h","severity":"HIGH","finding":"f","ip":"1.2.3.4","port":"443"}]',
}
SCANNER = {"nessus": im.parse_nessus, "openvas": im.parse_openvas,
           "nuclei": im.parse_nuclei, "testssl": im.parse_testssl}

CRED_SEEDS = {
    "nxc": "SMB 1.2.3.4 445 H [+] d\\u:aad3b435b51404eeaad3b435b51404ee:"
           "31d6cfe0d16ae931b73c59d7e0c089c0 (Pwn3d!)\n",
    "secretsdump": "d\\u:500:aad3b435b51404eeaad3b435b51404ee:"
                   "31d6cfe0d16ae931b73c59d7e0c089c0:::\n",
    "kerberoast": "MSSQLSvc/x  svc  \n$krb5tgs$23$*svc$R$x*$deadbeef\n",
    "asrep": "$krb5asrep$23$u@R:deadbeef\n",
}
CRED_FN = {"nxc": ce.parse_nxc_smb, "secretsdump": ce.parse_secretsdump,
           "kerberoast": ce.parse_getuserspns, "asrep": ce.parse_getnpusers}


def _mutations(seed: str, rng: random.Random):
    """Yield adversarial variants of a seed string."""
    b = seed.encode()
    yield ""                                             # empty
    yield "   \n\t "                                     # whitespace
    yield seed[: len(seed) // 2]                         # truncated (mid-token)
    yield seed[: len(seed) // 3] + seed[2 * len(seed) // 3:]   # spliced
    yield seed * 3                                       # repeated (concatenated)
    yield seed + "\x00\x00\x01\x02\xff"                 # trailing binary
    for _ in range(20):                                  # random byte flips -> latin-1 text
        ba = bytearray(b)
        for _ in range(rng.randint(1, 8)):
            if ba:
                ba[rng.randrange(len(ba))] = rng.randint(0, 255)
        yield ba.decode("latin-1", "replace")
    yield bytes(rng.randint(0, 255) for _ in range(200)).decode("latin-1")   # pure garbage


class ScannerParsersNeverCrash(unittest.TestCase):
    def test_scanner_parsers(self):
        rng = random.Random(1337)
        for name, fn in SCANNER.items():
            for variant in _mutations(SEEDS[name], rng):
                try:
                    out = fn(variant)
                except Exception as e:  # noqa: BLE001
                    self.fail(f"{name} parser raised on a mutation: {e!r}")
                self.assertIsInstance(out, list)

    def test_credential_parsers(self):
        rng = random.Random(4242)
        for name, fn in CRED_FN.items():
            for variant in _mutations(CRED_SEEDS[name], rng):
                try:
                    fn(variant)
                except Exception as e:  # noqa: BLE001
                    self.fail(f"{name} parser raised on a mutation: {e!r}")

    def test_masscan_and_decode_helpers(self):
        from recce.core.parser import parse_masscan_json, parse_masscan_list
        rng = random.Random(99)
        seeds = ["open tcp 80 1.2.3.4 1\n", '[{"ip":"1.2.3.4","ports":[{"port":80,"status":"open"}]}]']
        for seed in seeds:
            for variant in _mutations(seed, rng):
                d = tempfile.mkdtemp()
                p = os.path.join(d, "m")
                open(p, "w").write(variant)
                try:
                    parse_masscan_list(p)
                    parse_masscan_json(p)
                    im.decode_bytes(variant.encode("latin-1", "replace"))
                    im.host_from(variant[:80])
                    im.classify_secret(variant[:40])
                except Exception as e:  # noqa: BLE001
                    self.fail(f"helper raised on a mutation: {e!r}")


class EndpointNeverCrashes(unittest.TestCase):
    def test_endpoint_survives_garbage(self):
        from fastapi.testclient import TestClient
        from recce.webui.app import create_app
        d = tempfile.mkdtemp()
        Store(os.path.join(d, "results.sqlite")).close()
        c = TestClient(create_app(d))
        rng = random.Random(7)
        allseeds = list(SEEDS.values()) + list(CRED_SEEDS.values())
        for seed in allseeds:
            for variant in _mutations(seed, rng):
                raw = variant.encode("latin-1", "replace")
                r = c.post("/api/import", json={"content": base64.b64encode(raw).decode(),
                                                "encoding": "base64", "kind": "auto"})
                self.assertIn(r.status_code, (200, 400, 413, 422),
                              f"unexpected status {r.status_code} for a mutation")
        # the engagement must still be intact + queryable after all that
        self.assertEqual(c.get("/api/engagement").status_code, 200)


if __name__ == "__main__":
    unittest.main()
