#!/usr/bin/env python3
"""Live cross-surface count reconciliation sweep.

Point it at a running `recce serve` instance and it pulls every count from the
live APIs (dashboard, Hosts, Findings) and every generated deliverable (HTML
report, xlsx workbook, combined docx), then asserts they all agree. Exits
non-zero on any mismatch, so it doubles as a smoke gate against a deployed
workbench.

    python tools/reconcile.py http://127.0.0.1:8010

The automated form of this check (no live server; runs under pytest over a mock
engagement) lives in tests/test_report_reconciliation.py.
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import tempfile
import urllib.request
import zipfile


def get(base, path, binary=False):
    with urllib.request.urlopen(base + path, timeout=60) as r:
        return r.read() if binary else json.loads(r.read())


def _num(s):
    m = re.search(r"\d+", s or "")
    return int(m.group()) if m else None


def collect(base):
    """Pull every surface's counts into one dict."""
    results = {}

    ov = get(base, "/api/overview")
    sev = ov["by_severity"]
    results["overview"] = {
        "hosts_up": ov["hosts_up"], "open_ports": ov["services"],
        "findings": ov["findings_total"],
        "hc": sev.get("critical", 0) + sev.get("high", 0),
        "kev": ov["kev_total"], "candidates": ov.get("leads_hidden", 0),
    }

    hosts = get(base, "/api/hosts")["items"]
    hf, hl = {}, 0
    for h in hosts:
        for s, n in (h.get("findings") or {}).items():
            hf[s] = hf.get(s, 0) + n
        hl += h.get("leads", 0)
    results["hosts_tab"] = {
        "hosts_up": sum(1 for h in hosts if h.get("up")),
        "findings": sum(hf.values()),
        "hc": hf.get("critical", 0) + hf.get("high", 0),
        "candidates": hl,
    }

    fitems = get(base, "/api/findings")["items"]
    nonlead = [f for f in fitems if f["tier"] != "lead"]
    results["_raw_rows"] = len(fitems)
    results["findings_tab"] = {
        "findings": len(nonlead),
        "hc": sum(1 for f in nonlead if f["severity"] in ("critical", "high")),
        "kev": sum(1 for f in nonlead if f["kev"]),
        "candidates": sum(1 for f in fitems if f["tier"] == "lead"),
    }

    html = get(base, "/api/report/preview/html", binary=True).decode("utf-8", "replace")
    seg = html[html.find("Executive summary"):html.find("Executive summary") + 3000]
    tiles = {}
    for n, label, sub in re.findall(
            r'<div class="n">([^<]+)</div><div class="l">([^<]+)</div>'
            r'(?:<div class="sub">([^<]*)</div>)?', seg):
        tiles[label] = (n, sub)
    results["report_html"] = {
        "hosts_up": _num(tiles.get("Hosts up", ("",))[0]),
        "open_ports": _num(tiles.get("Open ports", ("",))[0]),
        "distinct": _num(tiles.get("Findings", ("",))[0]),
        "findings": _num(tiles.get("Findings", ("", ""))[1]),
        "hc_distinct": _num(tiles.get("High / Critical", ("",))[0]),
        "hc": _num(tiles.get("High / Critical", ("", ""))[1]),
        "kev_distinct": _num(tiles.get("Known-exploited", ("",))[0]),
        "kev": _num(tiles.get("Known-exploited", ("", ""))[1]),
        "candidates": _num(tiles.get("Candidates", ("",))[0]) or 0,
    }

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from recce.report.formats import xlsx
    xl = get(base, "/api/report/xlsx", binary=True)
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as fh:
        fh.write(xl)
        xlpath = fh.name
    try:
        sheets = xlsx.read_sheets(xlpath)
    finally:
        os.unlink(xlpath)

    def kv(name):
        out = {}
        for row in sheets.get(name, []):
            cells = [str(c) for c in row]
            if len(cells) >= 2 and cells[0].strip():
                out[cells[0].strip()] = cells[1:]
        return out
    summ = kv("Summary")

    def sn(label, idx=0):
        v = summ.get(label)
        return _num(v[idx]) if v else None
    results["xlsx_summary"] = {
        "hosts_up": sn("Hosts up"), "open_ports": sn("Open ports"),
        "distinct": sn("Distinct issues"),
        "findings": _num(summ.get("Distinct issues", ["", ""])[1]),
        "hc_distinct": sn("High / Critical"),
        "hc": _num(summ.get("High / Critical", ["", ""])[1]),
        "kev_distinct": sn("Known-exploited (KEV)"),
        "kev": _num(summ.get("Known-exploited (KEV)", ["", ""])[1]),
        "candidates": sn("Candidates") or 0,
    }
    ovs = kv("Overview")
    results["xlsx_overview"] = {
        "open_ports": _num(ovs.get("Open service ports", [""])[0]),
        "findings": _num(ovs.get("Vuln findings", [""])[0]),
        "hc": _num(ovs.get("High / Critical findings", [""])[0]),
        "candidates": _num(ovs.get("Unconfirmed candidates (leads)", [""])[0]),
    }

    dx = get(base, "/api/report/docx", binary=True)
    with zipfile.ZipFile(io.BytesIO(dx)) as z:
        doc = z.read("word/document.xml").decode("utf-8", "replace")
    dtext = re.sub(r"<[^>]+>", "", doc)
    m = re.search(r"(\d+)\s*distinct issue.*?(\d+)\s*finding.*?across\s*(\d+)\s*live host", dtext)
    cand = re.search(r"(\d+)\s*unconfirmed candidate", dtext)
    results["report_docx"] = {
        "distinct": int(m.group(1)) if m else None,
        "findings": int(m.group(2)) if m else None,
        "hosts_up": int(m.group(3)) if m else None,
        "candidates": int(cand.group(1)) if cand else 0,
    }
    return results


def main():
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8010"
    r = collect(base)

    print("=" * 74)
    print(f"RECONCILIATION SWEEP — {base}")
    print("=" * 74)
    for surface, d in r.items():
        if surface.startswith("_"):
            continue
        print(f"\n[{surface}]")
        for k, v in d.items():
            print(f"    {k:14} {v}")

    print("\n" + "=" * 74)
    print("CROSS-SURFACE CHECKS")
    print("=" * 74)
    canon = r["overview"]
    fails = 0

    def chk(name, cond):
        nonlocal fails
        if not cond:
            fails += 1
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}")

    for surface in ("hosts_tab", "findings_tab", "report_html",
                    "xlsx_summary", "xlsx_overview", "report_docx"):
        d = r[surface]
        for key in ("findings", "hc", "kev", "candidates", "hosts_up", "open_ports"):
            if key in d and d[key] is not None and key in canon:
                chk(f"{surface}.{key} == overview.{key} ({d[key]} vs {canon[key]})",
                    d[key] == canon[key])

    distincts = {s: r[s].get("distinct") for s in
                 ("report_html", "xlsx_summary", "report_docx")
                 if r[s].get("distinct") is not None}
    chk(f"distinct issues agree across deliverables {distincts}",
        len(set(distincts.values())) == 1)

    chk(f"findings + candidates == raw rows "
        f"({canon['findings']} + {canon['candidates']} == {r['_raw_rows']})",
        canon["findings"] + canon["candidates"] == r["_raw_rows"])

    print("\n" + ("ALL RECONCILED" if fails == 0 else f"{fails} MISMATCH(ES)"))
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
