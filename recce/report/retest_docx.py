"""Retest report — a per-finding verdict document.

Different shape than the combined findings report: the reader (the client)
wants to see WHAT'S FIXED vs WHAT'S STILL OWED, not a re-litigation of every
finding. So this doc leads with counts, then lists findings under each
verdict heading (still-open first — those are the ones we're here for),
one row per finding with the CVE / IP:port / severity.
"""
from __future__ import annotations

import os

from .formats.docx import Document


_SEV_COLOR = {
    "critical": "E12D39", "high": "F79A25", "medium": "F2CB05",
    "low": "83C46B", "info": "8CA0B4",
}
_VERDICT_HEADING = {
    "still-open": "Still open — not remediated",
    "regressed":  "Regressed — was fixed, now back",
    "new":        "New — introduced since prior engagement",
    "fixed":      "Fixed — remediated since prior engagement",
}


def build_retest_report(verdicts: list, summary: dict, out_path: str, *,
                        title: str = "Retest Report",
                        meta: dict | None = None,
                        eng_dir: str | None = None) -> dict:
    """Write the retest .docx. `verdicts` is the ordered list from
    retest.compare(); `summary` is retest.summary(verdicts). `meta` /
    `eng_dir` are the same branding hooks build_combined uses — cover page
    picks up client/logo/dates when set."""
    meta = meta or {}
    doc = Document()
    if meta.get("client_logo") and eng_dir:
        try:
            with open(os.path.join(eng_dir, meta["client_logo"]), "rb") as fh:
                doc.image(fh.read())
        except OSError:
            pass
    doc.title(title)
    if meta.get("client"):
        doc.para(f"Prepared for: {meta['client']}", bold=True)
    _dates = " – ".join(x for x in (meta.get("start_date"), meta.get("end_date")) if x)
    if _dates:
        doc.para(f"Retest window: {_dates}", italic=True, color="666666")
    _testers = meta.get("testers") or meta.get("tester") or ""
    if _testers:
        doc.para(f"Tester(s): {_testers}", italic=True, color="666666")
    doc.page_break()

    # Summary section — counts at a glance. Still-open leads because that's
    # what a client needs to see first: the work they still owe.
    doc.heading("Summary", 1)
    counts = summary.get("counts", {})
    doc.table(
        ["Still open", "Regressed", "New", "Fixed", "Total"],
        [[str(counts.get("still-open", 0)), str(counts.get("regressed", 0)),
          str(counts.get("new", 0)), str(counts.get("fixed", 0)),
          str(summary.get("total", 0))]],
        widths=[1600, 1600, 1600, 1600, 1600],
        body_colors=[["E12D39", "E12D39", "F79A25", "83C46B", "666666"]],
    )
    doc.para("")
    doc.para(
        "Verdicts are computed by canonical finding key (host:port:CVE / "
        "host:port:script_id). A finding fixed on one port and open on another "
        "on the same host is reported as two verdicts, not one.",
        italic=True, color="666666")

    # One section per verdict, in reader-priority order.
    for kind in ("still-open", "regressed", "new", "fixed"):
        rows = [v for v in verdicts if v["verdict"] == kind]
        if not rows:
            continue
        doc.page_break()
        doc.heading(f"{_VERDICT_HEADING[kind]} ({len(rows)})", 1)
        table_rows = []
        for v in rows:
            host = v["ip"] + (f":{v['port']}" if v.get("port") else "")
            table_rows.append([
                v.get("cve", "") or "-",
                (v.get("severity") or "info").upper() + (" · KEV" if v.get("kev") else ""),
                host, v.get("title", "-")[:80],
            ])
        doc.table(
            ["CVE", "Severity", "Host", "Finding"],
            table_rows,
            widths=[1600, 1300, 1600, 4860],
            body_colors=[
                ["FFFFFF", _SEV_COLOR.get((r[1].split(" ")[0]).lower(), "8CA0B4"),
                 "FFFFFF", "FFFFFF"] for r in table_rows
            ],
        )

    doc.save(out_path)
    return {"path": out_path, "total": summary.get("total", 0),
            "counts": counts}
