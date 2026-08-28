"""Report download endpoint."""
from __future__ import annotations

import os
import threading

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

from .._common import _REPORTS

_report_lock = threading.Lock()


def register_report_routes(app: FastAPI, ctx) -> None:
    eng_dir = ctx.eng_dir
    db_path = ctx.db_path

    @app.get("/api/report/{kind}")
    def report(kind: str, include: str = ""):
        """Regenerate the deliverables from the live datastore and hand back the
        requested file as a download - byte-for-byte what `recce report` produces
        (same builder), so the UI export and the CLI export never diverge.

        include: same filter as the preview endpoint — comma-separated finding
        keys. Empty = every finding, matching the CLI's default behavior."""
        if kind not in _REPORTS:
            raise HTTPException(404, f"unknown report kind {kind!r}")
        from ...core.store import Store
        from ...cli import _generate_reports, _open_paths
        include_keys = None
        if include.strip():
            include_keys = {k for k in include.split(",") if k}
        paths = _open_paths(eng_dir)
        with _report_lock, Store(db_path) as st:
            title = st.get_meta("engagement") or "recce engagement"
            _generate_reports(st, paths, title, quiet=True, include_keys=include_keys)
        pkey, fname, media = _REPORTS[kind]
        path = paths[pkey]
        if not os.path.exists(path):
            raise HTTPException(500, "report generation produced no file")
        return FileResponse(path, media_type=media, filename=fname)

    @app.get("/api/report/writeup/one")
    def report_writeup(include: str = ""):
        """Per-finding walkthrough .docx from report/docx.build_one_writeup.
        Different SHAPE than the combined report: one document focused on
        one finding, with pre-filled [TESTER: ...] placeholders for the
        fields only the operator can supply (mission risk / difficulty /
        step-by-step walkthrough with screenshots).

        include: a single finding key (from Finding.key). Multiple keys
        aren't supported here — use the combined report."""
        from fastapi.responses import FileResponse
        from ...core.store import Store
        from ...report import docx as _docx
        if not include.strip():
            raise HTTPException(400, "include=<finding_key> required")
        with Store(db_path) as st:
            hosts = st.all_hosts()
        # Frontend key: "vuln:ip:port:script_id:title[:60]" — pass the title
        # tail as selector; if that's ambiguous, fall back to IP:port. The
        # matcher accepts either.
        parts = include.split(":", 4)
        selector = parts[4] if len(parts) == 5 else include
        # Write to the engagement's writeups/ dir directly so the docx
        # persists (matches CLI's `recce writeup` behavior) and there's
        # no tempdir cleanup race with FileResponse.
        eng_out = os.path.join(eng_dir, "writeups")
        os.makedirs(eng_out, exist_ok=True)
        with _report_lock:
            res = _docx.build_one_writeup(hosts, eng_out, selector, overwrite=True)
        matched = res.get("matched", [])
        if len(matched) != 1 or not res.get("written"):
            raise HTTPException(
                404 if not matched else 409,
                f"selector matched {len(matched)} findings — need exactly 1")
        path = res["written"]  # absolute path returned by the builder
        fname = os.path.basename(path)
        return FileResponse(
            path, filename=fname,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")

    @app.get("/api/report/writeup/preview/html")
    def writeup_preview_html(include: str = ""):
        """Live-preview an in-progress per-finding writeup as HTML. Same
        target audience as `/api/report/writeup/one` (which returns .docx),
        but without the Word round-trip — the tester can see the writeup
        shape and [TESTER: …] placeholders directly in the Report Studio
        preview pane. Returns 404 if the selector matches != 1 finding."""
        from fastapi.responses import Response
        from ...core.store import Store
        import html as _html
        if not include.strip():
            raise HTTPException(400, "include=<finding_key> required")
        with Store(db_path) as st:
            hosts = st.all_hosts()
        # Match strategy: prefer EXACT key match (frontend passes the full
        # `vuln:ip:port:sid:title-tail` shape) so the same finding on
        # multiple hosts doesn't collide. Fall back to a title-tail
        # substring for bare selectors from CLI-side callers.
        looks_like_key = include.startswith("vuln:") and include.count(":") >= 4
        matches: list = []
        for h in hosts:
            for v in (h.vulns or []):
                key = f"vuln:{h.ip}:{v.port or 0}:{v.script_id or ''}:{(v.title or '')[:60]}"
                if looks_like_key:
                    if key == include:
                        matches.append((h, v)); break
                else:
                    if include.lower() in (v.title or "").lower():
                        matches.append((h, v)); break
        if len(matches) != 1:
            raise HTTPException(404, f"selector matched {len(matches)} findings — need exactly 1")
        h, v = matches[0]
        # Render an HTML skeleton matching the writeup .docx shape. Uses only
        # tokens the docx template already fills in, so what the tester
        # previews maps 1:1 to what they download. [TESTER:…] placeholders
        # are highlighted so the operator knows what still needs filling in.
        sev = (v.severity or "info").lower()
        sev_color = {"critical": "#dc2626", "high": "#e05d00", "medium": "#c59b07",
                     "low": "#64748b", "info": "#5a6b82"}.get(sev, "#5a6b82")
        # Vuln stores CVE/BID references in `ids`; CWEs in `cwes`.
        cves = ", ".join(x for x in (getattr(v, "ids", None) or []) if x.startswith("CVE-"))
        cwes = ", ".join(getattr(v, "cwes", None) or [])
        def _p(s):
            """Render [TESTER: …] tokens as highlighted spans so the operator
            can spot what's still a placeholder at a glance."""
            import re as _re
            escaped = _html.escape(s or "")
            return _re.sub(
                r"\[TESTER:\s*([^\]]+)\]",
                r'<span style="background:#fff3cd;color:#8a6d3b;padding:2px 6px;border-radius:3px;font-weight:600;">[TESTER: \1]</span>',
                escaped,
            )
        html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Writeup preview — {_html.escape(v.title or '?')}</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 780px; margin: 30px auto; padding: 0 24px; color: #1f2937; line-height: 1.55; }}
  header {{ border-bottom: 3px solid {sev_color}; padding-bottom: 12px; margin-bottom: 20px; }}
  header h1 {{ margin: 0 0 6px; font-size: 22px; color: {sev_color}; }}
  header .meta {{ font-size: 13px; color: #6b7280; }}
  .sev {{ display: inline-block; background: {sev_color}; color: #fff; padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .05em; margin-right: 8px; }}
  h2 {{ margin: 22px 0 8px; font-size: 15px; text-transform: uppercase; letter-spacing: .06em; color: #4b5563; border-left: 3px solid {sev_color}; padding-left: 10px; }}
  pre {{ background: #f3f4f6; padding: 12px; border-radius: 6px; font-size: 12px; white-space: pre-wrap; overflow-wrap: anywhere; }}
  .kv {{ display: grid; grid-template-columns: 140px 1fr; gap: 6px 12px; margin: 8px 0; }}
  .k {{ font-weight: 600; color: #4b5563; }}
  .placeholder {{ color: #92400e; font-style: italic; }}
  .empty {{ color: #9ca3af; font-style: italic; }}
</style></head><body>
<header>
  <h1><span class="sev">{sev}</span>{_html.escape(v.title or '(untitled finding)')}</h1>
  <div class="meta">Host: <code>{_html.escape(h.ip)}</code>
    {' · Port <code>' + str(v.port) + '/' + _html.escape(v.protocol or 'tcp') + '</code>' if v.port else ''}
    {' · ' + _html.escape(h.hostnames[0]) if h.hostnames else ''}
    {' · CVE: ' + _html.escape(cves) if cves else ''}
    {' · CWE: ' + _html.escape(cwes) if cwes else ''}
  </div>
</header>

<h2>Summary</h2>
<p>{_p(v.title or '')}</p>

<h2>Evidence</h2>
{'<pre>' + _html.escape(v.output or '') + '</pre>' if v.output else '<p class="empty">No evidence captured for this finding.</p>'}

<h2>Impact <small class="placeholder">(tester fills in)</small></h2>
<div>{_p('[TESTER: describe the concrete mission impact — data at risk, systems reachable, downstream compromise possible from this finding.]')}</div>

<h2>Reproduction</h2>
<div>{_p('[TESTER: step-by-step commands and observed responses that demonstrate the issue. Attach screenshots via the Evidence upload tab.]')}</div>

<h2>Remediation</h2>
<div>{_p(v.remediation) if v.remediation else '<span class="empty">No remediation guidance recorded.</span>'}</div>

<h2>Difficulty / Risk of exploitation <small class="placeholder">(tester fills in)</small></h2>
<div class="kv">
  <div class="k">Difficulty:</div><div>{_p('[TESTER: trivial / low / moderate / high / theoretical]')}</div>
  <div class="k">Detection likelihood:</div><div>{_p('[TESTER: none / logging / IDS / SIEM alert]')}</div>
  <div class="k">Preconditions:</div><div>{_p('[TESTER: creds required? network position? user interaction?]')}</div>
</div>

<hr style="margin-top:36px;border:0;border-top:1px solid #e5e7eb;">
<p style="font-size:11px;color:#9ca3af;">Preview of the .docx writeup that would be downloaded. Yellow-highlighted <code>[TESTER: …]</code> tokens mark fields the operator supplies before shipping.</p>
</body></html>"""
        return Response(html, media_type="text/html; charset=utf-8",
                        headers={"Cache-Control": "no-store"})

    @app.get("/api/report/preview/html")
    def report_preview_html(include: str = ""):
        """Serve the HTML report INLINE (not as a download) so the Report tab
        can render it in an iframe for live preview. Same builder as the
        download endpoint — the tester sees exactly what they will ship.

        include: optional comma-separated finding keys (from Finding.key on
        the frontend). When set, only those findings appear in the preview —
        the Report Studio uses this to reshape the report live as the tester
        selects/deselects rows."""
        from fastapi.responses import Response
        from ...core.store import Store
        from ...cli import _generate_reports, _open_paths
        include_keys = None
        if include.strip():
            include_keys = {k for k in include.split(",") if k}
        paths = _open_paths(eng_dir)
        with _report_lock, Store(db_path) as st:
            title = st.get_meta("engagement") or "recce engagement"
            _generate_reports(st, paths, title, quiet=True, include_keys=include_keys)
        html_path = paths["html"]
        if not os.path.exists(html_path):
            raise HTTPException(500, "report generation produced no file")
        with open(html_path, "rb") as f:
            data = f.read()
        # X-Frame-Options omitted deliberately so same-origin iframes work.
        return Response(data, media_type="text/html; charset=utf-8",
                        headers={"Cache-Control": "no-store"})
