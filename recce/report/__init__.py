"""Report renderers: html · docx · excel · markdown.

The four public renderers each build one output format from the engagement
Store. Low-level format writers (raw .docx / .xlsx bytes) live under
report/formats/ — the renderers reach through this subpackage; callers
should import from recce.report.<format>, not from recce.report.formats.<x>.

Backward-compat shims at the old paths (recce/report_html.py, report_docx.py,
report_excel.py, report_markdown.py, docx.py, xlsx.py) re-export the same
symbols so existing `from recce.report_docx import ...` calls keep working.
Callers migrate lazily to `from recce.report.docx import ...`.
"""
