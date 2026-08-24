import { useEffect, useMemo, useRef, useState } from "react";
import { Finding, SEVS, AttackPath, getAttackPath } from "./api";
import { SevTag, Chips } from "./ui";

type ReportFormat = "xlsx" | "html" | "docx" | "csv" | "md";

const REPORTS: [ReportFormat, string, string][] = [
  ["xlsx", "Excel Workbook", "Structured findings + pivot tables"],
  ["html", "HTML Report", "Interactive web-ready report"],
  ["docx", "Findings Write-ups (Word)", "Detailed write-ups + evidence + remediation"],
  ["csv", "Services CSV", "Discovered services for pivot analysis"],
  ["md", "Markdown", "Machine-readable findings"],
];

interface ReportTabProps {
  findings: Finding[];
  onRefresh?: () => void;
}

// Debounce a value — the include filter changes as fast as the tester clicks,
// but each preview render regenerates the whole report on the server, so wait
// until the click storm settles before firing.
function useDebounced<T>(value: T, delay: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = window.setTimeout(() => setV(value), delay);
    return () => window.clearTimeout(t);
  }, [value, delay]);
  return v;
}

// Report Studio: two-pane layout. Left = triage controls + selection list;
// right = live HTML preview that reshapes to the tester's selection.
// Triage becomes the report; the download is a byproduct.
export function ReportTab({ findings, onRefresh }: ReportTabProps) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastGenerated, setLastGenerated] = useState<Record<ReportFormat, number>>({} as any);
  const [selected, setSelected] = useState<Set<string> | null>(null); // null = "all"
  const [sevFilter, setSevFilter] = useState("all");
  const [searchQ, setSearchQ] = useState("");
  const [showPreview, setShowPreview] = useState(true);
  const [previewKey, setPreviewKey] = useState(0);
  const [narrative, setNarrative] = useState<AttackPath | null>(null);

  const realFindings = useMemo(
    () => findings.filter((f) => f.tier !== "lead"),
    [findings]
  );

  const filtered = useMemo(() => {
    const q = searchQ.toLowerCase();
    return realFindings.filter((f) =>
      (sevFilter === "all" || f.severity === sevFilter) &&
      (!q || `${f.title} ${f.ip} ${f.cve} ${f.port}`.toLowerCase().includes(q))
    );
  }, [realFindings, sevFilter, searchQ]);

  // Live attack narrative for the preview header — the single highest-value
  // insight recce produces, always visible while the tester is composing.
  useEffect(() => {
    getAttackPath().then(setNarrative).catch(() => {});
  }, []);

  // Debounced include-filter string. null = "all findings" (empty include).
  // Selecting/clearing rows shifts this; the iframe re-renders when it changes.
  const includeParam = useMemo(() => {
    if (selected === null) return "";
    return [...selected].join(",");
  }, [selected]);
  const debouncedInclude = useDebounced(includeParam, 800);
  useEffect(() => { setPreviewKey(k => k + 1); }, [debouncedInclude]);

  function toggleFinding(key: string) {
    setSelected((prev) => {
      const start = prev === null ? new Set(realFindings.map(f => f.key)) : new Set(prev);
      if (start.has(key)) start.delete(key); else start.add(key);
      return start;
    });
  }
  function selectVisible() { setSelected(new Set(filtered.map((f) => f.key))); }
  function selectAll() { setSelected(null); }
  function selectNone() { setSelected(new Set()); }

  const isIncluded = (key: string) => selected === null || selected.has(key);
  const includedCount = selected === null ? realFindings.length : selected.size;

  async function downloadReport(format: ReportFormat) {
    setBusy(format); setError(null);
    try {
      const params = includeParam ? `?include=${encodeURIComponent(includeParam)}` : "";
      const r = await fetch(`/api/report/${format}${params}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const blob = await r.blob();
      const cd = r.headers.get("content-disposition") || "";
      const name = /filename="?([^"]+)"?/.exec(cd)?.[1] || `recce.${format}`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = name;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
      setLastGenerated({ ...lastGenerated, [format]: Date.now() });
      onRefresh?.();
    } catch (e) { setError(String(e instanceof Error ? e.message : e)); }
    finally { setBusy(null); }
  }

  // Per-finding writeup: a SEPARATE document shape (report/docx.build_one_writeup),
  // not the combined report shrunk to one finding. Only offered when exactly one
  // finding is selected — that's what the selector needs to be unambiguous.
  async function downloadWriteup() {
    if (!selected || selected.size !== 1) return;
    const [key] = selected;
    setBusy("writeup" as any); setError(null);
    try {
      const r = await fetch(`/api/report/writeup/one?include=${encodeURIComponent(key)}`);
      if (!r.ok) {
        const detail = await r.json().catch(() => ({}));
        throw new Error(detail.detail || `HTTP ${r.status}`);
      }
      const blob = await r.blob();
      const cd = r.headers.get("content-disposition") || "";
      const name = /filename="?([^"]+)"?/.exec(cd)?.[1] || "finding-writeup.docx";
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = name;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
    } catch (e) { setError(String(e instanceof Error ? e.message : e)); }
    finally { setBusy(null); }
  }

  const timeAgo = (ts: number) => {
    const s = Math.round((Date.now() - ts) / 1000);
    if (s < 60) return "just now";
    if (s < 3600) return `${Math.round(s / 60)}m ago`;
    if (s < 86400) return `${Math.round(s / 3600)}h ago`;
    return `${Math.round(s / 86400)}d ago`;
  };

  const previewSrc = `/api/report/preview/html?_=${previewKey}` +
    (debouncedInclude ? `&include=${encodeURIComponent(debouncedInclude)}` : "");

  return (
    <div className="report-studio">
      <div className="rs-header">
        <div>
          <h2>Report Studio</h2>
          <p className="muted">
            Every triage decision reshapes the preview on the right. The download at the
            bottom is byte-for-byte what the tester sees now.
          </p>
        </div>
        <div className="rs-header-count">
          <div className="rs-count-n">{includedCount}<span className="muted">/{realFindings.length}</span></div>
          <div className="muted small">findings included</div>
        </div>
      </div>

      {narrative && narrative.step_count > 0 && (
        <div className="rs-narrative">
          <span className="rs-narrative-label">Attack narrative</span>
          {narrative.narrative.map((line, i) => <p key={i}>{line}</p>)}
        </div>
      )}

      {error && <div className="ranmsg warn-msg">{error}</div>}

      <div className={"rs-body" + (showPreview ? " with-preview" : "")}>
        <div className="rs-controls">
          <div className="rs-controls-h">
            <h3>Select findings</h3>
            <button className="toggle" onClick={() => setShowPreview(v => !v)}>
              {showPreview ? "hide preview" : "show preview"}
            </button>
          </div>

          <div className="rs-filters">
            <Chips value={sevFilter} onChange={setSevFilter} options={["all", ...SEVS]} />
            <input className="search" placeholder="filter…" value={searchQ}
                   onChange={(e) => setSearchQ(e.target.value)} spellCheck={false} />
          </div>
          <div className="rs-selactions">
            <button className="linkish" onClick={selectAll}>all</button>
            <button className="linkish" onClick={selectVisible}>visible ({filtered.length})</button>
            <button className="linkish" onClick={selectNone}>none</button>
          </div>

          <div className="rs-finding-list">
            {filtered.slice(0, 200).map((f) => (
              <label key={f.key} className={`rs-finding ${isIncluded(f.key) ? "in" : "out"}`}>
                <input type="checkbox" checked={isIncluded(f.key)} onChange={() => toggleFinding(f.key)} />
                <SevTag severity={f.severity} />
                <span className="rs-finding-title">{f.title}</span>
                <span className="rs-finding-host mono">{f.ip}{f.port ? `:${f.port}` : ""}</span>
                {f.kev && <span className="badge kev">KEV</span>}
                {f.cve && <span className="rs-finding-cve mono">{f.cve}</span>}
              </label>
            ))}
            {filtered.length > 200 && (
              <div className="muted small" style={{padding: "8px 12px"}}>
                Showing 200 of {filtered.length} — narrow with the filters
              </div>
            )}
            {filtered.length === 0 && (
              <div className="muted" style={{padding: "12px"}}>No findings match this filter</div>
            )}
          </div>
        </div>

        {showPreview && (
          <div className="rs-preview">
            <div className="rs-preview-h">
              <span className="rs-preview-label">Live preview</span>
              <span className="muted small">re-renders 800ms after your last change</span>
              <button className="linkish" onClick={() => setPreviewKey(k => k + 1)}
                      title="force re-render">↻</button>
            </div>
            <iframe key={previewKey} className="rs-preview-frame"
                    src={previewSrc} title="Report preview" />
          </div>
        )}
      </div>

      <div className="rs-downloads">
        <div className="rs-downloads-h">
          <h3>Download</h3>
          <span className="muted small">
            {selected === null || selected.size === realFindings.length
              ? `all ${realFindings.length} findings included`
              : `${selected.size} of ${realFindings.length} findings included`}
          </span>
        </div>
        {selected && selected.size === 1 && (
          <div className="rs-writeup-cta">
            <div className="rs-writeup-body">
              <div className="rs-writeup-title">📝 Per-finding writeup</div>
              <div className="rs-writeup-desc muted small">
                Single-finding walkthrough document with pre-filled [TESTER:…]
                placeholders for mission risk, difficulty, and step-by-step
                reproduction — different shape than the combined report below.
              </div>
            </div>
            <button className="run" onClick={downloadWriteup} disabled={!!busy}>
              {busy === ("writeup" as any) ? "Generating…" : "⬇ Writeup .docx"}
            </button>
          </div>
        )}
        <div className="rs-download-grid">
          {REPORTS.map(([fmt, label, desc]) => (
            <button key={fmt} className="rs-download-card"
                    onClick={() => downloadReport(fmt)} disabled={!!busy}>
              <div className="rs-dl-label">
                <span className="rs-dl-fmt">{fmt.toUpperCase()}</span>
                {lastGenerated[fmt] && <span className="rs-dl-time">{timeAgo(lastGenerated[fmt])}</span>}
              </div>
              <div className="rs-dl-name">{label}</div>
              <div className="rs-dl-desc muted small">{desc}</div>
              <div className="rs-dl-cta">
                {busy === fmt ? "Generating…" : "⬇ Download"}
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
