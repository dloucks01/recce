import { useMemo, useState } from "react";
import { Finding, SEVS } from "./api";
import { SevTag, Chips } from "./ui";

type ReportFormat = "xlsx" | "html" | "docx" | "csv" | "md";

const REPORTS: [ReportFormat, string, string][] = [
  ["xlsx", "Excel Workbook", "Structured findings with pivot tables and sorting"],
  ["html", "HTML Report", "Interactive web-ready report"],
  ["docx", "Findings Write-ups (Word)", "Detailed write-ups with evidence and remediation"],
  ["csv", "Services CSV", "Discovered services and versions for pivot analysis"],
  ["md", "Markdown", "Machine-readable findings in Markdown format"],
];

interface ReportTabProps {
  findings: Finding[];
  onRefresh?: () => void;
}

export function ReportTab({ findings, onRefresh }: ReportTabProps) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastGenerated, setLastGenerated] = useState<Record<ReportFormat, number>>({} as any);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [sevFilter, setSevFilter] = useState("all");
  const [searchQ, setSearchQ] = useState("");

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

  function toggleFinding(key: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  }

  function selectAll() {
    setSelected(new Set(filtered.map((f) => f.key)));
  }

  function selectNone() {
    setSelected(new Set());
  }

  async function downloadReport(format: ReportFormat) {
    setBusy(format);
    setError(null);
    try {
      const params = selected.size > 0
        ? `?findings=${Array.from(selected).join(",")}`
        : "";
      const r = await fetch(`/api/report/${format}${params}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const blob = await r.blob();
      const cd = r.headers.get("content-disposition") || "";
      const name = /filename="?([^"]+)"?/.exec(cd)?.[1] || `recce.${format}`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setLastGenerated({ ...lastGenerated, [format]: Date.now() });
      onRefresh?.();
    } catch (e) {
      setError(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(null);
    }
  }

  const timeAgo = (ts: number) => {
    const s = Math.round((Date.now() - ts) / 1000);
    if (s < 60) return "just now";
    if (s < 3600) return `${Math.round(s / 60)}m ago`;
    if (s < 86400) return `${Math.round(s / 3600)}h ago`;
    return `${Math.round(s / 86400)}d ago`;
  };

  return (
    <div className="report-tab">
      <div className="report-header">
        <h2>Reports</h2>
        <p>Generate engagement reports. Select specific findings below, or leave empty to include all.</p>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {/* Finding selector */}
      <div className="rpt-selector">
        <div className="rpt-selector-header">
          <h3>Finding Selection</h3>
          <span className="rpt-sel-count">
            {selected.size > 0
              ? `${selected.size} of ${realFindings.length} selected`
              : `All ${realFindings.length} findings (none selected)`}
          </span>
        </div>

        <div className="rpt-selector-controls">
          <Chips value={sevFilter} onChange={setSevFilter} options={["all", ...SEVS]} />
          <input
            className="search"
            placeholder="Filter findings..."
            value={searchQ}
            onChange={(e) => setSearchQ(e.target.value)}
            spellCheck={false}
          />
          <div className="rpt-sel-actions">
            <button className="toggle" onClick={selectAll}>Select visible</button>
            <button className="toggle" onClick={selectNone}>Clear</button>
          </div>
        </div>

        <div className="rpt-finding-list">
          {filtered.slice(0, 80).map((f) => (
            <label key={f.key} className={`rpt-finding ${selected.has(f.key) ? "checked" : ""}`}>
              <input
                type="checkbox"
                checked={selected.has(f.key)}
                onChange={() => toggleFinding(f.key)}
              />
              <SevTag severity={f.severity} />
              <span className="rpt-finding-title">{f.title}</span>
              <span className="rpt-finding-host mono">{f.ip}{f.port ? `:${f.port}` : ""}</span>
              {f.cve && <span className="rpt-finding-cve mono">{f.cve}</span>}
            </label>
          ))}
          {filtered.length === 0 && (
            <div className="muted" style={{ padding: "12px" }}>No findings match this filter</div>
          )}
          {filtered.length > 80 && (
            <div className="muted" style={{ padding: "8px 12px", fontSize: "12px" }}>
              Showing 80 of {filtered.length} &mdash; use the filter to narrow down
            </div>
          )}
        </div>
      </div>

      {/* Report format cards */}
      <div className="report-grid">
        {REPORTS.map(([fmt, label, desc]) => (
          <div key={fmt} className="report-card">
            <div className="card-header">
              <h3>{label}</h3>
              {lastGenerated[fmt] && (
                <div className="generated-time">Generated {timeAgo(lastGenerated[fmt])}</div>
              )}
            </div>
            <p className="card-desc">{desc}</p>
            <button
              className="run"
              onClick={() => downloadReport(fmt)}
              disabled={!!busy}
            >
              {busy === fmt ? "Generating…" : selected.size > 0 ? `⬇ ${selected.size} findings` : "⬇ All findings"}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
