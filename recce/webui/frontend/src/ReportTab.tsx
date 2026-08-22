import { useState } from "react";

type ReportFormat = "xlsx" | "html" | "docx" | "csv" | "md";

const REPORTS: [ReportFormat, string, string][] = [
  ["xlsx", "Excel Workbook", "Structured findings with pivot tables and sorting"],
  ["html", "HTML Report", "Interactive web-ready report"],
  ["docx", "Findings Write-ups (Word)", "Detailed write-ups with evidence and remediation"],
  ["csv", "Services CSV", "Discovered services and versions for pivot analysis"],
  ["md", "Markdown", "Machine-readable findings in Markdown format"],
];

interface ReportTabProps {
  onRefresh?: () => void;
}

export function ReportTab({ onRefresh }: ReportTabProps) {
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [lastGenerated, setLastGenerated] = useState<Record<ReportFormat, number>>({} as any);

  async function downloadReport(format: ReportFormat) {
    setBusy(format);
    setError(null);
    try {
      const r = await fetch(`/api/report/${format}`);
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
        <p>Generate engagement reports in multiple formats. All reports are built from the live findings database.</p>
      </div>

      {error && <div className="error-banner">{error}</div>}

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
              {busy === fmt ? "Generating…" : "📥 Download"}
            </button>
          </div>
        ))}
      </div>

      <div className="report-info">
        <h3>About reports</h3>
        <ul>
          <li><strong>Excel:</strong> Primary deliverable. Includes all findings, hosts, services, and pivot tables.</li>
          <li><strong>HTML:</strong> Interactive report for sharing via email or browser. Includes severity filters and drill-down.</li>
          <li><strong>Word:</strong> Detailed write-ups for each real finding, with evidence, impact, and remediation guidance.</li>
          <li><strong>CSV:</strong> Services list for pivot analysis, correlation with other datasets, or feed into SIEM.</li>
          <li><strong>Markdown:</strong> Machine-readable findings for CI/CD integration or GitHub issue creation.</li>
        </ul>
      </div>
    </div>
  );
}
