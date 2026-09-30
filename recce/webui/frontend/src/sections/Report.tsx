// Report — generate the client deliverables + engagement metadata, with a live
// HTML preview. By default every finding is included; the "Only in-report" toggle
// narrows the deliverable to findings triaged to the in-report status.
import { useEffect, useMemo, useRef, useState } from "react";
import { EngagementMeta, getEngagementMeta, setEngagementMeta } from "../api";
import { SectionProps } from "../nav";
import { Panel, Chip } from "../kit";
import { toast } from "../toast";

const FORMATS: [string, string][] = [["html", "HTML report"], ["xlsx", "Excel workbook"], ["docx", "DOCX write-ups"], ["csv", "CSV"], ["md", "Markdown"]];
const META_FIELDS: [keyof EngagementMeta, string][] = [
  ["engagement", "Engagement name"], ["client", "Client"], ["tester", "Lead tester"],
  ["testers", "Team (comma-sep)"], ["start_date", "Start date"], ["end_date", "End date"],
];

export function Report({ data }: SectionProps) {
  const [meta, setMeta] = useState<EngagementMeta>({});
  const [busy, setBusy] = useState("");
  const [bust, setBust] = useState(Date.now());
  const [onlyInReport, setOnlyInReport] = useState(false);
  // The values last loaded from the server — the compare-and-swap base for the
  // free-text fields, so a concurrent edit by another operator surfaces as a
  // conflict instead of being silently clobbered.
  const baseRef = useRef<EngagementMeta>({});

  const load = () =>
    getEngagementMeta().then((m) => { setMeta(m); baseRef.current = m; }).catch(() => {});
  useEffect(() => { load(); }, []);
  const inReportKeys = useMemo(
    () => data.findings.filter((f) => f.status === "in-report").map((f) => f.key), [data.findings]);
  const inReport = inReportKeys.length;
  // The include filter is only actually applied when the toggle is on AND there
  // are in-report findings — otherwise the report covers everything (matching the
  // CLI default). Kept as a query string both the download and preview reuse.
  const includeQS = useMemo(
    () => (onlyInReport && inReport ? `include=${encodeURIComponent(inReportKeys.join(","))}` : ""),
    [onlyInReport, inReport, inReportKeys]);

  async function download(kind: string) {
    setBusy(kind);
    try {
      const r = await fetch(`/api/report/${kind}${includeQS ? `?${includeQS}` : ""}`);
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const blob = await r.blob();
      const cd = r.headers.get("content-disposition") || "";
      const name = /filename="?([^"]+)"?/.exec(cd)?.[1] || `report.${kind}`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url; a.download = name; a.click(); URL.revokeObjectURL(url);
    } catch (e) { toast.show(`report failed: ${(e as Error).message}`); }
    finally { setBusy(""); }
  }
  const saveMeta = () =>
    setEngagementMeta(meta, baseRef.current).then((r) => {
      if ("conflict" in r) {
        const fields = Object.keys(r.conflicts).join(", ") || "notes";
        toast.show(`${fields} changed by another operator — reloaded their version`);
        load();
        return;
      }
      baseRef.current = meta;
      toast.show("engagement details saved");
      setBust(Date.now());
    }).catch((e) => toast.show(String(e)));

  return (
    <div className="grid" style={{ gridTemplateColumns: "minmax(0,380px) minmax(0,1fr)", gap: 12, alignItems: "start" }}>
      <div className="grid" style={{ gap: 12 }}>
        <Panel title="Deliverables"
               sub={onlyInReport && inReport ? `${inReport} in-report finding${inReport === 1 ? "" : "s"}` : "all findings included"}>
          {inReport > 0 ? (
            <div className="row" style={{ marginBottom: 8 }}>
              <Chip label={`Only in-report (${inReport})`} on={onlyInReport} onClick={() => setOnlyInReport(!onlyInReport)} />
            </div>
          ) : (
            <div className="muted" style={{ fontSize: 12, marginBottom: 8 }}>All findings are included. Set findings to <b>in report</b> in the Findings tab to enable a narrowed deliverable.</div>
          )}
          <div className="grid" style={{ gap: 6 }}>
            {FORMATS.map(([k, label]) => (
              <button key={k} className="btn" disabled={busy === k} onClick={() => download(k)} style={{ justifyContent: "space-between" }}>
                <span>{label}</span><span className="faint mono">{busy === k ? "…" : `.${k}`}</span>
              </button>
            ))}
          </div>
        </Panel>

        <Panel title="Engagement details" sub="cover page + report metadata">
          {META_FIELDS.map(([f, label]) => (
            <label key={f} className="field"><span className="fl">{label}</span>
              <input className="fin" value={meta[f] || ""} onChange={(e) => setMeta((m) => ({ ...m, [f]: e.target.value }))} /></label>
          ))}
          <label className="field"><span className="fl">Scope notes</span>
            <textarea className="fin" rows={2} value={meta.scope_notes || ""} onChange={(e) => setMeta((m) => ({ ...m, scope_notes: e.target.value }))} /></label>
          <label className="field"><span className="fl">Rules of engagement</span>
            <textarea className="fin" rows={2} value={meta.roe_notes || ""} onChange={(e) => setMeta((m) => ({ ...m, roe_notes: e.target.value }))} /></label>
          <button className="btn primary" onClick={saveMeta}>Save details</button>
        </Panel>
      </div>

      <Panel title="Live preview" actions={<button className="linkish" onClick={() => setBust(Date.now())}>refresh</button>}>
        <iframe title="report preview" src={`/api/report/preview/html?_=${bust}${includeQS ? `&${includeQS}` : ""}`}
                style={{ width: "100%", height: "70vh", border: "1px solid var(--line)", borderRadius: "var(--radius-sm)", background: "var(--surface)" }} />
      </Panel>
    </div>
  );
}
