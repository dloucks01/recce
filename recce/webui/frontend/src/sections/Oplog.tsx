// Op log — the shared operations log: who ran what on which host (post-ex
// actions), most recent first, live-updating as teammates work. This is the
// team-visibility + reporting record fed by every one-shot session task.
import { Fragment, useEffect, useMemo, useState } from "react";
import { OplogEntry, getOplog } from "../api";
import { SectionProps } from "../nav";
import { Panel, Empty, Chip } from "../kit";
import { copyText } from "../util";
import { toast } from "../toast";

function when(ts: string): string {
  const n = Number(ts);
  if (!n) return "";
  try { return new Date(n * 1000).toLocaleString(); } catch { return ts; }
}

export function Oplog(_: SectionProps) {
  const [rows, setRows] = useState<OplogEntry[]>([]);
  const [q, setQ] = useState("");
  // Keyed by a stable row identity, not the array index: the filter and the live
  // SSE refresh reorder/resize `filtered`, so an index would point at a different
  // command after either. rowId() derives a stable key from the row's own fields.
  const [open, setOpen] = useState<string | null>(null);
  const rowId = (r: OplogEntry) => `${r.ts}|${r.host_ip}|${r.command}`;

  const load = () => getOplog({ limit: 500 }).then(setRows).catch(() => {});
  useEffect(() => { load(); }, []);

  // Live refresh: refetch whenever a teammate tasks a session anywhere. One
  // lightweight EventSource, closed when the view unmounts.
  useEffect(() => {
    let es: EventSource | null = null;
    try {
      es = new EventSource("/api/events");
      es.onmessage = (m) => {
        // "session" = a task ran; "add" = a credential/artifact was folded in
        // (also written to the oplog). Reload on either so cred-capture rows
        // appear live rather than waiting for a manual refresh.
        try { const t = JSON.parse(m.data)?.type; if (t === "session" || t === "add") load(); } catch { /* noop */ }
      };
    } catch { /* SSE unavailable — the manual refresh still works */ }
    return () => es?.close();
  }, []);

  const operators = useMemo(
    () => [...new Set(rows.map((r) => r.operator).filter(Boolean))].sort(), [rows]);

  const filtered = useMemo(() => {
    const n = q.toLowerCase();
    return rows.filter((r) =>
      !n || `${r.operator} ${r.host_ip} ${r.kind} ${r.command} ${r.attack}`.toLowerCase().includes(n));
  }, [rows, q]);

  return (
    <>
      <Panel title={`Operations log (${filtered.length === rows.length ? rows.length : `${filtered.length} of ${rows.length}`})`}
             sub="every command a teammate ran through a session — shared, durable, and the source for post-ex reporting"
             actions={<>
               <input className="namebox" style={{ width: 220 }} placeholder="filter: operator, host, command…"
                      value={q} onChange={(e) => setQ(e.target.value)} />
               <button className="btn sm" title="refresh" onClick={load}>↻</button>
             </>}>
        {rows.length === 0 ? (
          <Empty>No operations logged yet — commands run through a session (task / quick-actions) show up here for the whole team.</Empty>
        ) : (
          <>
            {operators.length > 0 && (
              <div className="row wrap" style={{ gap: 6, marginBottom: 10 }}>
                {operators.map((o) => (
                  <Chip key={o} label={o} on={q.toLowerCase() === o.toLowerCase()}
                        onClick={() => setQ(q.toLowerCase() === o.toLowerCase() ? "" : o)} />
                ))}
              </div>
            )}
            <table className="tbl">
              <thead><tr>
                <th style={{ width: 150 }}>When</th>
                <th style={{ width: 90 }}>Operator</th>
                <th style={{ width: 110 }}>Host</th>
                <th style={{ width: 60 }}>Kind</th>
                <th>Command</th>
                <th style={{ width: 70 }}>ATT&CK</th>
              </tr></thead>
              <tbody>
                {filtered.map((r, i) => { const id = rowId(r); return (
                  <Fragment key={`${id}#${i}`}>
                    <tr style={{ cursor: "pointer" }} onClick={() => setOpen(open === id ? null : id)}>
                      <td className="mono faint">{when(r.ts)}</td>
                      <td>{r.operator || "—"}</td>
                      <td className="mono">{r.host_ip || "—"}</td>
                      <td><span className="chip">{r.kind}</span></td>
                      <td className="mono" style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: 360 }}>
                        {r.status && r.status !== "ok" &&
                          <span title={`command status: ${r.status}`} style={{ color: "var(--warn)", fontWeight: 700, marginRight: 6 }}>✗</span>}
                        {r.command}</td>
                      <td className="muted">{r.attack || ""}</td>
                    </tr>
                    {open === id && (
                      <tr>
                        <td colSpan={6} style={{ background: "var(--surface2)" }}>
                          {/* Full command — the row cell truncates it, but an ops
                              log's value is the exact command that ran, so show it
                              in full (wrapped + copyable) when the row is opened. */}
                          <div className="row" style={{ justifyContent: "space-between", marginBottom: 4 }}>
                            <span className="muted">command</span>
                            <button className="linkish" onClick={(e) => { e.stopPropagation(); copyText(r.command).then(() => toast.show("command copied")); }}>copy</button>
                          </div>
                          <pre className="mono" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere", margin: "0 0 8px", fontSize: 12 }}>{r.command}</pre>
                          <div className="row" style={{ justifyContent: "space-between", marginBottom: 4 }}>
                            <span className="muted">output {r.status && r.status !== "ok" ? `(${r.status})` : ""}</span>
                            <button className="linkish" onClick={(e) => { e.stopPropagation(); copyText(r.output).then(() => toast.show("output copied")); }}>copy</button>
                          </div>
                          <pre className="mono" style={{ whiteSpace: "pre-wrap", maxHeight: 260, overflow: "auto", margin: 0, fontSize: 12 }}>{r.output || "(no output captured)"}</pre>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ); })}
              </tbody>
            </table>
          </>
        )}
      </Panel>
    </>
  );
}
