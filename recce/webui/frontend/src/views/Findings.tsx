import { useMemo, useState } from "react";
import { Finding, VulnDetail, SEVS, getHost } from "../api";
import { SevTag, NoteCell, Chips, useBounded } from "../ui";
import { FindingDetail } from "../FindingDetail";
import { useCollab } from "../collab";
import { FindingFilters, Nav } from "./shared";

export function Findings(
  { findings, f, setF, nav, onTick, onNote }:
  { findings: Finding[]; f: FindingFilters; setF: (o: Partial<FindingFilters>) => void;
    nav: Nav; onTick: (k: string, r: boolean) => void; onNote: (k: string, t: string) => void }
) {
  // Leads = QoD-below-threshold version/banner inferences (tier "lead"). They are the
  // bulk of the noise and the classic false-positive class, so they are hidden by
  // default; the "Leads" toggle brings them back when a tester wants to dig.
  const leadCount = useMemo(() => findings.filter((x) => x.tier === "lead").length, [findings]);
  const rows = useMemo(() => {
    const n = f.q.toLowerCase();
    return findings.filter((x) =>
      (f.leads || x.tier !== "lead") &&
      (f.sev === "all" || x.severity === f.sev) &&
      (!f.host || x.ip === f.host) &&
      (!f.unreviewed || !x.reviewed) &&
      (!f.kev || x.kev) &&
      (!n || `${x.title} ${x.ip} ${x.cve} ${x.port} ${x.source}`.toLowerCase().includes(n)));
  }, [findings, f]);
  const { shown, limit, total, sentinel } =
    useBounded(rows, 120, [f.sev, f.host, f.kev, f.unreviewed, f.leads, f.q]);

  // Inline expansion: full detail (output/remediation/QoD) isn't in the findings list
  // payload, so lazy-fetch it per host (one /api/host call, cached) on first expand.
  const [openKey, setOpenKey] = useState<string | null>(null);
  const [cache, setCache] = useState<Record<string, VulnDetail[]>>({});
  async function toggle(x: Finding) {
    if (openKey === x.key) { setOpenKey(null); return; }
    setOpenKey(x.key);
    if (!cache[x.ip]) {
      try {
        const h = await getHost(x.ip);
        setCache((c) => ({ ...c, [x.ip]: h.vulns }));
      } catch { /* leave it; the row just won't expand */ }
    }
  }
  const detailFor = (x: Finding) => cache[x.ip]?.find((v) => v.key === x.key);
  const { c: cst, dismiss } = useCollab();

  return (
    <>
      <div className="controls">
        <Chips value={f.sev} onChange={(v) => setF({ sev: v })} options={["all", ...SEVS]} />
        <div className="toggles">
          <button className={"toggle" + (f.unreviewed ? " on" : "")} onClick={() => setF({ unreviewed: !f.unreviewed })}>Unreviewed</button>
          <button className={"toggle" + (f.kev ? " on" : "")} onClick={() => setF({ kev: !f.kev })}>🔥 KEV</button>
          {leadCount > 0 && (
            <button className={"toggle" + (f.leads ? " on" : "")} onClick={() => setF({ leads: !f.leads })}
                    title="version/banner inferences below the confidence threshold">
              Leads <span className="ct">{leadCount}</span>
            </button>
          )}
        </div>
        <input className="search" placeholder="filter: cve, host, port…" value={f.q}
               onChange={(e) => setF({ q: e.target.value })} spellCheck={false} />
      </div>

      <div className="tablewrap">
        <table className="tbl">
          <thead><tr><th className="tick-col">✓</th><th>Sev</th><th>Finding</th><th>Host</th><th>Conf.</th><th>Note</th></tr></thead>
          <tbody>
            {shown.map((x) => {
              const open = openKey === x.key;
              const detail = open ? detailFor(x) : undefined;
              return [
              <tr key={x.key} className={(x.reviewed ? "done" : "") + (open ? " open" : "") + (cst.dismissed[x.key] ? " dismissed" : "")}>
                <td className="tick-col">
                  <input type="checkbox" checked={x.reviewed} onChange={() => onTick(x.key, !x.reviewed)} />
                </td>
                <td><SevTag severity={x.severity} /></td>
                <td className="expand" onClick={() => toggle(x)} title="show detail">
                  <div className="t"><span className="caret">{open ? "▾" : "▸"}</span> {x.title}</div>
                  <div className="m">{x.cve && <span>{x.cve} · </span>}{x.source}</div>
                  <div className="badges">
                    {x.kev && <span className="badge kev" title="CISA Known Exploited Vulnerability — confirmed exploited in the wild; fix first">🔥 KEV</span>}
                    {x.epss > 0 && <span className="badge epss" title="EPSS — 30-day probability this CVE is exploited (FIRST.org)">EPSS {x.epss}%</span>}
                  </div>
                </td>
                <td className="mono host-link" onClick={() => nav.openHost(x.ip)} title="host detail">
                  {x.ip}{x.port ? `:${x.port}` : ""}
                </td>
                <td><span className={"tier " + x.tier}>{x.tier === "lead" ? "lead · verify" : x.tier}</span></td>
                <td className="note-col">
                  <NoteCell value={x.notes} onSave={(t) => onNote(x.key, t)} />
                  <button className={"dismiss-btn" + (cst.dismissed[x.key] ? " on" : "")}
                          title={cst.dismissed[x.key] ? "restore this finding" : "mark not a finding (false positive)"}
                          onClick={() => dismiss(x.key, !cst.dismissed[x.key])}>
                    {cst.dismissed[x.key] ? "restore" : "dismiss"}
                  </button>
                </td>
              </tr>,
              open && (
                <tr key={x.key + ":d"} className="detail-row">
                  <td />
                  <td colSpan={5}>
                    {detail
                      ? <FindingDetail v={detail} onNote={onNote} />
                      : <div className="muted small">loading detail…</div>}
                  </td>
                </tr>
              ),
              ];
            })}
            {rows.length === 0 && (
              <tr><td colSpan={6} className="empty">
                {!f.leads && leadCount > 0
                  ? `no confirmed findings match — ${leadCount} lead${leadCount > 1 ? "s" : ""} hidden (toggle “Leads” to show)`
                  : "no findings match this filter"}
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
      {sentinel}
      {total > 0 && (
        <div className="rowcount">
          showing {limit.toLocaleString()} of {total.toLocaleString()} findings
          {!f.leads && leadCount > 0 && <span className="muted"> · {leadCount} leads hidden</span>}
        </div>
      )}
    </>
  );
}
