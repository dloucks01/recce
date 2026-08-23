import { useMemo } from "react";
import { Host, Overview, hostScore } from "../api";
import { Stat, SevBar, NoteCell, useBounded } from "../ui";
import { AssignControl, LabelChips, OwnerProgress, ownerStats, useCollab } from "../collab";
import { Nav } from "./shared";

// Merged host inventory: scope + coverage progress + findings + ownership/triage.
export function Hosts(
  { hosts, ov, q, who, cov, setQ, setWho, setCov, nav, onTick, onNote }:
  { hosts: Host[]; ov: Overview; q: string; who: string; cov: string;
    setQ: (v: string) => void; setWho: (v: string) => void; setCov: (v: string) => void;
    nav: Nav; onTick: (k: string, r: boolean) => void; onNote: (k: string, t: string) => void }
) {
  const { c, me } = useCollab();
  const stats = useMemo(
    () => ownerStats(c.assignments, Object.fromEntries(hosts.map((h) => [h.ip, h.reviewed]))),
    [c.assignments, hosts]);
  const rows = useMemo(() => {
    const n = q.toLowerCase();
    return hosts
      .filter((h) => !n || `${h.ip} ${h.hostname} ${h.os} ${h.roles.join(" ")}`.toLowerCase().includes(n))
      .filter((h) =>
        cov === "all" ? true :
        cov === "todo" ? !h.enumerated :
        cov === "enumerated" ? h.enumerated :
        cov === "access" ? h.access :
        /* reviewed */ h.reviewed)
      .filter((h) =>
        who === "all" ? true :
        who === "unclaimed" ? !c.assignments[h.ip] :
        who === "queue" ? (c.assignments[h.ip] === me && !h.reviewed) :
        c.assignments[h.ip] === who)
      .slice().sort((a, b) => hostScore(b.findings) - hostScore(a.findings)
        || a.ip.localeCompare(b.ip, undefined, { numeric: true }));
  }, [hosts, q, cov, who, c.assignments, me]);
  const { shown, limit, total, sentinel } = useBounded(rows, 120, [q, cov, who]);

  if (hosts.length === 0) return (
    <div className="firstrun">
      <div className="fr-emoji">🛰️</div>
      <h3>No hosts yet</h3>
      <p>Discover hosts with <b>▶ Scan</b>, or fold in results you already have with
        <b> ⭱ Import</b> (nmap, netexec, Nessus, on-target loot…) — both are in the toolbar above.</p>
      <p className="muted">Everything you scan or import lands here, live for the whole team.</p>
    </div>
  );

  const enumPct = ov.hosts_up ? Math.round((100 * ov.enumerated) / ov.hosts_up) : 0;
  const revHosts = hosts.filter((h) => h.reviewed).length;
  const COV: [string, string, number][] = [
    ["all", "All", hosts.length],
    ["todo", "To-do", hosts.filter((h) => !h.enumerated).length],
    ["enumerated", "Enumerated", hosts.filter((h) => h.enumerated).length],
    ["access", "Access", hosts.filter((h) => h.access).length],
    ["reviewed", "Reviewed", revHosts],
  ];

  return (
    <>
      <section className="stats">
        <Stat k="Scope" v={`${ov.scope_size || ov.hosts_up}`} sub={`${ov.scope_subnets} subnets`}
              title="show all hosts" onClick={() => setCov("all")} />
        <Stat k="Discovered" v={`${ov.hosts_up}`} sub="up"
              title="show all discovered hosts" onClick={() => setCov("all")} />
        <Stat k="Enumerated" v={`${enumPct}%`} sub={`${ov.enumerated}/${ov.hosts_up}`}
              title="filter to enumerated hosts" onClick={() => setCov("enumerated")} />
        <Stat k="Access" v={`${ov.accessed}`} cls="ok" sub="hosts"
              title="filter to hosts with access" onClick={() => setCov("access")} />
        <Stat k="Reviewed" v={`${revHosts}`} sub={`/ ${ov.hosts_up}`}
              title="filter to reviewed hosts" onClick={() => setCov("reviewed")} />
      </section>

      <div className="controls">
        <div className="chips">
          {COV.map(([k, label, n]) => (
            <button key={k} className={"chip" + (cov === k ? " sel" : "")} onClick={() => setCov(k)}>
              {label} <span className="ct">{n}</span>
            </button>
          ))}
        </div>
        <div className="host-filter" title="ownership">
          <button className={"chip" + (who === "all" ? " sel" : "")} onClick={() => setWho("all")}>everyone</button>
          <button className={"chip" + (who === me ? " sel" : "")} onClick={() => setWho(me)}>mine</button>
          <button className={"chip" + (who === "unclaimed" ? " sel" : "")} onClick={() => setWho("unclaimed")}>unclaimed</button>
          {who === "queue" && (
            <button className="chip sel queue-chip" onClick={() => setWho("all")} title="my claimed, not-yet-reviewed hosts">★ my queue ✕</button>
          )}
          {who !== "all" && who !== "unclaimed" && who !== "queue" && who !== me && (
            <button className="chip sel" onClick={() => setWho("all")} title="clear owner filter">{who} ✕</button>
          )}
        </div>
        <input className="search" placeholder="filter: ip, host, os…" value={q}
               onChange={(e) => setQ(e.target.value)} spellCheck={false} />
      </div>

      <div className="tablewrap">
        <table className="tbl hosts">
          <thead><tr><th className="tick-col">✓</th><th>Host</th><th>OS</th><th>Progress</th><th>Findings</th><th>Owner / triage</th><th>Note</th></tr></thead>
          <tbody>
            {shown.map((h) => (
              <tr key={h.ip} className={h.reviewed ? "done" : ""}>
                <td className="tick-col"><input type="checkbox" checked={h.reviewed} onChange={() => onTick(h.key, !h.reviewed)} title="mark host reviewed" /></td>
                <td className="host-link" onClick={() => nav.openHost(h.ip)}>
                  <div className="t mono">{h.ip}</div>
                  {h.hostname && <div className="m">{h.hostname}</div>}
                  {h.roles.length > 0 && <div className="badges">{h.roles.slice(0, 3).map((r) => <span key={r} className="badge role">{r}</span>)}</div>}
                </td>
                <td className="os">{h.os || "—"}</td>
                <td>
                  <div className="steps">
                    <Step on={h.ports.length > 0} label="scan" />
                    <Step on={h.enumerated} label="enum" />
                    <Step on={h.vuln_scanned} label="vuln" />
                    <Step on={h.access} label="access" cls="ok" />
                  </div>
                </td>
                <td><SevBar findings={h.findings} /></td>
                <td><div className="host-collab"><AssignControl ip={h.ip} /><OwnerProgress ip={h.ip} stats={stats} /><LabelChips ip={h.ip} /></div></td>
                <td className="note-col"><NoteCell value={h.notes} onSave={(t) => onNote(h.key, t)} /></td>
              </tr>
            ))}
            {rows.length === 0 && <tr><td colSpan={7} className="empty">no hosts match this filter</td></tr>}
          </tbody>
        </table>
      </div>
      {sentinel}
      {total > 0 && <div className="rowcount">showing {limit.toLocaleString()} of {total.toLocaleString()} hosts</div>}
    </>
  );
}

function Step({ on, label, cls }: { on: boolean; label: string; cls?: string }) {
  return <span className={"step" + (on ? " on" : "") + (on && cls ? " " + cls : "")} title={on ? `${label} done` : `${label} pending`}>{label}</span>;
}
