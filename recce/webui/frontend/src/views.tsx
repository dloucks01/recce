import { useMemo } from "react";
import {
  Finding, Host, Overview, SEVS, SEV_ALL, hostScore, sevTotal,
} from "./api";
import { Stat, SevTag, SevBar, NoteCell, Chips, useBounded } from "./ui";

export type FindingFilters = {
  sev: string; host: string; kev: boolean; unreviewed: boolean; leads: boolean; q: string;
};
export type Nav = {
  toFindings: (o?: Partial<FindingFilters>) => void;
  toHosts: (o?: { q?: string; sev?: string }) => void;
  toTargets: () => void;
};

/* ------------------------------- Dashboard ------------------------------- */

export function Dashboard(
  { ov, nav }: { ov: Overview; nav: Nav }
) {
  const reviewPct = ov.findings_total ? Math.round((100 * ov.reviewed) / ov.findings_total) : 0;
  const enumPct = ov.hosts_up ? Math.round((100 * ov.enumerated) / ov.hosts_up) : 0;
  return (
    <div className="dash">
      <section className="stats">
        <Stat k="Hosts up" v={`${ov.hosts_up}`} sub={`/ ${ov.hosts_total}`} onClick={() => nav.toHosts()} />
        <Stat k="Services" v={`${ov.services}`} />
        <Stat k="Critical" v={`${ov.by_severity.critical ?? 0}`} cls="crit"
              onClick={() => nav.toFindings({ sev: "critical", leads: true })} />
        <Stat k="🔥 KEV" v={`${ov.kev_total}`} cls="kev"
              onClick={() => nav.toFindings({ kev: true })} />
        <Stat k="Reviewed" v={`${reviewPct}%`} sub={`${ov.reviewed}/${ov.findings_total}`}
              onClick={() => nav.toFindings({ unreviewed: true })} />
      </section>

      <section className="panel">
        <div className="panel-h">
          <h3>Severity</h3><span className="muted">{ov.findings_total} findings</span>
        </div>
        <div className="sevrow">
          {SEV_ALL.map((s) => {
            const c = ov.by_severity[s] ?? 0;
            return (
              <button key={s} className={"sevblock s-bg-" + s} disabled={!c}
                      onClick={() => nav.toFindings({ sev: s, leads: true })}>
                <span className="n">{c}</span>
                <span className="l">{s}</span>
              </button>
            );
          })}
        </div>
      </section>

      <div className="cols2">
        <section className="panel">
          <div className="panel-h"><h3>Top-risk hosts</h3>
            <button className="link" onClick={() => nav.toHosts()}>all hosts →</button></div>
          <ul className="risklist">
            {ov.top_hosts.length === 0 && <li className="muted">no findings yet</li>}
            {ov.top_hosts.map((h) => (
              <li key={h.ip} onClick={() => nav.toFindings({ host: h.ip })}>
                <div className="ri">
                  <span className="mono ip">{h.ip}</span>
                  {h.hostname && <span className="hn">{h.hostname}</span>}
                  {h.roles.slice(0, 2).map((r) => <span key={r} className="badge role">{r}</span>)}
                </div>
                <SevBar findings={h.findings} />
              </li>
            ))}
          </ul>
        </section>

        <section className="panel">
          <div className="panel-h"><h3>🔥 Known-exploited</h3>
            <button className="link" onClick={() => nav.toFindings({ kev: true })}>all KEV →</button></div>
          <ul className="kevlist">
            {ov.kev_findings.length === 0 && <li className="muted">no KEV findings</li>}
            {ov.kev_findings.map((f) => (
              <li key={f.key} onClick={() => nav.toFindings({ host: f.ip, kev: true })}>
                <SevTag severity={f.severity} />
                <div className="kf">
                  <div className="t">{f.title}</div>
                  <div className="m mono">{f.ip}{f.port ? `:${f.port}` : ""} {f.cve && `· ${f.cve}`}</div>
                </div>
                {f.epss > 0 && <span className="badge epss">EPSS {f.epss}%</span>}
              </li>
            ))}
          </ul>
        </section>
      </div>

      <section className="panel">
        <div className="panel-h"><h3>Coverage</h3>
          <button className="link" onClick={() => nav.toTargets()}>targets →</button></div>
        <div className="coverage">
          <Meter label="Scope discovered" now={ov.hosts_up}
                 total={Math.max(ov.scope_size, ov.hosts_up)} unit="hosts" />
          <Meter label="Enumerated" now={ov.enumerated} total={ov.hosts_up} unit="hosts" pct={enumPct} />
          <Meter label="Access gained" now={ov.accessed} total={ov.hosts_up} unit="hosts" cls="ok" />
          <Meter label="Findings reviewed" now={ov.reviewed} total={ov.findings_total} unit="" />
        </div>
      </section>
    </div>
  );
}

function Meter({ label, now, total, unit, pct, cls }:
  { label: string; now: number; total: number; unit: string; pct?: number; cls?: string }) {
  const p = pct ?? (total ? Math.round((100 * now) / total) : 0);
  return (
    <div className="meter">
      <div className="meter-h"><span>{label}</span><span className="mono">{now}{total ? ` / ${total}` : ""} {unit}</span></div>
      <div className="track"><div className={"fill" + (cls ? " " + cls : "")} style={{ width: `${Math.min(p, 100)}%` }} /></div>
    </div>
  );
}

/* ------------------------------- Findings -------------------------------- */

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
            {shown.map((x) => (
              <tr key={x.key} className={x.reviewed ? "done" : ""}>
                <td className="tick-col">
                  <input type="checkbox" checked={x.reviewed} onChange={() => onTick(x.key, !x.reviewed)} />
                </td>
                <td><SevTag severity={x.severity} /></td>
                <td>
                  <div className="t">{x.title}</div>
                  <div className="m">{x.cve && <span>{x.cve} · </span>}{x.source}</div>
                  <div className="badges">
                    {x.kev && <span className="badge kev">🔥 KEV</span>}
                    {x.epss > 0 && <span className="badge epss">EPSS {x.epss}%</span>}
                  </div>
                </td>
                <td className="mono host-link" onClick={() => nav.toHosts({ q: x.ip })} title="see host">
                  {x.ip}{x.port ? `:${x.port}` : ""}
                </td>
                <td><span className={"tier " + x.tier}>{x.tier === "lead" ? "lead · verify" : x.tier}</span></td>
                <td className="note-col"><NoteCell value={x.notes} onSave={(t) => onNote(x.key, t)} /></td>
              </tr>
            ))}
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

/* --------------------------------- Hosts --------------------------------- */

export function Hosts(
  { hosts, q, sev, setQ, setSev, nav, onTick, onNote }:
  { hosts: Host[]; q: string; sev: string; setQ: (v: string) => void; setSev: (v: string) => void;
    nav: Nav; onTick: (k: string, r: boolean) => void; onNote: (k: string, t: string) => void }
) {
  const rows = useMemo(() => {
    const n = q.toLowerCase();
    return hosts
      .filter((h) => !n || `${h.ip} ${h.hostname} ${h.os} ${h.roles.join(" ")}`.toLowerCase().includes(n))
      .filter((h) => sev === "all" || (h.findings[sev] || 0) > 0)
      .slice().sort((a, b) => hostScore(b.findings) - hostScore(a.findings) || a.ip.localeCompare(b.ip, undefined, { numeric: true }));
  }, [hosts, q, sev]);
  const { shown, limit, total, sentinel } = useBounded(rows, 120, [q, sev]);

  return (
    <>
      <div className="controls">
        <Chips value={sev} onChange={setSev} options={["all", ...SEVS]} />
        <input className="search" placeholder="filter: ip, host, os…" value={q}
               onChange={(e) => setQ(e.target.value)} spellCheck={false} />
      </div>
      <div className="tablewrap">
        <table className="tbl hosts">
          <thead><tr><th className="tick-col">✓</th><th>Host</th><th>OS</th><th className="num">Svcs</th><th>Findings</th><th>Note</th></tr></thead>
          <tbody>
            {shown.map((h) => (
              <tr key={h.ip} className={h.reviewed ? "done" : ""}>
                <td className="tick-col"><input type="checkbox" checked={h.reviewed} onChange={() => onTick(h.key, !h.reviewed)} /></td>
                <td className="host-link" onClick={() => nav.toFindings({ host: h.ip })}>
                  <div className="t mono">{h.ip}</div>
                  {h.hostname && <div className="m">{h.hostname}</div>}
                  {h.roles.length > 0 && <div className="badges">{h.roles.slice(0, 3).map((r) => <span key={r} className="badge role">{r}</span>)}</div>}
                </td>
                <td className="os">{h.os || "—"}</td>
                <td className="num mono">{h.ports.length}</td>
                <td><SevBar findings={h.findings} /></td>
                <td className="note-col"><NoteCell value={h.notes} onSave={(t) => onNote(h.key, t)} /></td>
              </tr>
            ))}
            {rows.length === 0 && <tr><td colSpan={6} className="empty">no hosts match this filter</td></tr>}
          </tbody>
        </table>
      </div>
      {sentinel}
      {total > 0 && <div className="rowcount">showing {limit.toLocaleString()} of {total.toLocaleString()} hosts</div>}
    </>
  );
}

/* -------------------------------- Targets -------------------------------- */

type TgFilter = "all" | "todo" | "enumerated" | "access" | "reviewed";

export function Targets(
  { hosts, ov, q, filter, setQ, setFilter, nav, onTick, onNote }:
  { hosts: Host[]; ov: Overview; q: string; filter: TgFilter;
    setQ: (v: string) => void; setFilter: (v: TgFilter) => void;
    nav: Nav; onTick: (k: string, r: boolean) => void; onNote: (k: string, t: string) => void }
) {
  const rows = useMemo(() => {
    const n = q.toLowerCase();
    return hosts
      .filter((h) => !n || `${h.ip} ${h.hostname} ${h.os}`.toLowerCase().includes(n))
      .filter((h) =>
        filter === "all" ? true :
        filter === "todo" ? !h.enumerated :
        filter === "enumerated" ? h.enumerated :
        filter === "access" ? h.access :
        /* reviewed */ h.reviewed)
      .slice().sort((a, b) => {
        // incomplete first, then by risk
        const ac = (a.enumerated ? 1 : 0) + (a.access ? 1 : 0);
        const bc = (b.enumerated ? 1 : 0) + (b.access ? 1 : 0);
        return ac - bc || hostScore(b.findings) - hostScore(a.findings);
      });
  }, [hosts, q, filter]);
  const { shown, limit, total, sentinel } = useBounded(rows, 120, [q, filter]);

  const enumPct = ov.hosts_up ? Math.round((100 * ov.enumerated) / ov.hosts_up) : 0;
  const revHosts = hosts.filter((h) => h.reviewed).length;

  const FILTERS: [TgFilter, string, number][] = [
    ["all", "All", hosts.length],
    ["todo", "Not enumerated", hosts.filter((h) => !h.enumerated).length],
    ["enumerated", "Enumerated", hosts.filter((h) => h.enumerated).length],
    ["access", "Access", hosts.filter((h) => h.access).length],
    ["reviewed", "Reviewed", revHosts],
  ];

  return (
    <>
      <section className="stats">
        <Stat k="Scope" v={`${ov.scope_size || ov.hosts_up}`} sub={`${ov.scope_subnets} subnets`} />
        <Stat k="Discovered" v={`${ov.hosts_up}`} sub="up" />
        <Stat k="Enumerated" v={`${enumPct}%`} sub={`${ov.enumerated}/${ov.hosts_up}`} />
        <Stat k="Access" v={`${ov.accessed}`} cls="ok" sub="hosts" />
        <Stat k="Hosts done" v={`${revHosts}`} sub={`/ ${ov.hosts_up}`} />
      </section>

      <div className="controls">
        <div className="chips">
          {FILTERS.map(([k, label, n]) => (
            <button key={k} className={"chip" + (filter === k ? " sel" : "")} onClick={() => setFilter(k)}>
              {label} <span className="ct">{n}</span>
            </button>
          ))}
        </div>
        <input className="search" placeholder="filter: ip, host, os…" value={q}
               onChange={(e) => setQ(e.target.value)} spellCheck={false} />
      </div>

      <div className="tablewrap">
        <table className="tbl targets">
          <thead><tr><th className="tick-col">done</th><th>Host</th><th>OS</th><th>Progress</th><th>Findings</th><th>Note</th></tr></thead>
          <tbody>
            {shown.map((h) => (
              <tr key={h.ip} className={h.reviewed ? "done" : ""}>
                <td className="tick-col"><input type="checkbox" checked={h.reviewed} onChange={() => onTick(h.key, !h.reviewed)} title="mark this host done" /></td>
                <td className="host-link" onClick={() => nav.toFindings({ host: h.ip })}>
                  <div className="t mono">{h.ip}</div>
                  {h.hostname && <div className="m">{h.hostname}</div>}
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
                <td className="note-col"><NoteCell value={h.notes} onSave={(t) => onNote(h.key, t)} /></td>
              </tr>
            ))}
            {rows.length === 0 && <tr><td colSpan={6} className="empty">no targets match this filter</td></tr>}
          </tbody>
        </table>
      </div>
      {sentinel}
      {total > 0 && <div className="rowcount">showing {limit.toLocaleString()} of {total.toLocaleString()} targets</div>}
    </>
  );
}

function Step({ on, label, cls }: { on: boolean; label: string; cls?: string }) {
  return <span className={"step" + (on ? " on" : "") + (on && cls ? " " + cls : "")} title={on ? `${label} done` : `${label} pending`}>{label}</span>;
}
