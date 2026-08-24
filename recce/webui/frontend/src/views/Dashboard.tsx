import { useEffect, useMemo, useState } from "react";
import { Overview, Host, ActCard, ScanDiff, SEV_ALL, getAct, getDiff, getExploitHint } from "../api";
import { Stat, SevTag, SevBar } from "../ui";
import { TeamCoverage } from "../collab";
import { Nav, ARCH_ICON, archLabel } from "./shared";

export function Dashboard(
  { ov, hosts, nav }: { ov: Overview; hosts: Host[]; nav: Nav }
) {
  const reviewedByIp = useMemo(() => Object.fromEntries(hosts.map((h) => [h.ip, h.reviewed])), [hosts]);
  const reviewPct = ov.findings_total ? Math.round((100 * ov.reviewed) / ov.findings_total) : 0;
  const enumPct = ov.hosts_up ? Math.round((100 * ov.enumerated) / ov.hosts_up) : 0;
  return (
    <div className="dash">
      <section className="stats">
        <Stat k="Hosts up" v={`${ov.hosts_up}`} sub={`/ ${ov.hosts_total}`} onClick={() => nav.toHosts()} />
        <Stat k="Services" v={`${ov.services}`} />
        <Stat k="Critical" v={`${ov.by_severity.critical ?? 0}`} cls="crit"
              onClick={() => nav.toFindings({ sev: "critical", leads: true })} />
        <Stat k="🔥 Known-exploited" v={`${ov.kev_total}`} cls="kev"
              title="CISA KEV (Known Exploited Vulnerabilities) — CVEs confirmed exploited in the wild. Fix these first."
              onClick={() => nav.toFindings({ kev: true })} />
        <Stat k="Reviewed" v={`${reviewPct}%`} sub={`${ov.reviewed}/${ov.findings_total}`}
              onClick={() => nav.toFindings({ unreviewed: true })} />
      </section>

      <NextMoves nav={nav} />

      <RecentChanges nav={nav} />

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
              <li key={h.ip} onClick={() => nav.openHost(h.ip)}>
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
          <div className="panel-h">
            <div>
              <h3>🔥 Known-exploited (CISA KEV)</h3>
              <span className="panel-sub">CVEs confirmed exploited in the wild — fix these first</span>
            </div>
            <button className="link" onClick={() => nav.toFindings({ kev: true })}>view all →</button></div>
          <ul className="kevlist">
            {ov.kev_findings.length === 0 && <li className="muted">no KEV findings</li>}
            {ov.kev_findings.map((f) => (
              <li key={f.key} onClick={() => nav.openHost(f.ip)}>
                <SevTag severity={f.severity} />
                <div className="kf">
                  <div className="t">{f.title}</div>
                  <div className="m mono">{f.ip}{f.port ? `:${f.port}` : ""} {f.cve && `· ${f.cve}`}</div>
                </div>
                {f.epss > 0 && <span className="badge epss" title="EPSS — 30-day probability this CVE is exploited (FIRST.org)">EPSS {f.epss}%</span>}
                {nav.toExploitShell && (
                  <button className="kev-shell-btn" title="Get shell — opens Sessions with the msf module + target pre-filled"
                          onClick={async (e) => {
                            e.stopPropagation();
                            try {
                              const h = await getExploitHint(f.key);
                              nav.toExploitShell!({
                                ip: h.ip, port: h.port, cve: h.cve, title: f.title,
                                module: h.hint?.module || "", payload: h.hint?.payload || "",
                                note: h.hint?.note || "",
                              });
                            } catch { /* silent — worst case is no banner shown */ }
                          }}>🎯 shell</button>
                )}
              </li>
            ))}
          </ul>
        </section>
      </div>

      <TeamCoverage hostsUp={ov.hosts_up} reviewedByIp={reviewedByIp} onOpen={(owner) => nav.toHosts({ owner })} />

      <section className="panel">
        <div className="panel-h"><h3>Coverage</h3>
          <button className="link" onClick={() => nav.toHosts()}>hosts →</button></div>
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

// "What happened while I was away" — hosts touched + activity since the
// chosen window. Uses hosts.updated (populated on fresh scans) + the collab
// activity log (always populated). Windowed 1h / 24h / 7d.
const WINDOWS: [string, number][] = [["1h", 3600], ["24h", 86400], ["7d", 604800]];

function RecentChanges({ nav }: { nav: Nav }) {
  const [win, setWin] = useState(86400);
  const [d, setD] = useState<ScanDiff | null>(null);
  useEffect(() => {
    const since = Date.now() / 1000 - win;
    getDiff(since).then(setD).catch(() => setD(null));
  }, [win]);
  if (!d) return null;
  const empty = d.hosts_touched.length === 0 && d.activity.length === 0;
  return (
    <section className="panel recent">
      <div className="panel-h">
        <h3>Recent changes</h3>
        <span className="muted">
          {d.summary.hosts} host{d.summary.hosts !== 1 ? "s" : ""} touched
          {d.summary.findings_added > 0 && ` · ${d.summary.findings_added} findings added`}
          {d.summary.credentials_added > 0 && ` · ${d.summary.credentials_added} creds looted`}
        </span>
        <div className="recent-wins">
          {WINDOWS.map(([lab, s]) => (
            <button key={lab} className={"chip" + (win === s ? " sel" : "")} onClick={() => setWin(s)}>
              {lab}
            </button>
          ))}
        </div>
      </div>
      {empty && <div className="muted" style={{padding: "12px 4px"}}>Quiet — nothing has changed in this window.</div>}
      {d.hosts_touched.length > 0 && (
        <ul className="recent-hosts">
          {d.hosts_touched.slice(0, 6).map((h) => (
            <li key={h.ip} onClick={() => nav.openHost(h.ip)} title="open host detail">
              <span className="mono ip">{h.ip}</span>
              {h.hostname && <span className="hn">{h.hostname}</span>}
              <span className="muted">{h.port_count} port{h.port_count !== 1 ? "s" : ""}</span>
              <span className="recent-when muted mono">{relTime(h.updated)}</span>
              <SevBar findings={h.sev} />
            </li>
          ))}
          {d.hosts_touched.length > 6 && (
            <li className="muted recent-more">+{d.hosts_touched.length - 6} more</li>
          )}
        </ul>
      )}
      {d.activity.length > 0 && (
        <div className="recent-activity">
          <div className="recent-activity-h muted">Activity</div>
          <ul>
            {d.activity.slice(0, 8).map((a, i) => (
              <li key={i}>
                <span className="mono recent-when">{relTime(a.ts)}</span>
                <span className="tester">{a.tester}</span>
                <span className="atxt">{a.text}</span>
              </li>
            ))}
            {d.activity.length > 8 && (
              <li className="muted">+{d.activity.length - 8} more events</li>
            )}
          </ul>
        </div>
      )}
    </section>
  );
}

function relTime(ts: number): string {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

// Landing-page "so what": the top action-plan moves, so the operator lands on WHAT
// TO DO, not just what's wrong. Click through to the full Act plan.
function NextMoves({ nav }: { nav: Nav }) {
  const [top, setTop] = useState<ActCard[] | null>(null);
  useEffect(() => { getAct().then((p) => setTop(p.top.slice(0, 3))).catch(() => setTop([])); }, []);
  if (!top || top.length === 0) return null;
  return (
    <section className="panel nextmoves">
      <div className="panel-h"><h3>★ Next moves</h3>
        <button className="link" onClick={() => nav.toAct()}>full action plan →</button></div>
      <ul className="nmlist">
        {top.map((c, i) => (
          <li key={i} onClick={() => nav.toAct()}>
            <span className="nm-rank">{i + 1}</span>
            <div className="nm-body">
              <div className="nm-t">{ARCH_ICON[c.archetype] || "•"} {c.title}
                {c.target && c.target !== "engagement" && <span className="mono nm-tgt"> {c.target}</span>}</div>
              <div className="nm-y muted">→ {c.yields}</div>
            </div>
            <span className="badge nm-arch">{archLabel(c.archetype)}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
