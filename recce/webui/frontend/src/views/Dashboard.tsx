import { useEffect, useMemo, useState } from "react";
import { Overview, Host, ActCard, SEV_ALL, getAct } from "../api";
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
