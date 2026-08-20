import { useEffect, useMemo, useState } from "react";
import {
  Finding, Host, Overview, VulnDetail, SEVS, SEV_ALL, hostScore, sevTotal, getHost,
  ActPlan, ActCard, Credential, AttackCoverage, getAct, getCredentials, getAttack, postActRun,
  SprayHit, postSpray,
} from "./api";
import { Stat, SevTag, SevBar, NoteCell, Chips, useBounded } from "./ui";
import { FindingDetail } from "./FindingDetail";
import { AssignControl, LabelChips, TeamCoverage, OwnerProgress, ownerStats, useCollab } from "./collab";

export type FindingFilters = {
  sev: string; host: string; kev: boolean; unreviewed: boolean; leads: boolean; q: string;
};
export type Nav = {
  toFindings: (o?: Partial<FindingFilters>) => void;
  toHosts: (o?: { q?: string; owner?: string }) => void;
  toAct: () => void;
  openHost: (ip: string) => void;
};

/* ------------------------------- Dashboard ------------------------------- */

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

/* --------------------------------- Hosts --------------------------------- */
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

/* ----------------------------------- Act ----------------------------------- */
// "I found things — what do I DO?" The ranked, guided action plan, so the UI
// carries the operator from findings to next moves instead of stopping at a list.

const ARCH_ICON: Record<string, string> = {
  loot: "🔓", crack: "🔑", spray: "💧", exploit: "💥", escalate: "⬆️",
  pivot: "↪️", "ad-path": "👑", "default-cred": "🔐",
};
// Display labels — keep the internal archetype keys, but present them professionally
// (e.g. "loot" reads as "collect" in the UI).
const ARCH_LABEL: Record<string, string> = { loot: "collect" };
const archLabel = (a: string) => ARCH_LABEL[a] || a;

function ActCardRow({ c, nav }: { c: ActCard; nav: Nav }) {
  const [copied, setCopied] = useState(false);
  const copy = () => navigator.clipboard?.writeText(c.command).then(() => {
    setCopied(true); setTimeout(() => setCopied(false), 1200);
  });
  const host = c.target && c.target !== "engagement" ? c.target.split(":")[0] : "";
  return (
    <div className={"actcard tier-" + c.tier}>
      <div className="actcard-h">
        <span className="arch">{ARCH_ICON[c.archetype] || "•"} {archLabel(c.archetype)}</span>
        <span className="acttitle">{c.title}{c.count > 1 ? ` ·+${c.count - 1}` : ""}</span>
        {host && <span className="mono host-link" onClick={() => nav.openHost(host)} title="host detail">{c.target}</span>}
        <span className="actscore" title="impact × confidence × leverage">{c.score}</span>
      </div>
      <div className="actyield">→ {c.yields}
        {c.verify_first && <span className="tag warn"> candidate — verify</span>}
        {c.needs.length > 0 && <span className="muted"> · needs: {c.needs.join(", ")}</span>}
      </div>
      <div className="actcmd"><code>{c.command}</code>
        <button className="copy" onClick={copy}>{copied ? "✓ copied" : "copy"}</button>
      </div>
      <div className="acttags">
        {c.attack_id && <a className="tag atk" target="_blank" rel="noopener"
          href={`https://attack.mitre.org/techniques/${c.attack_id.replace(".", "/")}/`}>ATT&CK {c.attack_id}</a>}
        {c.cwe && <span className="tag">{c.cwe}</span>}
        <span className={"tag safety " + c.safety.replace(/[^a-z]/g, "")}>{c.safety}</span>
      </div>
    </div>
  );
}

const ARCHETYPES = ["loot", "spray", "exploit", "escalate", "crack", "default-cred", "ad-path", "pivot"];

export function Act({ nav }: { nav: Nav }) {
  const [plan, setPlan] = useState<ActPlan | null>(null);
  const [atk, setAtk] = useState<AttackCoverage | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [arch, setArch] = useState<string>("all");   // archetype filter (declutter)
  const [running, setRunning] = useState(false);
  const [ranMsg, setRanMsg] = useState<string | null>(null);
  const load = () => getAct().then(setPlan).catch((e) => setErr(String(e)));
  useEffect(() => { load(); getAttack().then(setAtk).catch(() => {}); }, []);

  async function runAuto() {
    setRunning(true); setRanMsg(null);
    try {
      const r = await postActRun();
      setRanMsg(r.looted > 0
        ? `Collected ${r.looted} new credential(s) — see the Credentials tab. Spray plan refreshed.`
        : "No new credentials collected (already captured, or hosts unreachable).");
      await load();
    } catch { setRanMsg("run failed — is the engagement reachable?"); }
    finally { setRunning(false); }
  }

  if (err) return <div className="err">{err}</div>;
  if (!plan) return <div className="loading">Building the action plan…</div>;
  if (plan.top.length === 0)
    return <div className="empty">Nothing actionable yet — run a scan, then the deep modules, and the plan builds itself.</div>;
  const keep = (c: ActCard) => arch === "all" || c.archetype === arch;
  return (
    <div className="actview">
      <div className="act-controls">
        <div className="chips">
          <button className={"chip" + (arch === "all" ? " sel" : "")} onClick={() => setArch("all")}>all</button>
          {ARCHETYPES.map((a) => (
            <button key={a} className={"chip" + (arch === a ? " sel" : "")} onClick={() => setArch(a)}>{archLabel(a)}</button>
          ))}
        </div>
        <button className="run auto-loot" onClick={runAuto} disabled={running}
                title="collect credentials from the read-only unauth services + refresh the spray plan (intrusive actions are never auto-run)">
          {running ? "Collecting…" : "⚡ Collect credentials (read-only)"}
        </button>
      </div>
      {ranMsg && <div className="ranmsg">{ranMsg}</div>}
      <section className="panel top-actions">
        <div className="panel-h"><h3>★ Top priorities</h3><span className="muted">highest impact you can act on now</span></div>
        {plan.top.filter(keep).map((c, i) => <ActCardRow key={i} c={c} nav={nav} />)}
      </section>
      {plan.tiers.map((t) => {
        const cards = t.cards.filter(keep);
        if (cards.length === 0) return null;
        return (
          <section className="panel" key={t.tier}>
            <div className="panel-h"><h3 className="tier-label">{t.label}</h3><span className="muted">{cards.length}</span></div>
            {cards.map((c, i) => <ActCardRow key={i} c={c} nav={nav} />)}
          </section>
        );
      })}
      {(plan.top.some((c) => c.archetype === "ad-path" || c.archetype === "exploit")) && (
        <section className="panel">
          <div className="panel-h"><h3>Attack path <span className="tag">projected</span></h3>
            <span className="muted">route to Domain Admin, grounded in confirmed findings — not executed</span></div>
          <div className="apath-wrap">
            <img className="apath" src="/api/attackpath.svg" alt="Attack path" />
          </div>
        </section>
      )}
      {atk && atk.tactics.length > 0 && (
        <section className="panel">
          <div className="panel-h"><h3>MITRE ATT&CK coverage</h3>
            <span className="muted">{atk.technique_count} techniques · {atk.tactic_count} tactics</span></div>
          <div className="atkgrid">
            {atk.tactics.map((tac) => (
              <div className="atktac" key={tac.tactic}>
                <div className="atktac-h">{tac.tactic} <span className="muted">{tac.tactic_id}</span></div>
                {tac.techniques.map((te) => (
                  <a className="atktech" key={te.id} href={te.url} target="_blank" rel="noopener"
                     title={`${te.hosts.length} host(s)`}>{te.id} {te.name} <span className="muted">×{te.hosts.length}</span></a>
                ))}
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

/* ----------------------------------- Loot ---------------------------------- */
// "What did we extract?" The credential store — looted (web/db/share) + captured
// (kerberoast/gpp/secretsdump) — which the UI never surfaced before.

const KIND_LABEL: Record<string, string> = {
  password: "password", nthash: "NT hash", hash: "hash", blank: "blank",
};

export function Loot() {
  const [creds, setCreds] = useState<Credential[] | null>(null);
  const [reveal, setReveal] = useState<Set<number>>(new Set());
  const [err, setErr] = useState<string | null>(null);
  // spray control
  const [tgt, setTgt] = useState("");
  const [safe, setSafe] = useState(true);
  const [spraying, setSpraying] = useState(false);
  const [hits, setHits] = useState<SprayHit[] | null>(null);
  const [sprayMsg, setSprayMsg] = useState<string | null>(null);
  const load = () => getCredentials().then(setCreds).catch((e) => setErr(String(e)));
  useEffect(() => { load(); }, []);
  async function spray() {
    setSpraying(true); setSprayMsg(null); setHits(null);
    try {
      const r = await postSpray(tgt.trim(), safe);
      if (!r.ok) { setSprayMsg(r.error || "spray failed"); }
      else { setHits(r.hits); setSprayMsg(r.hits.length ? `${r.hits.length} valid login(s); ${r.new} new credential(s) stored.` : "no valid logins."); await load(); }
    } catch { setSprayMsg("spray failed"); }
    finally { setSpraying(false); }
  }
  if (err) return <div className="err">{err}</div>;
  if (!creds) return <div className="loading">Loading credentials…</div>;
  if (creds.length === 0)
    return <div className="empty">No credentials collected yet. They appear here once the credential-bearing modules run — web <code>.git</code>/<code>.env</code>, database trust / empty-password, SMB shares, Kerberoasting, GPP.</div>;
  const bySource: Record<string, number> = {};
  creds.forEach((c) => { bySource[c.source] = (bySource[c.source] || 0) + 1; });
  const toggle = (i: number) => setReveal((s) => { const n = new Set(s); n.has(i) ? n.delete(i) : n.add(i); return n; });
  return (
    <div className="lootview">
      <section className="stats">
        <Stat k="credentials" v={String(creds.length)} />
        <Stat k="sources" v={String(Object.keys(bySource).length)} />
        <Stat k="plaintext" v={String(creds.filter((c) => c.kind === "password").length)} />
        <Stat k="hashes" v={String(creds.filter((c) => c.kind === "nthash" || c.kind === "hash").length)} />
      </section>
      <section className="panel spraybar">
        <div className="panel-h"><h3>Spray these credentials</h3>
          <span className="muted">reuse the collected credentials across the login surface (SMB/WinRM/MSSQL/LDAP/SSH)</span></div>
        <div className="spray-row">
          <input className="scan-in" placeholder="target scope — blank = all, or 10.0.0.5 / 10.0.0.0/24"
                 value={tgt} onChange={(e) => setTgt(e.target.value)} disabled={spraying} />
          <label className="safetog" title="lockout-safe: paired user↔pass, one pass (netexec --no-bruteforce)">
            <input type="checkbox" checked={safe} onChange={(e) => setSafe(e.target.checked)} disabled={spraying} />
            lockout-safe
          </label>
          <button className="run" onClick={spray} disabled={spraying || creds.length === 0}>
            {spraying ? "Spraying…" : "💧 Spray"}
          </button>
        </div>
        {!safe && <div className="ranmsg warn-msg">Full user × password — real lockout risk on a domain lockout policy. Rules of engagement only.</div>}
        {sprayMsg && <div className="ranmsg">{sprayMsg}</div>}
        {hits && hits.length > 0 && (
          <table className="loottable"><thead><tr><th>Proto</th><th>Host</th><th>Login</th><th></th></tr></thead>
            <tbody>{hits.map((h, i) => (
              <tr key={i}><td className="mono">{h.proto}</td><td className="mono">{h.ip}</td>
                <td className="mono">{h.cred}</td>
                <td>{h.admin && <span className="tag warn">ADMIN · Pwn3d!</span>}</td></tr>
            ))}</tbody>
          </table>
        )}
      </section>

      <section className="panel">
        <div className="panel-h"><h3>Collected credentials</h3>
          <span className="muted">what recce collected / captured — or <code>recce creds --run</code> to spray</span></div>
        <div className="tablewrap">
          <table className="loottable">
            <thead><tr><th>Account</th><th>Secret</th><th>Kind</th><th>Source</th><th>From</th><th>Notes</th></tr></thead>
            <tbody>
              {creds.map((c, i) => (
                <tr key={i}>
                  <td className="mono">{c.label}</td>
                  <td className="mono secret">
                    <span className="secretval" onClick={() => toggle(i)} title="click to reveal / hide">
                      {reveal.has(i) ? (c.secret || "—") : "•".repeat(Math.min(12, (c.secret || "").length || 4))}</span>
                    {c.secret && <button className="copy" onClick={() => navigator.clipboard?.writeText(c.secret)} title="copy secret">copy</button>}
                  </td>
                  <td><span className="tag">{KIND_LABEL[c.kind] || c.kind}</span></td>
                  <td className="mono">{c.source}</td>
                  <td className="mono">{c.origin_ip}</td>
                  <td className="muted notes">{c.notes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
