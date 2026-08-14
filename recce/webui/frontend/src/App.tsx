import { useEffect, useMemo, useRef, useState } from "react";

type Finding = {
  key: string; reviewed: boolean;
  severity: string; title: string; ip: string; port: number | null;
  cve: string; kev: boolean; epss: number; tier: string; source: string;
};
type Port = { port: number; proto: string; service: string; product: string };
type Host = {
  ip: string; hostname: string; os: string; roles: string[]; up: boolean;
  ports: Port[]; findings: Record<string, number>;
};
type Engagement = {
  name: string; hosts_up: number; hosts_total: number; services: number;
  findings_by_severity: Record<string, number>; kev: number; checked_pct: number;
};

const SEVS = ["critical", "high", "medium", "low"];
const PAGE = 120; // rows materialised at a time — keeps the DOM small at 200-host scale

function sevCount(f: Record<string, number>, s: string) { return f[s] || 0; }
function hostTotal(h: Host) { return SEVS.reduce((n, s) => n + sevCount(h.findings, s), 0); }
// most-dangerous host first: critical desc, then high, medium, low
function riskCmp(a: Host, b: Host) {
  for (const s of SEVS) {
    const d = sevCount(b.findings, s) - sevCount(a.findings, s);
    if (d) return d;
  }
  return a.ip.localeCompare(b.ip, undefined, { numeric: true });
}

export default function App() {
  const [eng, setEng] = useState<Engagement | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [view, setView] = useState<"findings" | "hosts">("findings");
  const [sev, setSev] = useState("all");
  const [q, setQ] = useState("");
  const [hostFilter, setHostFilter] = useState("");   // set by clicking a host
  const [unreviewedOnly, setUnreviewedOnly] = useState(false);
  const [kevOnly, setKevOnly] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  // Who's driving this browser — kept in localStorage, sent as X-Tester so ticks
  // and scans are attributed to a person the whole team can see.
  const [who, setWho] = useState(() => localStorage.getItem("recce.tester") || "");
  const [nameInput, setNameInput] = useState("");
  const tester = who || "someone";
  const [flash, setFlash] = useState<string | null>(null);

  function saveTester(name: string) {
    const n = name.trim();
    if (!n) return;
    localStorage.setItem("recce.tester", n);
    setWho(n);
  }

  // scan job state
  const [targets, setTargets] = useState("");
  const [profile, setProfile] = useState("quick");
  const [log, setLog] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  async function refresh() {
    const [e, f, h] = await Promise.all([
      fetch("/api/engagement").then((r) => r.json()),
      fetch("/api/findings").then((r) => r.json()),
      fetch("/api/hosts").then((r) => r.json()),
    ]);
    setEng(e);
    setFindings(f);
    setHosts(h);
  }
  useEffect(() => {
    refresh().catch((e) => setErr(String(e)));
  }, []);
  useEffect(() => {
    logRef.current?.scrollTo(0, logRef.current.scrollHeight);
  }, [log]);

  // Live cross-user channel: when anyone ticks a finding or a scan finishes,
  // every open browser refreshes and shows a short who-did-what note.
  useEffect(() => {
    const es = new EventSource("/api/events");
    es.onmessage = (m) => {
      let d: any;
      try { d = JSON.parse(m.data); } catch { return; }
      if (d.type === "tick") {
        setFindings((fs) =>
          fs.map((f) => (f.key === d.key ? { ...f, reviewed: d.reviewed } : f)));
        if (d.tester !== tester) note(`${d.tester} ${d.reviewed ? "reviewed" : "un-reviewed"} a finding`);
      } else if (d.type === "scan_started") {
        note(`${d.tester} started a ${d.targets} scan`);
      } else if (d.type === "scan") {
        note(`${d.tester}'s scan ${d.status}`);
        refresh().catch(() => {});
      }
    };
    return () => es.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tester]);

  const flashTimer = useRef<number | undefined>(undefined);
  function note(msg: string) {
    setFlash(msg);
    window.clearTimeout(flashTimer.current);
    flashTimer.current = window.setTimeout(() => setFlash(null), 4000);
  }

  async function toggle(f: Finding) {
    const reviewed = !f.reviewed;
    setFindings((fs) => fs.map((x) => (x.key === f.key ? { ...x, reviewed } : x)));
    await fetch("/api/tick", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Tester": tester },
      body: JSON.stringify({ key: f.key, reviewed }),
    }).catch(() => {});
  }

  async function runScan() {
    if (!targets.trim() || running) return;
    setLog([]);
    setRunning(true);
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Tester": tester },
      body: JSON.stringify({ targets, phase: "scan", profile }),
    });
    if (!res.ok) {
      setLog([`error: ${(await res.json()).detail ?? res.statusText}`]);
      setRunning(false);
      return;
    }
    const { id } = await res.json();
    const es = new EventSource(`/api/jobs/${id}/events`);
    es.onmessage = (m) => {
      const d = JSON.parse(m.data);
      if (d.line !== undefined) setLog((l) => [...l, d.line]);
      if (d.done) {
        es.close();
        setRunning(false);
        refresh().catch(() => {});
      }
    };
    es.onerror = () => {
      es.close();
      setRunning(false);
    };
  }

  function drillHost(ip: string) {
    setHostFilter(ip);
    setView("findings");
  }

  const rows = useMemo(() => {
    const n = q.toLowerCase();
    return findings.filter(
      (f) =>
        (sev === "all" || f.severity === sev) &&
        (!hostFilter || f.ip === hostFilter) &&
        (!unreviewedOnly || !f.reviewed) &&
        (!kevOnly || f.kev) &&
        (!n || `${f.title} ${f.ip} ${f.cve} ${f.port} ${f.source}`.toLowerCase().includes(n))
    );
  }, [findings, sev, q, hostFilter, unreviewedOnly, kevOnly]);

  const hostRows = useMemo(() => {
    const n = q.toLowerCase();
    return hosts
      .filter((h) => !n || `${h.ip} ${h.hostname} ${h.os} ${h.roles.join(" ")}`.toLowerCase().includes(n))
      .filter((h) => sev === "all" || sevCount(h.findings, sev) > 0)
      .slice()
      .sort(riskCmp);
  }, [hosts, q, sev]);

  // Bounded rendering: only PAGE rows exist until you scroll to the sentinel.
  const [limit, setLimit] = useState(PAGE);
  useEffect(() => { setLimit(PAGE); }, [sev, q, hostFilter, unreviewedOnly, kevOnly, view]);
  const sentinel = useRef<HTMLDivElement>(null);
  const total = view === "findings" ? rows.length : hostRows.length;
  useEffect(() => {
    const el = sentinel.current;
    if (!el || limit >= total) return;
    const io = new IntersectionObserver((es) => {
      if (es[0].isIntersecting) setLimit((l) => Math.min(l + PAGE, total));
    }, { rootMargin: "400px" });
    io.observe(el);
    return () => io.disconnect();
  }, [limit, total]);

  const reviewedCount = useMemo(() => findings.filter((f) => f.reviewed).length, [findings]);

  if (err) return <div className="err">Could not reach the recce API: {err}</div>;
  if (!eng) return <div className="loading">Loading engagement…</div>;

  const shownFindings = rows.slice(0, limit);
  const shownHosts = hostRows.slice(0, limit);

  return (
    <div className="app">
      <header className="top">
        <span className="brand">
          <span className="dot" />
          recce <small>{eng.name}</small>
        </span>
        {who ? (
          <button className="whoami" onClick={() => setWho("")} title="click to change">
            {tester}
          </button>
        ) : (
          <form
            className="namegate"
            onSubmit={(e) => { e.preventDefault(); saveTester(nameInput); }}
          >
            <input
              placeholder="your name…"
              value={nameInput}
              onChange={(e) => setNameInput(e.target.value)}
              autoFocus
            />
            <button type="submit" disabled={!nameInput.trim()}>Set</button>
          </form>
        )}
      </header>

      {flash && <div className="flash">{flash}</div>}

      <main>
        <section className="stats">
          <Stat k="Hosts up" v={`${eng.hosts_up}`} sub={`/ ${eng.hosts_total} scoped`} />
          <Stat k="Services" v={`${eng.services}`} />
          <Stat k="Critical" v={`${eng.findings_by_severity.critical ?? 0}`} cls="crit" />
          <Stat k="🔥 KEV" v={`${eng.kev}`} cls="kev" />
          <Stat k="Reviewed" v={`${reviewedCount}`} sub={`/ ${findings.length}`} />
        </section>

        <section className="scanbar">
          <input
            className="scan-in"
            placeholder="targets to scan — 10.0.0.0/24, host.corp.local …"
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && runScan()}
            disabled={running}
          />
          <select value={profile} onChange={(e) => setProfile(e.target.value)} disabled={running}>
            <option value="quick">quick</option>
            <option value="standard">standard</option>
            <option value="thorough">thorough</option>
          </select>
          <button className="run" onClick={runScan} disabled={running || !targets.trim()}>
            {running ? "Scanning…" : "Run scan"}
          </button>
        </section>

        {(running || log.length > 0) && (
          <div className="console" ref={logRef}>
            {log.map((l, i) => (
              <div key={i} className="ln">
                {l}
              </div>
            ))}
            {running && <div className="ln cursor">▋</div>}
          </div>
        )}

        <div className="viewbar">
          <div className="tabs">
            <button className={"tab" + (view === "findings" ? " sel" : "")}
                    onClick={() => setView("findings")}>
              Findings <span className="ct">{rows.length}</span>
            </button>
            <button className={"tab" + (view === "hosts" ? " sel" : "")}
                    onClick={() => setView("hosts")}>
              Hosts <span className="ct">{hosts.length}</span>
            </button>
          </div>
          {hostFilter && (
            <button className="hostpill" onClick={() => setHostFilter("")}>
              host {hostFilter} ✕
            </button>
          )}
        </div>

        <div className="controls">
          <div className="chips">
            {["all", ...SEVS].map((s) => (
              <button
                key={s}
                className={"chip" + (sev === s ? " sel" : "")}
                onClick={() => setSev(s)}
              >
                {s === "all" ? "All" : s[0].toUpperCase() + s.slice(1)}
              </button>
            ))}
          </div>
          {view === "findings" && (
            <div className="toggles">
              <button className={"toggle" + (unreviewedOnly ? " on" : "")}
                      onClick={() => setUnreviewedOnly((v) => !v)}>Unreviewed</button>
              <button className={"toggle" + (kevOnly ? " on" : "")}
                      onClick={() => setKevOnly((v) => !v)}>🔥 KEV</button>
            </div>
          )}
          <input
            className="search"
            placeholder={view === "hosts" ? "filter: ip, host, os…" : "filter: cve, host, port…"}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            spellCheck={false}
          />
        </div>

        {view === "findings" ? (
          <div className="tablewrap">
            <table className="tbl">
              <thead>
                <tr>
                  <th className="tick-col">✓</th>
                  <th>Sev</th>
                  <th>Finding</th>
                  <th>Host</th>
                  <th>Confidence</th>
                </tr>
              </thead>
              <tbody>
                {shownFindings.map((f) => (
                  <tr key={f.key} className={f.reviewed ? "done" : ""}>
                    <td className="tick-col">
                      <input
                        type="checkbox"
                        checked={f.reviewed}
                        onChange={() => toggle(f)}
                        title={f.reviewed ? "reviewed" : "mark reviewed"}
                      />
                    </td>
                    <td>
                      <span className="sev-cell">
                        <span className={"stripe s-" + f.severity} />
                        <span className={"sev-tag s-" + f.severity}>{f.severity.slice(0, 4)}</span>
                      </span>
                    </td>
                    <td>
                      <div className="t">{f.title}</div>
                      <div className="m">
                        {f.cve && <span>{f.cve} · </span>}
                        {f.source}
                      </div>
                      <div className="badges">
                        {f.kev && <span className="badge kev">🔥 KEV</span>}
                        {f.epss > 0 && <span className="badge epss">EPSS {f.epss}%</span>}
                      </div>
                    </td>
                    <td className="mono host-link" onClick={() => drillHost(f.ip)} title="see this host">
                      {f.ip}
                      {f.port ? `:${f.port}` : ""}
                    </td>
                    <td>
                      <span className={"tier " + f.tier}>
                        {f.tier === "lead" ? "lead · verify" : f.tier}
                      </span>
                    </td>
                  </tr>
                ))}
                {rows.length === 0 && (
                  <tr>
                    <td colSpan={5} className="empty">
                      {eng.hosts_up === 0
                        ? "no hosts yet — run a scan above to begin"
                        : "no findings match this filter"}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="tablewrap">
            <table className="tbl hosts">
              <thead>
                <tr>
                  <th>Host</th>
                  <th>OS</th>
                  <th className="num">Svcs</th>
                  <th>Findings</th>
                </tr>
              </thead>
              <tbody>
                {shownHosts.map((h) => (
                  <tr key={h.ip} className="host-row" onClick={() => drillHost(h.ip)}>
                    <td>
                      <div className="t mono">{h.ip}</div>
                      {h.hostname && <div className="m">{h.hostname}</div>}
                      {h.roles.length > 0 && (
                        <div className="badges">
                          {h.roles.slice(0, 3).map((r) => (
                            <span key={r} className="badge role">{r}</span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="os">{h.os || "—"}</td>
                    <td className="num mono">{h.ports.length}</td>
                    <td>
                      <SevBar findings={h.findings} total={hostTotal(h)} />
                    </td>
                  </tr>
                ))}
                {hostRows.length === 0 && (
                  <tr>
                    <td colSpan={4} className="empty">
                      {eng.hosts_up === 0
                        ? "no hosts yet — run a scan above to begin"
                        : "no hosts match this filter"}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {limit < total && <div className="sentinel" ref={sentinel} />}
        {total > 0 && (
          <div className="rowcount">
            showing {Math.min(limit, total).toLocaleString()} of {total.toLocaleString()}{" "}
            {view === "findings" ? "findings" : "hosts"}
          </div>
        )}
      </main>
    </div>
  );
}

function SevBar({ findings, total }: { findings: Record<string, number>; total: number }) {
  if (total === 0) return <span className="clean">clean</span>;
  return (
    <div className="sevbar">
      <div className="bar">
        {SEVS.map((s) => {
          const c = findings[s] || 0;
          if (!c) return null;
          return <span key={s} className={"seg s-" + s} style={{ flex: c }} title={`${c} ${s}`} />;
        })}
      </div>
      <div className="counts">
        {SEVS.map((s) => (findings[s] ? (
          <span key={s} className={"c s-" + s}>{findings[s]}</span>
        ) : null))}
      </div>
    </div>
  );
}

function Stat({ k, v, sub, cls }: { k: string; v: string; sub?: string; cls?: string }) {
  return (
    <div className={"stat" + (cls ? " " + cls : "")}>
      <div className="k">{k}</div>
      <div className="v">
        {v} {sub && <small>{sub}</small>}
      </div>
    </div>
  );
}
