import { useEffect, useMemo, useRef, useState } from "react";

type Finding = {
  severity: string; title: string; ip: string; port: number | null;
  cve: string; kev: boolean; epss: number; tier: string; source: string;
};
type Engagement = {
  name: string; hosts_up: number; hosts_total: number; services: number;
  findings_by_severity: Record<string, number>; kev: number; checked_pct: number;
};

const SEVS = ["critical", "high", "medium", "low"];

export default function App() {
  const [eng, setEng] = useState<Engagement | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [sev, setSev] = useState("all");
  const [q, setQ] = useState("");
  const [err, setErr] = useState<string | null>(null);

  // scan job state
  const [targets, setTargets] = useState("");
  const [profile, setProfile] = useState("quick");
  const [log, setLog] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  async function refresh() {
    const [e, f] = await Promise.all([
      fetch("/api/engagement").then((r) => r.json()),
      fetch("/api/findings").then((r) => r.json()),
    ]);
    setEng(e);
    setFindings(f);
  }
  useEffect(() => {
    refresh().catch((e) => setErr(String(e)));
  }, []);
  useEffect(() => {
    logRef.current?.scrollTo(0, logRef.current.scrollHeight);
  }, [log]);

  async function runScan() {
    if (!targets.trim() || running) return;
    setLog([]);
    setRunning(true);
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
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

  const rows = useMemo(() => {
    const n = q.toLowerCase();
    return findings.filter(
      (f) =>
        (sev === "all" || f.severity === sev) &&
        (!n || `${f.title} ${f.ip} ${f.cve} ${f.port} ${f.source}`.toLowerCase().includes(n))
    );
  }, [findings, sev, q]);

  if (err) return <div className="err">Could not reach the recce API: {err}</div>;
  if (!eng) return <div className="loading">Loading engagement…</div>;

  return (
    <div className="app">
      <header className="top">
        <span className="brand">
          <span className="dot" />
          recce <small>{eng.name}</small>
        </span>
      </header>

      <main>
        <section className="stats">
          <Stat k="Hosts up" v={`${eng.hosts_up}`} sub={`/ ${eng.hosts_total} scoped`} />
          <Stat k="Services" v={`${eng.services}`} />
          <Stat k="Critical" v={`${eng.findings_by_severity.critical ?? 0}`} cls="crit" />
          <Stat k="🔥 KEV" v={`${eng.kev}`} cls="kev" />
          <Stat k="Checked" v={`${eng.checked_pct}%`} />
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
          <input
            className="search"
            placeholder="filter: cve, host, port…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            spellCheck={false}
          />
        </div>

        <div className="tablewrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>Sev</th>
                <th>Finding</th>
                <th>Host</th>
                <th>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((f, i) => (
                <tr key={i}>
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
                  <td className="mono">
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
                  <td colSpan={4} className="empty">
                    {eng.hosts_up === 0
                      ? "no hosts yet — run a scan above to begin"
                      : "no findings match this filter"}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </main>
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
