import { useEffect, useState, useRef, useCallback, useMemo } from "react";
import { CmdCatalog, CmdSpec, getCommands, postCommand } from "./api";

interface Job {
  id: string;
  status: "running" | "done" | "failed";
  cmd: string;
  tester: string;
  started: number;
  ended?: number;
}

interface ScanTabProps {
  tester: string;
  onRunning: (running: boolean) => void;
  onLog: (lines: string[]) => void;
}

const GROUP_META: Record<string, { icon: string; desc: string }> = {
  scan: { icon: "\u{1F4F6}", desc: "Port & vulnerability scanning" },
  services: { icon: "\u{1F4E1}", desc: "Service enumeration" },
  databases: { icon: "\u{1F5C4}", desc: "Database enumeration & extraction" },
  web: { icon: "\u{1F310}", desc: "Web application testing" },
  credentialed: { icon: "\u{1F511}", desc: "Authenticated / credentialed checks" },
  exploitation: { icon: "\u{1F4A5}", desc: "Exploit & attack modules" },
  reporting: { icon: "\u{1F4CB}", desc: "Report generation & analysis" },
  discovery: { icon: "\u{1F50D}", desc: "Network & host discovery" },
  enumeration: { icon: "\u{1F4E1}", desc: "Protocol enumeration" },
  credential: { icon: "\u{1F511}", desc: "Credential testing" },
  bruteforce: { icon: "\u{1F528}", desc: "Brute-force attacks" },
  auxiliary: { icon: "\u{1F9F0}", desc: "Utility modules" },
};

function elapsed(start: number, end?: number): string {
  const s = Math.round(((end || Date.now() / 1000) - start));
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}

function groupBy(catalog: CmdCatalog): Record<string, { key: string; spec: CmdSpec }[]> {
  const g: Record<string, { key: string; spec: CmdSpec }[]> = {};
  for (const [k, s] of Object.entries(catalog)) {
    const grp = s.group || "other";
    (g[grp] ||= []).push({ key: k, spec: s });
  }
  return g;
}

export function ScanTab({ tester, onRunning, onLog }: ScanTabProps) {
  const [catalog, setCatalog] = useState<CmdCatalog>({});
  const [jobs, setJobs] = useState<Job[]>([]);
  const [activeGroup, setActiveGroup] = useState<string | null>(null);
  const [command, setCommand] = useState<string | null>(null);
  const [targets, setTargets] = useState("");
  const [profile, setProfile] = useState("quick");
  const [cUser, setCUser] = useState("");
  const [cPass, setCPass] = useState("");
  const [cDomain, setCDomain] = useState("");
  const [cLhost, setCLhost] = useState("");
  const [cFlags, setCFlags] = useState<Record<string, boolean>>({});
  const [log, setLog] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const [showLog, setShowLog] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    getCommands().then((c) => {
      setCatalog(c);
      const groups = Object.keys(groupBy(c));
      if (groups.length > 0) setActiveGroup(groups[0]);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    async function pollJobs() {
      try {
        const res = await fetch("/api/jobs");
        const data = await res.json();
        setJobs(data || []);
      } catch {}
    }
    pollJobs();
    const id = window.setInterval(pollJobs, 2000);
    return () => window.clearInterval(id);
  }, []);

  useEffect(() => { onRunning(running); }, [running, onRunning]);
  useEffect(() => {
    onLog(log);
    logRef.current?.scrollTo(0, logRef.current.scrollHeight);
  }, [log, onLog]);

  const streamJob = useCallback((jobId: string) => {
    setLog([]);
    setRunning(true);
    setShowLog(true);
    const es = new EventSource(`/api/jobs/${jobId}/events`);
    es.onmessage = (m) => {
      try {
        const d = JSON.parse(m.data);
        if (d.line !== undefined) setLog((l) => [...l, d.line]);
        if (d.done) { es.close(); setRunning(false); }
      } catch {}
    };
    es.onerror = () => { es.close(); setRunning(false); };
  }, []);

  async function runScan() {
    if (!command || running) return;
    const s = catalog[command];
    if (!s) return;
    if (s.targets === "required" && !targets.trim()) return;
    const flags = Object.keys(cFlags).filter((k) => cFlags[k]);
    try {
      const { id } = await postCommand({
        command, targets, profile,
        username: s.creds ? cUser : undefined,
        password: s.creds ? cPass : undefined,
        domain: s.creds ? cDomain : undefined,
        lhost: s.lhost ? cLhost : undefined,
        flags,
      });
      streamJob(id);
    } catch (e) {
      setLog([`error: ${e}`]);
      setShowLog(true);
    }
  }

  const grouped = useMemo(() => groupBy(catalog), [catalog]);
  const groups = Object.entries(grouped);
  const currentCmds = activeGroup ? grouped[activeGroup] || [] : [];
  const spec = command ? catalog[command] : null;
  const runningJobs = jobs.filter((j) => j.status === "running");
  const recentJobs = jobs.filter((j) => j.status !== "running").slice(0, 10);

  return (
    <div className="sv2">
      {/* Category tabs */}
      <div className="sv2-tabs">
        {groups.map(([g, cmds]) => {
          const meta = GROUP_META[g.toLowerCase()] || { icon: "▸", desc: g };
          return (
            <button
              key={g}
              className={`sv2-tab ${activeGroup === g ? "active" : ""}`}
              onClick={() => { setActiveGroup(g); setCommand(null); setCFlags({}); }}
            >
              <span className="sv2-tab-icon">{meta.icon}</span>
              <span className="sv2-tab-name">{g}</span>
              <span className="sv2-tab-ct">{cmds.length}</span>
            </button>
          );
        })}
      </div>

      <div className="sv2-body">
        {/* Left: command list + config */}
        <div className="sv2-main">
          {activeGroup && (
            <>
              <div className="sv2-cmds">
                {currentCmds.map(({ key, spec: s }) => (
                  <button
                    key={key}
                    className={`sv2-cmd ${command === key ? "active" : ""}`}
                    onClick={() => { setCommand(key); setCFlags({}); }}
                    disabled={running}
                  >
                    <span className="sv2-cmd-name">{s.label}</span>
                    <span className="sv2-cmd-tags">
                      {s.targets === "required" && <span className="sv2-tag need">target</span>}
                      {s.creds && <span className="sv2-tag cred">creds</span>}
                      {s.lhost && <span className="sv2-tag lhost">lhost</span>}
                    </span>
                  </button>
                ))}
              </div>

              {spec && command && (
                <div className="sv2-config">
                  <div className="sv2-config-title">{spec.label}</div>

                  {spec.targets !== "none" && (
                    <label className="sv2-field">
                      <span className="sv2-label">
                        Targets {spec.targets === "required" && <span className="sv2-req">*</span>}
                      </span>
                      <input
                        className="sv2-input"
                        value={targets}
                        onChange={(e) => setTargets(e.target.value)}
                        placeholder="10.0.0.0/24, 10.0.0.5, or @targets.txt"
                        disabled={running}
                      />
                    </label>
                  )}

                  {spec.profile && (
                    <label className="sv2-field">
                      <span className="sv2-label">Profile</span>
                      <select className="sv2-input" value={profile} onChange={(e) => setProfile(e.target.value)} disabled={running}>
                        <option value="quick">Quick</option>
                        <option value="standard">Standard</option>
                        <option value="thorough">Thorough</option>
                      </select>
                    </label>
                  )}

                  {spec.creds && (
                    <div className="sv2-cred-grid">
                      <label className="sv2-field">
                        <span className="sv2-label">Username</span>
                        <input className="sv2-input" value={cUser} onChange={(e) => setCUser(e.target.value)}
                               placeholder="domain\user" disabled={running} />
                      </label>
                      <label className="sv2-field">
                        <span className="sv2-label">Password</span>
                        <input className="sv2-input" type="password" value={cPass}
                               onChange={(e) => setCPass(e.target.value)} disabled={running} />
                      </label>
                      <label className="sv2-field">
                        <span className="sv2-label">Domain</span>
                        <input className="sv2-input" value={cDomain} onChange={(e) => setCDomain(e.target.value)}
                               placeholder="CORP.LOCAL" disabled={running} />
                      </label>
                    </div>
                  )}

                  {spec.lhost && (
                    <label className="sv2-field">
                      <span className="sv2-label">LHOST</span>
                      <input className="sv2-input" value={cLhost} onChange={(e) => setCLhost(e.target.value)}
                             placeholder="attacker.ip:port" disabled={running} />
                    </label>
                  )}

                  {spec.flags && spec.flags.length > 0 && (
                    <div className="sv2-flags">
                      <span className="sv2-label">Flags</span>
                      <div className="sv2-flag-list">
                        {spec.flags.map((f) => (
                          <label key={f.name} className={`sv2-flag ${cFlags[f.name] ? "on" : ""}`}>
                            <input type="checkbox" checked={cFlags[f.name] || false}
                                   onChange={(e) => setCFlags({ ...cFlags, [f.name]: e.target.checked })}
                                   disabled={running} />
                            <span>{f.label}</span>
                            {f.active && <span className="sv2-flag-hot">active</span>}
                          </label>
                        ))}
                      </div>
                    </div>
                  )}

                  <button
                    className="sv2-exec"
                    onClick={runScan}
                    disabled={running || (spec.targets === "required" && !targets.trim())}
                  >
                    {running ? <><span className="sv2-spinner" /> Running&hellip;</> : <span>&#9654; Execute</span>}
                  </button>
                </div>
              )}

              {!command && (
                <div className="sv2-hint">Select a command above to configure and run it</div>
              )}
            </>
          )}
        </div>

        {/* Right: job queue */}
        <div className="sv2-jobs">
          <div className="sv2-jobs-h">
            <h3>Jobs</h3>
            {runningJobs.length > 0 && <span className="sv2-live">{runningJobs.length} running</span>}
          </div>

          {runningJobs.map((j) => (
            <div key={j.id} className="sv2-job live" onClick={() => streamJob(j.id)}>
              <span className="sv2-job-dot" />
              <div className="sv2-job-info">
                <div className="sv2-job-cmd">{j.cmd}</div>
                <div className="sv2-job-meta">{j.tester} &middot; {elapsed(j.started)}</div>
              </div>
            </div>
          ))}

          {recentJobs.map((j) => (
            <div key={j.id} className={`sv2-job ${j.status}`}>
              <span className="sv2-job-icon">{j.status === "done" ? "✓" : "✗"}</span>
              <div className="sv2-job-info">
                <div className="sv2-job-cmd">{j.cmd}</div>
                <div className="sv2-job-meta">
                  {j.tester} &middot; {new Date(j.started * 1000).toLocaleTimeString()}
                  {j.ended && <span> &middot; {elapsed(j.started, j.ended)}</span>}
                </div>
              </div>
            </div>
          ))}

          {runningJobs.length === 0 && recentJobs.length === 0 && (
            <div className="sv2-jobs-empty">No jobs yet</div>
          )}
        </div>
      </div>

      {/* Console output */}
      {showLog && (
        <div className="scan-console">
          <div className="scan-console-bar">
            <span className="scan-console-title">
              {running && <span className="scan-pulse-sm" />}
              Output &middot; {log.length} lines
            </span>
            <button className="scan-console-close" onClick={() => setShowLog(false)}>&times;</button>
          </div>
          <div className="scan-console-body" ref={logRef}>
            {log.map((line, i) => (
              <div key={i} className="scan-console-line">{line}</div>
            ))}
            {running && <div className="scan-console-line scan-console-cursor">_</div>}
            {!running && log.length > 0 && (
              <div className="scan-console-line scan-console-done">&mdash; done &mdash;</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
