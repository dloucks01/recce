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

const GROUP_ICONS: Record<string, string> = {
  discovery: "🔍", enumeration: "📡", credential: "🔑", exploit: "💥",
  bruteforce: "🔨", spray: "💧", auxiliary: "🧰", scan: "📶",
};

function elapsed(start: number, end?: number): string {
  const s = Math.round(((end || Date.now() / 1000) - start));
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}

export function ScanTab({ tester, onRunning, onLog }: ScanTabProps) {
  const [catalog, setCatalog] = useState<CmdCatalog>({});
  const [jobs, setJobs] = useState<Job[]>([]);
  const [command, setCommand] = useState("scan");
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
    getCommands().then(setCatalog).catch(() => {});
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
      const d = JSON.parse(m.data);
      if (d.line !== undefined) setLog((l) => [...l, d.line]);
      if (d.done) { es.close(); setRunning(false); }
    };
    es.onerror = () => { es.close(); setRunning(false); };
  }, []);

  async function runScan() {
    const spec = catalog[command];
    if (running) return;
    if (spec?.targets === "required" && !targets.trim()) return;
    const flags = Object.keys(cFlags).filter((k) => cFlags[k]);
    try {
      const { id } = await postCommand({
        command, targets, profile,
        username: spec?.creds ? cUser : undefined,
        password: spec?.creds ? cPass : undefined,
        domain: spec?.creds ? cDomain : undefined,
        lhost: spec?.lhost ? cLhost : undefined,
        flags,
      });
      streamJob(id);
    } catch (e) {
      setLog([`error: ${e}`]);
      setShowLog(true);
    }
  }

  const grouped = useMemo(() => {
    const g: Record<string, { key: string; spec: CmdSpec }[]> = {};
    for (const [k, s] of Object.entries(catalog)) {
      const grp = s.group || "other";
      (g[grp] ||= []).push({ key: k, spec: s });
    }
    return g;
  }, [catalog]);

  const spec = catalog[command] || ({} as Partial<CmdSpec>);
  const runningJobs = jobs.filter((j) => j.status === "running");
  const recentJobs = jobs.filter((j) => j.status !== "running").slice(0, 15);
  const cmdCount = Object.keys(catalog).length;

  return (
    <div className="scan-tab">
      <div className="scan-row">
        {/* ── Command form ── */}
        <div className="scan-form">
          {/* Selected command header */}
          {spec.label && (
            <div className="scan-cmd-header">
              <span className="scan-cmd-group">
                {GROUP_ICONS[spec.group?.toLowerCase()] || "▸"} {spec.group || "other"}
              </span>
              <span className="scan-cmd-label">{spec.label}</span>
            </div>
          )}

          <div className="scan-section">
            <div className="scan-section-label">Command</div>
            <select
              className="scan-select"
              value={command}
              onChange={(e) => { setCommand(e.target.value); setCFlags({}); }}
              disabled={running}
            >
              {Object.entries(grouped).map(([group, cmds]) => (
                <optgroup key={group} label={`${GROUP_ICONS[group.toLowerCase()] || "▸"} ${group}`}>
                  {cmds.map(({ key, spec: s }) => (
                    <option key={key} value={key}>{s.label}</option>
                  ))}
                </optgroup>
              ))}
            </select>
            <span className="scan-cmd-count">{cmdCount} commands available</span>
          </div>

          {spec.targets !== "none" && (
            <div className="scan-section">
              <div className="scan-section-label">
                Targets {spec.targets === "required" && <span className="scan-req">required</span>}
              </div>
              <input
                className="scan-input"
                type="text"
                value={targets}
                onChange={(e) => setTargets(e.target.value)}
                placeholder="10.0.0.0/24, 10.0.0.5, or @targets.txt"
                disabled={running}
              />
            </div>
          )}

          {(spec.profile || spec.creds || spec.lhost) && (
            <div className="scan-options">
              <div className="scan-section-label">Options</div>

              {spec.profile && (
                <div className="scan-option-row">
                  <span className="scan-opt-label">Profile</span>
                  <select className="scan-opt-select" value={profile} onChange={(e) => setProfile(e.target.value)} disabled={running}>
                    <option value="quick">Quick</option>
                    <option value="standard">Standard</option>
                    <option value="thorough">Thorough</option>
                  </select>
                </div>
              )}

              {spec.creds && (
                <div className="scan-creds-grid">
                  <div className="scan-option-row">
                    <span className="scan-opt-label">Username</span>
                    <input className="scan-opt-input" type="text" value={cUser}
                           onChange={(e) => setCUser(e.target.value)} disabled={running}
                           placeholder="domain\\user or user" />
                  </div>
                  <div className="scan-option-row">
                    <span className="scan-opt-label">Password</span>
                    <input className="scan-opt-input" type="password" value={cPass}
                           onChange={(e) => setCPass(e.target.value)} disabled={running} />
                  </div>
                  <div className="scan-option-row">
                    <span className="scan-opt-label">Domain</span>
                    <input className="scan-opt-input" type="text" value={cDomain}
                           onChange={(e) => setCDomain(e.target.value)} disabled={running}
                           placeholder="CORP.LOCAL" />
                  </div>
                </div>
              )}

              {spec.lhost && (
                <div className="scan-option-row">
                  <span className="scan-opt-label">LHOST</span>
                  <input className="scan-opt-input" type="text" value={cLhost}
                         onChange={(e) => setCLhost(e.target.value)} disabled={running}
                         placeholder="attacker.ip:port" />
                </div>
              )}
            </div>
          )}

          {spec.flags && spec.flags.length > 0 && (
            <div className="scan-flags">
              <div className="scan-section-label">Flags</div>
              <div className="scan-flags-grid">
                {spec.flags.map((f) => (
                  <label key={f.name} className={"scan-flag" + (f.active ? " scan-flag-active" : "")}>
                    <input
                      type="checkbox"
                      checked={cFlags[f.name] || false}
                      onChange={(e) => setCFlags({ ...cFlags, [f.name]: e.target.checked })}
                      disabled={running}
                    />
                    <span>{f.label}</span>
                    {f.active && <span className="scan-flag-marker">active</span>}
                  </label>
                ))}
              </div>
            </div>
          )}

          <button className="scan-run-btn" onClick={runScan} disabled={running || (spec.targets === "required" && !targets.trim())}>
            {running ? (
              <><span className="scan-run-spinner" /> Running…</>
            ) : (
              <>▶ Execute</>
            )}
          </button>
        </div>

        {/* ── Job queue ── */}
        <div className="scan-queue">
          <div className="scan-queue-header">
            <h3>Job Queue</h3>
            <span className="scan-queue-counts">
              {runningJobs.length > 0 && <span className="scan-q-live">{runningJobs.length} running</span>}
              {recentJobs.length > 0 && <span className="scan-q-done">{recentJobs.length} completed</span>}
              {runningJobs.length === 0 && recentJobs.length === 0 && <span className="muted">idle</span>}
            </span>
          </div>

          {runningJobs.map((j) => (
            <div key={j.id} className="scan-job scan-job-running" onClick={() => streamJob(j.id)}>
              <div className="scan-job-indicator">
                <span className="scan-pulse" />
              </div>
              <div className="scan-job-body">
                <div className="scan-job-cmd">{j.cmd}</div>
                <div className="scan-job-meta">
                  <span className="scan-job-tester">{j.tester}</span>
                  <span className="scan-job-elapsed">{elapsed(j.started)}</span>
                </div>
              </div>
              <button className="scan-job-view" title="view output">▸</button>
            </div>
          ))}

          {recentJobs.length > 0 && runningJobs.length > 0 && <div className="scan-queue-divider" />}

          <div className="scan-history">
            {recentJobs.map((j) => (
              <div key={j.id} className={`scan-job scan-job-${j.status}`}>
                <span className="scan-job-icon">
                  {j.status === "done" ? "✓" : "✗"}
                </span>
                <div className="scan-job-body">
                  <div className="scan-job-cmd">{j.cmd}</div>
                  <div className="scan-job-meta">
                    <span className="scan-job-tester">{j.tester}</span>
                    <span className="scan-job-time">{new Date(j.started * 1000).toLocaleTimeString()}</span>
                    {j.ended && <span className="scan-job-dur">{elapsed(j.started, j.ended)}</span>}
                  </div>
                </div>
              </div>
            ))}
          </div>

          {runningJobs.length === 0 && recentJobs.length === 0 && (
            <div className="scan-queue-empty">
              <div className="scan-queue-empty-icon">📡</div>
              <div>No jobs yet</div>
              <div className="muted">Select a command and hit Execute</div>
            </div>
          )}
        </div>
      </div>

      {/* ── Console output (full width below) ── */}
      {showLog && (
        <div className="scan-console">
          <div className="scan-console-bar">
            <span className="scan-console-title">
              {running && <span className="scan-pulse-sm" />}
              Output
            </span>
            <span className="scan-console-meta">
              {log.length} line{log.length !== 1 ? "s" : ""}
            </span>
            <button className="scan-console-close" onClick={() => setShowLog(false)} title="close">✕</button>
          </div>
          <div className="scan-console-body" ref={logRef}>
            {log.map((line, i) => (
              <div key={i} className="scan-console-line">{line}</div>
            ))}
            {running && <div className="scan-console-line scan-console-cursor">_</div>}
            {!running && log.length > 0 && (
              <div className="scan-console-line scan-console-done">— done —</div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
