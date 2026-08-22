import { useEffect, useState, useRef, useCallback } from "react";
import { CmdCatalog, getCommands, postCommand } from "./api";

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

  // Fetch job list and stream updates for running jobs
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

  useEffect(() => {
    onRunning(running);
  }, [running, onRunning]);

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
      if (d.done) {
        es.close();
        setRunning(false);
      }
    };
    es.onerror = () => {
      es.close();
      setRunning(false);
    };
  }, []);

  async function runScan() {
    const spec = catalog[command];
    if (running) return;
    if (spec?.targets === "required" && !targets.trim()) return;
    const flags = Object.keys(cFlags).filter((k) => cFlags[k]);
    try {
      const { id } = await postCommand({
        command,
        targets,
        profile,
        username: spec?.creds ? cUser : undefined,
        password: spec?.creds ? cPass : undefined,
        domain: spec?.creds ? cDomain : undefined,
        lhost: spec?.lhost ? cLhost : undefined,
        flags,
      });
      streamJob(id);
    } catch (e) {
      setLog([`error: ${e}`]);
    }
  }

  const spec = catalog[command] || {};
  const runningJob = jobs.find((j) => j.status === "running");
  const recentJobs = jobs.filter((j) => j.status !== "running").slice(0, 10);

  return (
    <div className="scan-tab">
      <div className="scan-panel">
        <div className="scan-form">
          <h3>Command</h3>
          <label>
            Command
            <select value={command} onChange={(e) => setCommand(e.target.value)} disabled={running}>
              {Object.keys(catalog).map((k) => (
                <option key={k} value={k}>
                  {k}
                </option>
              ))}
            </select>
          </label>

          {spec.targets !== "none" && (
            <label>
              Targets {spec.targets === "required" && <span className="required">*</span>}
              <input
                type="text"
                value={targets}
                onChange={(e) => setTargets(e.target.value)}
                placeholder="10.0.0.0/24 or 10.0.0.5,10.0.0.10 or @file.txt"
                disabled={running}
              />
            </label>
          )}

          {spec.profile && (
            <label>
              Profile
              <select value={profile} onChange={(e) => setProfile(e.target.value)} disabled={running}>
                <option value="quick">quick</option>
                <option value="standard">standard</option>
                <option value="thorough">thorough</option>
              </select>
            </label>
          )}

          {spec.creds && (
            <>
              <label>
                Username
                <input
                  type="text"
                  value={cUser}
                  onChange={(e) => setCUser(e.target.value)}
                  disabled={running}
                />
              </label>
              <label>
                Password
                <input
                  type="password"
                  value={cPass}
                  onChange={(e) => setCPass(e.target.value)}
                  disabled={running}
                />
              </label>
              <label>
                Domain
                <input
                  type="text"
                  value={cDomain}
                  onChange={(e) => setCDomain(e.target.value)}
                  disabled={running}
                />
              </label>
            </>
          )}

          {spec.lhost && (
            <label>
              LHOST
              <input
                type="text"
                value={cLhost}
                onChange={(e) => setCLhost(e.target.value)}
                placeholder="your.ip:your.port"
                disabled={running}
              />
            </label>
          )}

          {spec.flags && (
            <div className="flags-group">
              <div className="flags-label">Flags</div>
              {spec.flags.map((f) => (
                <label key={f.name} className="flag-checkbox">
                  <input
                    type="checkbox"
                    checked={cFlags[f.name] || false}
                    onChange={(e) =>
                      setCFlags({ ...cFlags, [f.name]: e.target.checked })
                    }
                    disabled={running}
                  />
                  {f.label}
                  {f.active && <span className="active-marker"> [active]</span>}
                </label>
              ))}
            </div>
          )}

          <button onClick={runScan} disabled={running} className="run">
            {running ? "Running…" : "▶ Run"}
          </button>
        </div>

        <div className="scan-queue">
          <h3>Queue</h3>
          {runningJob && (
            <div className="job-item running">
              <div className="job-header">
                <span className="job-status">⟳ Running</span>
                <span className="job-cmd">{runningJob.cmd}</span>
              </div>
              <div className="job-meta">
                By <strong>{runningJob.tester}</strong> — {new Date(runningJob.started * 1000).toLocaleTimeString()}
              </div>
            </div>
          )}
          {recentJobs.map((j) => (
            <div key={j.id} className={`job-item ${j.status}`}>
              <div className="job-header">
                <span className={`job-status ${j.status}`}>
                  {j.status === "done" ? "✓" : j.status === "failed" ? "✗" : "⟳"}
                </span>
                <span className="job-cmd">{j.cmd}</span>
              </div>
              <div className="job-meta">
                By <strong>{j.tester}</strong> — {new Date(j.started * 1000).toLocaleTimeString()}
                {j.ended && ` (${Math.round((j.ended - j.started) / 60)}m)`}
              </div>
            </div>
          ))}
        </div>
      </div>

      {showLog && (
        <div className="scan-log">
          <div className="log-header">
            <h3>Progress</h3>
            <button className="log-close" onClick={() => setShowLog(false)}>
              ✕
            </button>
          </div>
          <div className="log-output" ref={logRef}>
            {log.map((line, i) => (
              <div key={i} className="log-line">
                {line}
              </div>
            ))}
            {running && <div className="log-line spinner">⟳ Running…</div>}
          </div>
        </div>
      )}
    </div>
  );
}
