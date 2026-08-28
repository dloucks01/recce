import { useEffect, useState, useRef, useCallback, useMemo } from "react";
import { CmdCatalog, CmdSpec, getCommands, postCommand, Host, getJSON } from "./api";
import { ScanConsole } from "./scan/ScanConsole";

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
  prefillTarget?: string | null;
}

type Preset = {
  label: string;
  desc: string;
  icon: string;
  cmds: { command: string; flags?: string[] }[];
};

const PRESETS: Preset[] = [
  {
    label: "Full Recon",
    desc: "Enumerate + vuln scan + deep sweep",
    icon: "🎯",
    cmds: [
      { command: "enum" },
      { command: "vulns" },
      { command: "sweep" },
    ],
  },
  {
    label: "Web App",
    desc: "Web crawl + API enum + nuclei active scan",
    icon: "🌐",
    cmds: [
      { command: "web", flags: ["crawl"] },
      { command: "api" },
      { command: "nuclei" },
    ],
  },
  {
    label: "AD Assessment",
    desc: "Kerberos + LDAP + SMB + DNS + Certipy (ADCS)",
    icon: "🏢",
    cmds: [
      { command: "kerberos" },
      { command: "ldap" },
      { command: "smb" },
      { command: "dns" },
      { command: "certipy" },
    ],
  },
  {
    label: "Database Sweep",
    desc: "Hit every database protocol",
    icon: "🗄",
    cmds: [
      { command: "db" },
    ],
  },
  {
    label: "Quick Vuln Scan",
    desc: "Fast vuln scan with aggressive NSE",
    icon: "⚡",
    cmds: [
      { command: "vulns", flags: ["aggressive"] },
    ],
  },
  {
    label: "Triage + Verify",
    desc: "Dry-run NSE re-checks against version leads",
    icon: "🔍",
    cmds: [
      { command: "verify" },
      { command: "prove" },
    ],
  },
  {
    label: "Exploit Planning",
    desc: "Attack path + exploit plan + PoC dossiers",
    icon: "💥",
    cmds: [
      { command: "attackpath" },
      { command: "exploitplan" },
      { command: "poc" },
    ],
  },
];

const GROUP_META: Record<string, { icon: string; desc: string }> = {
  scan: { icon: "📶", desc: "Port & vulnerability scanning" },
  services: { icon: "📡", desc: "Service enumeration" },
  databases: { icon: "🗄", desc: "Database enumeration & extraction" },
  web: { icon: "🌐", desc: "Web application testing" },
  credentialed: { icon: "🔑", desc: "Authenticated / credentialed checks" },
  exploitation: { icon: "💥", desc: "Exploit & attack modules" },
  reporting: { icon: "📋", desc: "Report generation & analysis" },
  discovery: { icon: "🔍", desc: "Network & host discovery" },
  enumeration: { icon: "📡", desc: "Protocol enumeration" },
  credential: { icon: "🔑", desc: "Credential testing" },
  bruteforce: { icon: "🔨", desc: "Brute-force attacks" },
  auxiliary: { icon: "🧰", desc: "Utility modules" },
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

type QueueItem = { command: string; targets: string; flags: string[]; label: string };

// `tester` stays in ScanTabProps (App passes it) but is unused here - the job
// rows render each job's own j.tester, not the current operator.
export function ScanTab({ onRunning, onLog, prefillTarget }: ScanTabProps) {
  const [catalog, setCatalog] = useState<CmdCatalog>({});
  const [hosts, setHosts] = useState<Host[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [activeGroup, setActiveGroup] = useState<string | null>(null);
  const [command, setCommand] = useState<string | null>(null);
  const [targets, setTargets] = useState("");

  useEffect(() => { if (prefillTarget) setTargets(prefillTarget); }, [prefillTarget]);
  const [profile, setProfile] = useState("quick");
  const [cUser, setCUser] = useState("");
  const [cPass, setCPass] = useState("");
  const [cDomain, setCDomain] = useState("");
  const [cLhost, setCLhost] = useState("");
  const [cFlags, setCFlags] = useState<Record<string, boolean>>({});
  // Value-carrying flags (text/int/list). Kept separate from boolean cFlags
  // so both can be sent to the backend independently.
  const [cFlagValues, setCFlagValues] = useState<Record<string, string>>({});
  // Bundled wordlist catalog, fetched once. Kind → list of {name, blurb,
  // line_count} entries. Feeds the dropdown next to every "wordlist"-kind
  // flag input. Empty until the first successful fetch.
  const [wordlists, setWordlists] = useState<Record<string, Array<{name:string; blurb:string; line_count:number}>>>({});
  const [log, setLog] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const [showLog, setShowLog] = useState(false);
  const [showSuggest, setShowSuggest] = useState(false);
  const [queue, setQueue] = useState<QueueItem[]>([]);
  const [chainRunning, setChainRunning] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const suggestRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    getCommands().then((c) => {
      setCatalog(c);
      const groups = Object.keys(groupBy(c));
      if (groups.length > 0) setActiveGroup(groups[0]);
    }).catch(() => {});
    getJSON<{ items: Host[] }>("/api/hosts?limit=500").then((r) => setHosts(r.items || [])).catch(() => {});
    // Bundled wordlists — one fetch, group by kind so each scan card's
    // dropdown filters to the relevant family without re-hitting the API.
    getJSON<{wordlists: Array<{name:string; kind:string; blurb:string; line_count:number}>}>("/api/wordlists")
      .then((r) => {
        const by: Record<string, Array<{name:string; blurb:string; line_count:number}>> = {};
        for (const w of r.wordlists || []) {
          if (!by[w.kind]) by[w.kind] = [];
          by[w.kind].push({ name: w.name, blurb: w.blurb, line_count: w.line_count });
        }
        setWordlists(by);
      }).catch(() => {});
  }, []);

  useEffect(() => {
    // Auto-refresh of Dashboard/Findings on scan completion is already
    // handled by useEngagement.ts subscribing to /api/events SSE and
    // calling refresh() on `type=scan` events. This poller is just the
    // Jobs list on the right rail — no cross-tab broadcast needed here.
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

  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (suggestRef.current && !suggestRef.current.contains(e.target as Node)) setShowSuggest(false);
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

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
    // Only forward non-empty flag_values (empty inputs → drop from the wire so
    // the backend's kind-specific validation doesn't need to see empty strings).
    const flag_values: Record<string, string> = {};
    for (const [k, v] of Object.entries(cFlagValues)) {
      if (v && v.trim()) flag_values[k] = v;
    }
    try {
      const { id } = await postCommand({
        command, targets, profile,
        username: s.creds ? cUser : undefined,
        password: s.creds ? cPass : undefined,
        domain: s.creds ? cDomain : undefined,
        lhost: s.lhost ? cLhost : undefined,
        flags,
        flag_values: Object.keys(flag_values).length ? flag_values : undefined,
      });
      streamJob(id);
    } catch (e) {
      setLog([`error: ${e}`]);
      setShowLog(true);
    }
  }

  async function runPreset(preset: Preset) {
    if (running || chainRunning) return;
    const t = targets.trim();
    const valid = preset.cmds.every((c) => {
      const s = catalog[c.command];
      return s && (s.targets !== "required" || t);
    });
    if (!valid) {
      setLog([`⚠ preset "${preset.label}" requires targets — enter a target above first`]);
      setShowLog(true);
      return;
    }
    setChainRunning(true);
    setShowLog(true);
    setLog([`▶ Running preset: ${preset.label} (${preset.cmds.length} scans)`]);
    for (const c of preset.cmds) {
      const s = catalog[c.command];
      if (!s) continue;
      try {
        setLog((l) => [...l, `\n━━━ ${s.label} ━━━`]);
        const { id } = await postCommand({
          command: c.command, targets: t, profile,
          flags: c.flags || [],
        });
        await new Promise<void>((resolve) => {
          const es = new EventSource(`/api/jobs/${id}/events`);
          es.onmessage = (m) => {
            try {
              const d = JSON.parse(m.data);
              if (d.line !== undefined) setLog((l) => [...l, d.line]);
              if (d.done) { es.close(); resolve(); }
            } catch {}
          };
          es.onerror = () => { es.close(); resolve(); };
        });
      } catch (e) {
        setLog((l) => [...l, `error: ${e}`]);
      }
    }
    setLog((l) => [...l, `\n✓ Preset "${preset.label}" complete`]);
    setChainRunning(false);
  }

  function addToQueue() {
    if (!command) return;
    const s = catalog[command];
    if (!s) return;
    const flags = Object.keys(cFlags).filter((k) => cFlags[k]);
    setQueue((q) => [...q, {
      command,
      targets: targets.trim(),
      flags,
      label: s.label,
    }]);
  }

  async function runQueue() {
    if (running || chainRunning || queue.length === 0) return;
    setChainRunning(true);
    setShowLog(true);
    setLog([`▶ Running scan chain (${queue.length} commands)`]);
    const items = [...queue];
    setQueue([]);
    for (const item of items) {
      try {
        setLog((l) => [...l, `\n━━━ ${item.label} ━━━`]);
        const { id } = await postCommand({
          command: item.command,
          targets: item.targets,
          profile,
          flags: item.flags,
        });
        await new Promise<void>((resolve) => {
          const es = new EventSource(`/api/jobs/${id}/events`);
          es.onmessage = (m) => {
            try {
              const d = JSON.parse(m.data);
              if (d.line !== undefined) setLog((l) => [...l, d.line]);
              if (d.done) { es.close(); resolve(); }
            } catch {}
          };
          es.onerror = () => { es.close(); resolve(); };
        });
      } catch (e) {
        setLog((l) => [...l, `error: ${e}`]);
      }
    }
    setLog((l) => [...l, `\n✓ Scan chain complete`]);
    setChainRunning(false);
  }

  const grouped = useMemo(() => groupBy(catalog), [catalog]);
  const groups = Object.entries(grouped);
  const currentCmds = activeGroup ? grouped[activeGroup] || [] : [];
  const spec = command ? catalog[command] : null;
  const runningJobs = jobs.filter((j) => j.status === "running");
  const recentJobs = jobs.filter((j) => j.status !== "running").slice(0, 10);

  const filteredHosts = useMemo(() => {
    if (!targets.trim()) return hosts.slice(0, 10);
    const q = targets.toLowerCase();
    return hosts.filter((h) =>
      h.ip.includes(q) || h.hostname?.toLowerCase().includes(q)
    ).slice(0, 10);
  }, [hosts, targets]);

  const isBusy = running || chainRunning;

  return (
    <div className="sv2">
      {/* Quick-start presets */}
      <div className="sv2-presets">
        <div className="sv2-presets-h">
          <span className="sv2-presets-label">Quick Start</span>
          <span className="muted small">{Object.keys(catalog).length} commands available</span>
        </div>
        <div className="sv2-presets-grid">
          {PRESETS.map((p) => (
            <button
              key={p.label}
              className="sv2-preset"
              onClick={() => runPreset(p)}
              disabled={isBusy}
              title={p.desc}
            >
              <span className="sv2-preset-icon">{p.icon}</span>
              <span className="sv2-preset-body">
                <span className="sv2-preset-name">{p.label}</span>
                <span className="sv2-preset-desc">{p.desc}</span>
              </span>
              <span className="sv2-preset-ct">{p.cmds.length}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Target bar */}
      <div className="sv2-targetbar" ref={suggestRef}>
        <label className="sv2-field sv2-target-field">
          <span className="sv2-label">Target(s)</span>
          <input
            className="sv2-input"
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
            onFocus={() => setShowSuggest(true)}
            placeholder="10.0.0.0/24, 10.0.0.5, hostname, or @targets.txt"
            disabled={isBusy}
          />
        </label>
        {showSuggest && filteredHosts.length > 0 && (
          <div className="sv2-suggest">
            <div className="sv2-suggest-h">Discovered hosts</div>
            {filteredHosts.map((h) => (
              <button
                key={h.ip}
                className="sv2-suggest-item"
                onClick={() => {
                  setTargets((t) => t ? `${t.replace(/,\s*$/, "")}, ${h.ip}` : h.ip);
                  setShowSuggest(false);
                }}
              >
                <span className="sv2-suggest-ip">{h.ip}</span>
                {h.hostname && <span className="sv2-suggest-name">{h.hostname}</span>}
                {h.os && <span className="sv2-suggest-os">{h.os.slice(0, 30)}</span>}
                <span className="sv2-suggest-ports">
                  {h.ports?.slice(0, 5).map((p) => p.port).join(", ")}
                  {(h.ports?.length || 0) > 5 && "…"}
                </span>
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Category tabs */}
      <div className="sv2-tabs">
        {groups.map(([g, cmds]) => {
          const meta = GROUP_META[g.toLowerCase()] || { icon: "▸", desc: g };
          return (
            <button
              key={g}
              className={`sv2-tab ${activeGroup === g ? "active" : ""}`}
              onClick={() => { setActiveGroup(g); setCommand(null); setCFlags({}); setCFlagValues({}); }}
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
                    onClick={() => { setCommand(key); setCFlags({}); setCFlagValues({}); }}
                    disabled={isBusy}
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

                  {spec.profile && (
                    <label className="sv2-field">
                      <span className="sv2-label">Profile</span>
                      <select className="sv2-input" value={profile} onChange={(e) => setProfile(e.target.value)} disabled={isBusy}
                              title="Stealth: slower T2, congestion-adaptive from pass 1, top-1000 TCP. Use when the target's IDS/rate-limiter is the constraint.">
                        <option value="quick">Quick</option>
                        <option value="standard">Standard</option>
                        <option value="thorough">Thorough</option>
                        <option value="stealth">Stealth (slow, rate-limit-safe)</option>
                      </select>
                    </label>
                  )}

                  {spec.creds && (
                    <div className="sv2-cred-grid">
                      <label className="sv2-field">
                        <span className="sv2-label">Username</span>
                        <input className="sv2-input" value={cUser} onChange={(e) => setCUser(e.target.value)}
                               placeholder="domain\user" disabled={isBusy} />
                      </label>
                      <label className="sv2-field">
                        <span className="sv2-label">Password</span>
                        <input className="sv2-input" type="password" value={cPass}
                               onChange={(e) => setCPass(e.target.value)} disabled={isBusy} />
                      </label>
                      <label className="sv2-field">
                        <span className="sv2-label">Domain</span>
                        <input className="sv2-input" value={cDomain} onChange={(e) => setCDomain(e.target.value)}
                               placeholder="CORP.LOCAL" disabled={isBusy} />
                      </label>
                    </div>
                  )}

                  {spec.lhost && (
                    <label className="sv2-field">
                      <span className="sv2-label">LHOST</span>
                      <input className="sv2-input" value={cLhost} onChange={(e) => setCLhost(e.target.value)}
                             placeholder="attacker.ip:port" disabled={isBusy} />
                    </label>
                  )}

                  {spec.flags && spec.flags.length > 0 && (
                    <div className="sv2-flags">
                      <span className="sv2-label">Flags</span>
                      <div className="sv2-flag-list">
                        {spec.flags.filter(f => (f.kind || "bool") === "bool").map((f) => (
                          <label key={f.name} className={`sv2-flag ${cFlags[f.name] ? "on" : ""}`}>
                            <input type="checkbox" checked={cFlags[f.name] || false}
                                   onChange={(e) => setCFlags({ ...cFlags, [f.name]: e.target.checked })}
                                   disabled={isBusy} />
                            <span>{f.label}</span>
                            {f.active && <span className="sv2-flag-hot">active</span>}
                          </label>
                        ))}
                      </div>
                      {spec.flags.some(f => (f.kind || "bool") !== "bool") && (
                        <div className="sv2-value-flags">
                          {spec.flags.filter(f => (f.kind || "bool") !== "bool").map((f) => {
                            // Wordlist flags: dropdown of bundled options
                            // filtered by wordlist_kind + free-text
                            // override. The dropdown seeds the input with
                            // `bundled:<name>`; the input stays editable so
                            // the operator can type a local file path.
                            if (f.kind === "wordlist") {
                              const opts = (wordlists[(f as any).wordlist_kind || ""] || []);
                              const cur = cFlagValues[f.name] || "";
                              // Sync dropdown selection to the current
                              // value (so the operator sees which bundled
                              // list is active even after page reload).
                              const selVal = cur.startsWith("bundled:") ? cur : "";
                              return (
                                <label key={f.name} className="sv2-field sv2-value-flag">
                                  <span className="sv2-label">
                                    {f.label}
                                    {f.active && <span className="sv2-flag-hot" style={{marginLeft:6}}>active</span>}
                                  </span>
                                  <div className="sv2-wordlist-row">
                                    <select className="sv2-select sv2-wordlist-picker"
                                            value={selVal}
                                            disabled={isBusy || opts.length === 0}
                                            title={opts.length === 0 ? "loading wordlists…" : "pick a bundled wordlist"}
                                            onChange={(e) => {
                                              const v = e.target.value;
                                              setCFlagValues({ ...cFlagValues, [f.name]: v });
                                            }}>
                                      <option value="">{opts.length === 0 ? "loading…" : "— bundled list —"}</option>
                                      {opts.map(o => (
                                        <option key={o.name} value={`bundled:${o.name}`}
                                                title={o.blurb}>
                                          {o.name} ({o.line_count})
                                        </option>
                                      ))}
                                    </select>
                                    <input className="sv2-input sv2-wordlist-input"
                                           type="text"
                                           value={cur}
                                           placeholder={f.placeholder || "bundled:<name> or /path/to/file"}
                                           disabled={isBusy}
                                           onChange={(e) => setCFlagValues({ ...cFlagValues, [f.name]: e.target.value })} />
                                  </div>
                                  {selVal && opts.find(o => `bundled:${o.name}` === selVal) && (
                                    <span className="sv2-wordlist-blurb">
                                      {opts.find(o => `bundled:${o.name}` === selVal)?.blurb}
                                    </span>
                                  )}
                                </label>
                              );
                            }
                            return (
                              <label key={f.name} className="sv2-field sv2-value-flag">
                                <span className="sv2-label">
                                  {f.label}
                                  {f.active && <span className="sv2-flag-hot" style={{marginLeft:6}}>active</span>}
                                </span>
                                <input className="sv2-input"
                                       type={f.kind === "int" ? "number" : "text"}
                                       value={cFlagValues[f.name] || ""}
                                       placeholder={f.placeholder || f.flag}
                                       disabled={isBusy}
                                       onChange={(e) => setCFlagValues({ ...cFlagValues, [f.name]: e.target.value })} />
                              </label>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  )}

                  <div className="sv2-exec-row">
                    <button
                      className="sv2-exec"
                      onClick={runScan}
                      disabled={isBusy || (spec.targets === "required" && !targets.trim())}
                    >
                      {isBusy ? <><span className="sv2-spinner" /> Running&hellip;</> : <span>&#9654; Execute</span>}
                    </button>
                    <button
                      className="sv2-queue-add"
                      onClick={addToQueue}
                      disabled={isBusy}
                      title="Add to scan chain — queue multiple commands to run in sequence"
                    >
                      + Chain
                    </button>
                  </div>
                </div>
              )}

              {!command && (
                <div className="sv2-hint">Select a command above to configure and run it</div>
              )}
            </>
          )}
        </div>

        {/* Right: job queue + scan chain */}
        <div className="sv2-jobs">
          {/* Scan chain */}
          {queue.length > 0 && (
            <div className="sv2-chain">
              <div className="sv2-chain-h">
                <h4>Scan Chain</h4>
                <span className="muted small">{queue.length} queued</span>
              </div>
              {queue.map((q, i) => (
                <div key={i} className="sv2-chain-item">
                  <span className="sv2-chain-num">{i + 1}</span>
                  <span className="sv2-chain-label">{q.label}</span>
                  {q.targets && <span className="sv2-chain-target">{q.targets}</span>}
                  <button className="sv2-chain-rm" onClick={() => setQueue((qs) => qs.filter((_, j) => j !== i))}>×</button>
                </div>
              ))}
              <div className="sv2-chain-actions">
                <button className="sv2-exec sv2-chain-run" onClick={runQueue} disabled={isBusy}>
                  ▶ Run Chain ({queue.length})
                </button>
                <button className="sv2-chain-clear" onClick={() => setQueue([])}>Clear</button>
              </div>
            </div>
          )}

          <div className="sv2-jobs-h">
            <h3>Jobs</h3>
            {runningJobs.length > 0 && <span className="sv2-live">{runningJobs.length} running</span>}
          </div>

          {runningJobs.map((j) => (
            <div key={j.id} className="sv2-job live" onClick={() => streamJob(j.id)} title={j.cmd}>
              <span className="sv2-job-dot" />
              <div className="sv2-job-info">
                <div className="sv2-job-cmd">{j.cmd}</div>
                <div className="sv2-job-meta">{j.tester} &middot; {elapsed(j.started)}</div>
              </div>
              <button className="sv2-job-cancel" title="cancel this scan"
                      onClick={(e) => {
                        e.stopPropagation();
                        if (!window.confirm(`Cancel this scan?\n\n${j.cmd}`)) return;
                        fetch(`/api/jobs/${j.id}/cancel`, { method: "POST" });
                      }}>✕</button>
            </div>
          ))}

          {recentJobs.map((j) => (
            <div key={j.id} className={`sv2-job ${j.status}`} title={j.cmd}>
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

          {runningJobs.length === 0 && recentJobs.length === 0 && queue.length === 0 && (
            <div className="sv2-jobs-empty">No jobs yet</div>
          )}
        </div>
      </div>

      {/* Console output */}
      {showLog && (
        <ScanConsole
          log={log}
          running={running}
          chainRunning={chainRunning}
          logRef={logRef}
          onClose={() => setShowLog(false)}
        />
      )}
    </div>
  );
}
