import { useEffect, useState, useRef, useCallback, useMemo } from "react";
import { CmdCatalog, CmdSpec, getCommands, postCommand, Host, getJSON, ScanSuggestion } from "./api";
import { SevTag } from "./ui";
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
  mail: { icon: "✉", desc: "Mail server enumeration (IMAP / POP3)" },
  storage: { icon: "💾", desc: "Networked storage (iSCSI / NBD / WebDAV)" },
  virtualization: { icon: "🖧", desc: "Hypervisors & cloud metadata surfaces" },
  monitoring: { icon: "📊", desc: "Monitoring agents (NRPE / Zabbix)" },
  "ot/ics": { icon: "⚙", desc: "OT / ICS / SCADA protocols" },
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
  // Discovered-host list is fetched to keep parity with the older tab, even
  // though the v3 layout surfaces host suggestions inline via scan/context.
  const [, setHosts] = useState<Host[]>([]);
  const [jobs, setJobs] = useState<Job[]>([]);
  const [command, setCommand] = useState<string | null>(null);
  const [scanCtx, setScanCtx] = useState<Record<string, {count: number; sample: string[]; hint?: string}>>({});
  const [suggestions, setSuggestions] = useState<ScanSuggestion[]>([]);
  const [dismissedSuggestions, setDismissedSuggestions] = useState<Set<string>>(() => {
    try {
      const raw = localStorage.getItem("recce.scan.dismissedSuggestions") || "[]";
      return new Set<string>(JSON.parse(raw));
    } catch { return new Set(); }
  });
  const [targets, setTargets] = useState("");

  useEffect(() => { if (prefillTarget) setTargets(prefillTarget); }, [prefillTarget]);
  const [profile, setProfile] = useState("quick");
  const [cUser, setCUser] = useState("");
  const [cPass, setCPass] = useState("");
  const [cDomain, setCDomain] = useState("");
  const [cLhost, setCLhost] = useState("");
  const [cFlags, setCFlags] = useState<Record<string, boolean>>({});
  const [cFlagValues, setCFlagValues] = useState<Record<string, string>>({});
  const [wordlists, setWordlists] = useState<Record<string, Array<{name:string; blurb:string; line_count:number}>>>({});
  const [log, setLog] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const [showLog, setShowLog] = useState(false);
  const [queue, setQueue] = useState<QueueItem[]>([]);
  const [chainRunning, setChainRunning] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const chainCancelledRef = useRef(false);
  const chainCurrentJobRef = useRef<string | null>(null);
  const chainCurrentEsRef = useRef<EventSource | null>(null);
  const [chainStopping, setChainStopping] = useState(false);

  // Sidebar state (two-pane workbench)
  const [treeSearch, setTreeSearch] = useState("");
  const [expandedGroups, setExpandedGroups] = useState<Set<string>>(() => {
    try {
      const raw = localStorage.getItem("recce.scan.expandedGroups") || "[]";
      return new Set<string>(JSON.parse(raw));
    } catch { return new Set(); }
  });
  const [presetOpen, setPresetOpen] = useState(false);
  const presetRef = useRef<HTMLDivElement>(null);
  // Persist which groups are expanded so operators don't re-open the same
  // three groups every reload.
  useEffect(() => {
    try {
      localStorage.setItem("recce.scan.expandedGroups",
        JSON.stringify(Array.from(expandedGroups)));
    } catch {}
  }, [expandedGroups]);

  useEffect(() => {
    getJSON<{hosts: number; commands: Record<string, {count: number; sample: string[]; hint?: string}>}>(
      "/api/scan/context").then((r) => setScanCtx(r.commands)).catch(() => {});
    getJSON<{suggestions: ScanSuggestion[]}>(
      "/api/scan/suggestions").then((r) => setSuggestions(r.suggestions || [])).catch(() => {});
    getCommands().then((c) => {
      setCatalog(c);
      // Expand the two most-used groups by default so first-load isn't a
      // wall of collapsed section headings.
      const groups = Object.keys(groupBy(c));
      setExpandedGroups((prev) => {
        if (prev.size > 0) return prev;
        const next = new Set(prev);
        for (const preferred of ["scan", "services", "web", "databases"]) {
          if (groups.includes(preferred)) next.add(preferred);
        }
        return next;
      });
    }).catch(() => {});
    getJSON<{ items: Host[] }>("/api/hosts?limit=500").then((r) => setHosts(r.items || [])).catch(() => {});
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

  // Close preset dropdown on outside click.
  useEffect(() => {
    if (!presetOpen) return;
    function close(e: MouseEvent) {
      if (presetRef.current && !presetRef.current.contains(e.target as Node)) setPresetOpen(false);
    }
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [presetOpen]);

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
    const cmdList = preset.cmds
      .map((c) => `  • ${catalog[c.command]?.label || c.command}`)
      .join("\n");
    const targetSummary = t || "(engagement default)";
    if (!window.confirm(
      `Run the "${preset.label}" preset?\n\n` +
      `${preset.cmds.length} scan(s) will run in sequence against: ${targetSummary}\n\n` +
      cmdList +
      `\n\nThe scans run one after another. Click Stop chain in the console\n` +
      `at any time to cancel the in-flight scan and skip the rest.`
    )) return;
    chainCancelledRef.current = false;
    setChainRunning(true);
    setShowLog(true);
    setLog([`▶ Running preset: ${preset.label} (${preset.cmds.length} scans)`]);
    for (const c of preset.cmds) {
      if (chainCancelledRef.current) {
        setLog((l) => [...l, `\n⛔ Chain cancelled — remaining ${preset.cmds.length - preset.cmds.indexOf(c)} scan(s) skipped`]);
        break;
      }
      const s = catalog[c.command];
      if (!s) continue;
      try {
        setLog((l) => [...l, `\n━━━ ${s.label} ━━━`]);
        const { id } = await postCommand({
          command: c.command, targets: t, profile,
          flags: c.flags || [],
        });
        chainCurrentJobRef.current = id;
        await new Promise<void>((resolve) => {
          const es = new EventSource(`/api/jobs/${id}/events`);
          chainCurrentEsRef.current = es;
          es.onmessage = (m) => {
            try {
              const d = JSON.parse(m.data);
              if (d.line !== undefined) setLog((l) => [...l, d.line]);
              if (d.done) { es.close(); resolve(); }
            } catch {}
          };
          es.onerror = () => { es.close(); resolve(); };
        });
        chainCurrentJobRef.current = null;
        chainCurrentEsRef.current = null;
      } catch (e) {
        setLog((l) => [...l, `error: ${e}`]);
      }
    }
    if (!chainCancelledRef.current)
      setLog((l) => [...l, `\n✓ Preset "${preset.label}" complete`]);
    setChainRunning(false);
    setChainStopping(false);
  }

  async function stopChain() {
    if (!chainRunning) return;
    if (!window.confirm(
      "Stop the running scan chain?\n\n" +
      "The current scan will be cancelled and any remaining\n" +
      "scans in the chain will be skipped."
    )) return;
    setChainStopping(true);
    chainCancelledRef.current = true;
    const jid = chainCurrentJobRef.current;
    if (jid) {
      try { await fetch(`/api/jobs/${jid}/cancel`, { method: "POST" }); }
      catch { /* server may already have finished the job */ }
    }
    try { chainCurrentEsRef.current?.close(); } catch { /* noop */ }
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
    const listing = queue.map((item) => `  • ${item.label}`).join("\n");
    if (!window.confirm(
      `Run the queued scan chain?\n\n` +
      `${queue.length} scan(s) will run in sequence:\n\n${listing}\n\n` +
      `Click Stop chain in the console at any time to cancel.`
    )) return;
    chainCancelledRef.current = false;
    setChainRunning(true);
    setShowLog(true);
    setLog([`▶ Running scan chain (${queue.length} commands)`]);
    const items = [...queue];
    setQueue([]);
    for (const item of items) {
      if (chainCancelledRef.current) {
        setLog((l) => [...l, `\n⛔ Chain cancelled — remaining ${items.length - items.indexOf(item)} scan(s) skipped`]);
        break;
      }
      try {
        setLog((l) => [...l, `\n━━━ ${item.label} ━━━`]);
        const { id } = await postCommand({
          command: item.command,
          targets: item.targets,
          profile,
          flags: item.flags,
        });
        chainCurrentJobRef.current = id;
        await new Promise<void>((resolve) => {
          const es = new EventSource(`/api/jobs/${id}/events`);
          chainCurrentEsRef.current = es;
          es.onmessage = (m) => {
            try {
              const d = JSON.parse(m.data);
              if (d.line !== undefined) setLog((l) => [...l, d.line]);
              if (d.done) { es.close(); resolve(); }
            } catch {}
          };
          es.onerror = () => { es.close(); resolve(); };
        });
        chainCurrentJobRef.current = null;
        chainCurrentEsRef.current = null;
      } catch (e) {
        setLog((l) => [...l, `error: ${e}`]);
      }
    }
    if (!chainCancelledRef.current)
      setLog((l) => [...l, `\n✓ Scan chain complete`]);
    setChainRunning(false);
    setChainStopping(false);
  }

  // Group active (non-dismissed) suggestions by target command so multiple
  // hints for the same command render as one card.
  const visibleSuggestions = useMemo(
    () => suggestions.filter((s) => !dismissedSuggestions.has(s.key)),
    [suggestions, dismissedSuggestions]);
  const rank = (s: ScanSuggestion) => {
    const sev = s.severity || "";
    if (sev === "critical") return 0;
    if (sev === "high") return 1;
    if (sev === "medium") return 2;
    if (sev === "low") return 3;
    if (s.confidence === "high") return 4;
    if (s.confidence === "medium") return 5;
    return 6;
  };
  const groupedSuggestions = useMemo(() => {
    const g: Record<string, ScanSuggestion[]> = {};
    for (const s of visibleSuggestions) {
      const bucket = s.command || `~${s.source}`;
      (g[bucket] ||= []).push(s);
    }
    for (const bucket of Object.keys(g)) g[bucket].sort((a, b) => rank(a) - rank(b));
    const ordered: Record<string, ScanSuggestion[]> = {};
    Object.entries(g)
      .sort(([, a], [, b]) => rank(a[0]) - rank(b[0]))
      .forEach(([k, v]) => { ordered[k] = v; });
    return ordered;
  }, [visibleSuggestions]);
  // Suggestions targeted at the current command — surfaced above the flag
  // form so a Prefill click is right where the flag inputs are.
  const currentSuggestions = useMemo(
    () => (command ? (groupedSuggestions[command] || []) : []),
    [command, groupedSuggestions]);

  function dismissSuggestion(key: string) {
    setDismissedSuggestions((prev) => {
      const next = new Set(prev);
      next.add(key);
      try {
        localStorage.setItem("recce.scan.dismissedSuggestions",
          JSON.stringify(Array.from(next)));
      } catch {}
      return next;
    });
  }

  function applySuggestion(s: ScanSuggestion) {
    if (!s.command) return;
    const spec = catalog[s.command];
    if (!spec) return;
    setCommand(s.command);
    setExpandedGroups((prev) => new Set(prev).add(spec.group || "other"));
    setCFlags({});
    setCFlagValues({});
    if (s.field === "targets")  setTargets(s.suggested_value);
    if (s.field === "username") setCUser(s.suggested_value);
    if (s.field === "domain")   setCDomain(s.suggested_value);
  }

  const grouped = useMemo(() => groupBy(catalog), [catalog]);
  const groups = Object.entries(grouped);
  const spec = command ? catalog[command] : null;
  const runningJobs = jobs.filter((j) => j.status === "running");
  const isBusy = running || chainRunning;

  // Search filter for the sidebar tree — match either command key or its label.
  const searchQ = treeSearch.trim().toLowerCase();
  const filteredGroups = useMemo(() => {
    if (!searchQ) return groups;
    const out: [string, { key: string; spec: CmdSpec }[]][] = [];
    for (const [g, cmds] of groups) {
      const hits = cmds.filter(({ key, spec: s }) =>
        key.toLowerCase().includes(searchQ) ||
        (s.label || "").toLowerCase().includes(searchQ));
      if (hits.length) out.push([g, hits]);
    }
    return out;
  }, [groups, searchQ]);

  // Live-target hint for the currently selected command.
  const cmdCtx = command ? scanCtx[command] : null;

  function toggleGroup(g: string) {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(g)) next.delete(g);
      else next.add(g);
      return next;
    });
  }
  // A group is treated as expanded when it's in the set OR the search is
  // active (search auto-expands every matching group so hits stay visible).
  const isExpanded = (g: string) => !!searchQ || expandedGroups.has(g);

  function selectCommand(key: string) {
    setCommand(key);
    setCFlags({});
    setCFlagValues({});
    const grp = catalog[key]?.group;
    if (grp) setExpandedGroups((prev) => new Set(prev).add(grp));
  }

  return (
    <div className="sv3">
      {/* -- Sticky top bar: target + preset + launch ------------------- */}
      <div className="sv3-topbar">
        <div className="sv3-topbar-target">
          <span className="sv3-tag">🎯 Target</span>
          <input
            className="sv3-target-input"
            value={targets}
            onChange={(e) => setTargets(e.target.value)}
            placeholder="10.0.0.0/24, 10.0.0.5, hostname, or @targets.txt"
            disabled={isBusy}
          />
        </div>
        <div className="sv3-topbar-actions">
          <div className="sv3-preset-menu" ref={presetRef}>
            <button className="sv3-btn sv3-btn-ghost"
                    onClick={() => setPresetOpen((v) => !v)}
                    disabled={isBusy}
                    title="Run a bundled multi-command scan chain">
              📋 Preset ▾
            </button>
            {presetOpen && (
              <div className="sv3-preset-popup" role="menu">
                {PRESETS.map((p) => (
                  <button key={p.label} className="sv3-preset-item" role="menuitem"
                          onClick={() => { setPresetOpen(false); runPreset(p); }}>
                    <span className="sv3-preset-ico">{p.icon}</span>
                    <span className="sv3-preset-body">
                      <span className="sv3-preset-name">{p.label}</span>
                      <span className="sv3-preset-desc">{p.desc}</span>
                    </span>
                    <span className="sv3-preset-ct">{p.cmds.length}</span>
                  </button>
                ))}
              </div>
            )}
          </div>
          <button className="sv3-btn sv3-btn-primary"
                  onClick={runScan}
                  disabled={!command || isBusy || (spec?.targets === "required" && !targets.trim())}
                  title={command ? `Run ${catalog[command]?.label || command} now` : "Select a scan from the sidebar first"}>
            {isBusy ? <><span className="sv3-spinner" /> Running…</> : <>▶ Launch scan</>}
          </button>
        </div>
      </div>

      {/* -- Body: sidebar tree + form pane ---------------------------- */}
      <div className="sv3-body">
        {/* Left sidebar */}
        <aside className="sv3-tree">
          <input className="sv3-tree-search"
                 placeholder="Search commands…"
                 value={treeSearch}
                 onChange={(e) => setTreeSearch(e.target.value)} />
          <div className="sv3-tree-scroll">
            {filteredGroups.length === 0 && (
              <div className="sv3-tree-empty">No commands match "{searchQ}"</div>
            )}
            {filteredGroups.map(([g, cmds]) => {
              const meta = GROUP_META[g.toLowerCase()] || { icon: "▸", desc: g };
              const open = isExpanded(g);
              return (
                <div key={g} className="sv3-tree-group">
                  <button className="sv3-tree-group-h"
                          onClick={() => toggleGroup(g)}
                          title={meta.desc}>
                    <span className="sv3-tree-chev">{open ? "▾" : "▸"}</span>
                    <span className="sv3-tree-ico">{meta.icon}</span>
                    <span className="sv3-tree-lbl">{g}</span>
                    <span className="sv3-tree-ct">{cmds.length}</span>
                  </button>
                  {open && (
                    <div className="sv3-tree-cmds">
                      {cmds.map(({ key, spec: s }) => {
                        const ctx = scanCtx[key];
                        const active = command === key;
                        return (
                          <button key={key}
                                  className={"sv3-tree-cmd" + (active ? " active" : "")}
                                  onClick={() => selectCommand(key)}
                                  disabled={isBusy}
                                  title={ctx && ctx.count > 0
                                    ? `${ctx.count} discovered host(s) expose ${key}`
                                    : (s.label || key)}>
                            <span className="sv3-tree-cmd-name">{s.label || key}</span>
                            <span className="sv3-tree-cmd-tags">
                              {ctx && ctx.count > 0 && (
                                <span className="sv3-dot sv3-dot-ok" title={`${ctx.count} discovered host(s)`}>{ctx.count}</span>
                              )}
                              {s.creds && <span className="sv3-mini-tag" title="needs creds">🔑</span>}
                              {s.targets === "required" && <span className="sv3-mini-tag" title="target required">◎</span>}
                            </span>
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
          <div className="sv3-tree-foot muted small">
            {Object.keys(catalog).length} commands · {groups.length} groups
          </div>
        </aside>

        {/* Right pane: selected-command form */}
        <main className="sv3-form">
          {!command && (
            <div className="sv3-form-empty">
              <div className="sv3-form-empty-inner">
                <div className="sv3-form-empty-h">Pick a scan from the sidebar</div>
                <p className="muted">
                  Or run a bundled preset from the button in the top-right.
                  Suggestions below are based on what the engagement has already learned.
                </p>
                {visibleSuggestions.length > 0 && (
                  <div className="sv3-suggests sv3-suggests-empty">
                    <div className="sv3-suggests-h">
                      <span>💡 Recce suggests</span>
                      <span className="muted small">{visibleSuggestions.length} hint(s)</span>
                    </div>
                    {Object.entries(groupedSuggestions).slice(0, 8).map(([bucket, items]) => {
                      const cmd = items[0].command;
                      const cs = cmd ? catalog[cmd] : null;
                      const title = cs ? cs.label : items[0].source.replace(/_/g, " ");
                      return (
                        <div key={bucket} className="sv3-suggest-card">
                          <div className="sv3-suggest-card-h">
                            <span className="sv3-suggest-title">{title}</span>
                            {cmd && <span className="mono small">{cmd}</span>}
                          </div>
                          {items.slice(0, 2).map((s) => (
                            <div key={s.key} className="sv3-suggest-row">
                              <div className="sv3-suggest-reason">
                                {s.severity ? <SevTag severity={s.severity} />
                                            : <span className={`sv3-conf-${s.confidence}`}>●</span>}
                                {" "}{s.reason}
                              </div>
                              <div className="sv3-suggest-actions">
                                {s.command && (
                                  <button className="sv3-btn sv3-btn-mini"
                                          onClick={() => applySuggestion(s)}
                                          disabled={isBusy}>Prefill</button>
                                )}
                                <button className="sv3-btn sv3-btn-mini sv3-btn-ghost"
                                        onClick={() => dismissSuggestion(s.key)}>×</button>
                              </div>
                            </div>
                          ))}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          )}

          {spec && command && (
            <>
              <header className="sv3-form-h">
                <div>
                  <h2 className="sv3-form-title">{spec.label}</h2>
                  <div className="sv3-form-sub">
                    <span className="mono small">recce {command}</span>
                  </div>
                </div>
                <div className="sv3-form-btns">
                  <button className="sv3-btn sv3-btn-ghost"
                          onClick={addToQueue}
                          disabled={isBusy}
                          title="Add to scan chain — queue multiple commands to run in sequence">
                    + Chain
                  </button>
                  <button className="sv3-btn sv3-btn-primary"
                          onClick={runScan}
                          disabled={isBusy || (spec.targets === "required" && !targets.trim())}>
                    {isBusy ? <><span className="sv3-spinner" /> Running…</> : <>▶ Launch</>}
                  </button>
                </div>
              </header>

              {/* Live target-context hint for the picked command. */}
              {cmdCtx && (
                cmdCtx.count > 0 ? (
                  <div className="sv3-ctx-hint">
                    <b>{cmdCtx.count}</b> discovered host{cmdCtx.count === 1 ? "" : "s"} expose{" "}
                    <span className="mono">{command}</span>:{" "}
                    <span className="mono">{cmdCtx.sample.join(", ")}</span>
                    {cmdCtx.count > cmdCtx.sample.length && " …"}
                    <button className="sv3-btn sv3-btn-mini sv3-btn-ghost"
                            style={{marginLeft:8}}
                            disabled={isBusy}
                            onClick={() => setTargets(cmdCtx.sample.join(", "))}>
                      use these
                    </button>
                  </div>
                ) : cmdCtx.hint ? (
                  <div className="sv3-ctx-hint warn">{cmdCtx.hint}</div>
                ) : null
              )}

              {/* Suggestions targeted at THIS command. */}
              {currentSuggestions.length > 0 && (
                <div className="sv3-suggests">
                  <div className="sv3-suggests-h">
                    <span>💡 Recce suggests for {command}</span>
                    <span className="muted small">{currentSuggestions.length} hint(s)</span>
                  </div>
                  {currentSuggestions.map((s) => (
                    <div key={s.key} className="sv3-suggest-row">
                      <div className="sv3-suggest-reason">
                        {s.severity ? <SevTag severity={s.severity} />
                                    : <span className={`sv3-conf-${s.confidence}`}>●</span>}
                        {" "}{s.reason}
                        {s.suggested_value && s.field && (
                          <div className="sv3-suggest-value">
                            <span className="muted small">{s.field}:</span>{" "}
                            <span className="mono">{s.suggested_value}</span>
                          </div>
                        )}
                      </div>
                      <div className="sv3-suggest-actions">
                        {s.field && (
                          <button className="sv3-btn sv3-btn-mini"
                                  onClick={() => applySuggestion(s)}
                                  disabled={isBusy}>Prefill</button>
                        )}
                        <button className="sv3-btn sv3-btn-mini sv3-btn-ghost"
                                onClick={() => dismissSuggestion(s.key)}>×</button>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              <section className="sv3-form-body">
                {spec.profile && (
                  <label className="sv3-field">
                    <span className="sv3-field-lbl">Profile</span>
                    <select className="sv3-input" value={profile}
                            onChange={(e) => setProfile(e.target.value)} disabled={isBusy}
                            title="Stealth: slower T2, congestion-adaptive from pass 1, top-1000 TCP.">
                      <option value="quick">Quick</option>
                      <option value="standard">Standard</option>
                      <option value="thorough">Thorough</option>
                      <option value="stealth">Stealth (slow, rate-limit-safe)</option>
                    </select>
                  </label>
                )}

                {spec.creds && (
                  <div className="sv3-field-row">
                    <label className="sv3-field">
                      <span className="sv3-field-lbl">Username</span>
                      <input className="sv3-input" value={cUser}
                             onChange={(e) => setCUser(e.target.value)}
                             placeholder="domain\user" disabled={isBusy} />
                    </label>
                    <label className="sv3-field">
                      <span className="sv3-field-lbl">Password</span>
                      <input className="sv3-input" type="password" value={cPass}
                             onChange={(e) => setCPass(e.target.value)} disabled={isBusy} />
                    </label>
                    <label className="sv3-field">
                      <span className="sv3-field-lbl">Domain</span>
                      <input className="sv3-input" value={cDomain}
                             onChange={(e) => setCDomain(e.target.value)}
                             placeholder="CORP.LOCAL" disabled={isBusy} />
                    </label>
                  </div>
                )}

                {spec.lhost && (
                  <label className="sv3-field">
                    <span className="sv3-field-lbl">LHOST</span>
                    <input className="sv3-input" value={cLhost}
                           onChange={(e) => setCLhost(e.target.value)}
                           placeholder="attacker.ip:port" disabled={isBusy} />
                  </label>
                )}

                {spec.flags && spec.flags.length > 0 && (
                  <div className="sv3-flags">
                    <div className="sv3-field-lbl">Flags</div>
                    <div className="sv3-flag-grid">
                      {spec.flags.filter(f => (f.kind || "bool") === "bool").map((f) => (
                        <label key={f.name} className={"sv3-flag" + (cFlags[f.name] ? " on" : "")}>
                          <input type="checkbox" checked={cFlags[f.name] || false}
                                 onChange={(e) => setCFlags({ ...cFlags, [f.name]: e.target.checked })}
                                 disabled={isBusy} />
                          <span>{f.label}</span>
                          {f.active && <span className="sv3-tag-hot">active</span>}
                        </label>
                      ))}
                    </div>
                    {spec.flags.some(f => (f.kind || "bool") !== "bool") && (
                      <div className="sv3-value-flags">
                        {spec.flags.filter(f => (f.kind || "bool") !== "bool").map((f) => {
                          if (f.kind === "wordlist") {
                            const opts = (wordlists[(f as any).wordlist_kind || ""] || []);
                            const cur = cFlagValues[f.name] || "";
                            const selVal = cur.startsWith("bundled:") ? cur : "";
                            return (
                              <label key={f.name} className="sv3-field">
                                <span className="sv3-field-lbl">
                                  {f.label}
                                  {f.active && <span className="sv3-tag-hot" style={{marginLeft:6}}>active</span>}
                                </span>
                                <div className="sv3-wordlist-row">
                                  <select className="sv3-input" style={{flex: "0 0 220px"}}
                                          value={selVal} disabled={isBusy || opts.length === 0}
                                          title={opts.length === 0 ? "loading wordlists…" : "pick a bundled wordlist"}
                                          onChange={(e) => setCFlagValues({ ...cFlagValues, [f.name]: e.target.value })}>
                                    <option value="">{opts.length === 0 ? "loading…" : "— bundled list —"}</option>
                                    {opts.map(o => (
                                      <option key={o.name} value={`bundled:${o.name}`} title={o.blurb}>
                                        {o.name} ({o.line_count})
                                      </option>
                                    ))}
                                  </select>
                                  <input className="sv3-input" type="text"
                                         value={cur}
                                         placeholder={f.placeholder || "bundled:<name> or /path/to/file"}
                                         disabled={isBusy}
                                         onChange={(e) => setCFlagValues({ ...cFlagValues, [f.name]: e.target.value })} />
                                </div>
                                {selVal && opts.find(o => `bundled:${o.name}` === selVal) && (
                                  <span className="muted small">
                                    {opts.find(o => `bundled:${o.name}` === selVal)?.blurb}
                                  </span>
                                )}
                              </label>
                            );
                          }
                          return (
                            <label key={f.name} className="sv3-field">
                              <span className="sv3-field-lbl">
                                {f.label}
                                {f.active && <span className="sv3-tag-hot" style={{marginLeft:6}}>active</span>}
                              </span>
                              <input className="sv3-input"
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
              </section>
            </>
          )}
        </main>
      </div>

      {/* -- Sticky bottom bar: queue + running-jobs summary ----------- */}
      {(queue.length > 0 || runningJobs.length > 0) && (
        <div className="sv3-bottom">
          {queue.length > 0 && (
            <div className="sv3-bottom-block">
              <span className="sv3-bottom-lbl">Queue ({queue.length}):</span>
              <span className="sv3-bottom-items">
                {queue.slice(0, 5).map((q, i) => (
                  <span key={i} className="sv3-chip">
                    {q.label}
                    <button className="sv3-chip-x"
                            onClick={() => setQueue((qs) => qs.filter((_, j) => j !== i))}
                            title="remove from queue">×</button>
                  </span>
                ))}
                {queue.length > 5 && <span className="muted small">+{queue.length - 5} more</span>}
              </span>
              <button className="sv3-btn sv3-btn-primary sv3-btn-sm"
                      onClick={runQueue} disabled={isBusy}>▶ Run chain</button>
              <button className="sv3-btn sv3-btn-ghost sv3-btn-sm"
                      onClick={() => setQueue([])}>Clear</button>
            </div>
          )}
          {runningJobs.length > 0 && (
            <div className="sv3-bottom-block">
              <span className="sv3-bottom-lbl">Running ({runningJobs.length}):</span>
              <span className="sv3-bottom-items">
                {runningJobs.slice(0, 3).map((j) => (
                  <span key={j.id} className="sv3-chip sv3-chip-live"
                        title={`${j.cmd} · ${j.tester} · ${elapsed(j.started)}`}
                        onClick={() => streamJob(j.id)}>
                    <span className="sv3-dot sv3-dot-live" /> {j.cmd.split(" ")[1] || j.cmd.slice(0, 20)}
                    <button className="sv3-chip-x"
                            onClick={(e) => {
                              e.stopPropagation();
                              if (!confirm(`Cancel this scan?\n\n${j.cmd}`)) return;
                              fetch(`/api/jobs/${j.id}/cancel`, { method: "POST" });
                            }}
                            title="cancel this scan">×</button>
                  </span>
                ))}
              </span>
              {!showLog && (
                <button className="sv3-btn sv3-btn-ghost sv3-btn-sm"
                        onClick={() => setShowLog(true)}>Show console</button>
              )}
            </div>
          )}
        </div>
      )}

      {/* -- Console overlay -------------------------------------------- */}
      {showLog && (
        <ScanConsole
          log={log}
          running={running}
          chainRunning={chainRunning}
          chainStopping={chainStopping}
          onStopChain={stopChain}
          logRef={logRef}
          onClose={() => setShowLog(false)}
        />
      )}
    </div>
  );
}
