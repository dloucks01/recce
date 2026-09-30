// Scan — a task-first launcher. Quick-launch the core flows, act on suggested
// next scans, or search the full command catalog (with "N hosts qualify"), then
// launch via a form drawer and watch jobs stream in a live console.
import { useEffect, useMemo, useRef, useState } from "react";
import {
  CmdCatalog, ScanCtx, ScanSuggestion, Wordlist, NmapLog,
  getCommands, getScanContext, getScanSuggestions, getWordlists,
  postNmapScan, resumeNmapScan, getNmapLogs,
} from "../api";
import { useJobs } from "../useJobs";
import { SectionProps } from "../nav";
import { Panel, Empty } from "../kit";
import { ScanLaunchDrawer } from "../ScanLaunchDrawer";
import { toast } from "../toast";

const QUICK = [
  ["enum", "Discover & enumerate", "hosts, ports, services"],
  ["vulns", "Vuln scan", "CVE/KEV on open ports"],
  ["sweep", "Deep sweep", "every applicable module"],
  ["credsweep", "Cred sweep", "authenticated modules"],
] as const;

export function Scan({ data, nav }: SectionProps) {
  const [cat, setCat] = useState<CmdCatalog>({});
  const [ctx, setCtx] = useState<ScanCtx>({});
  const [sug, setSug] = useState<ScanSuggestion[]>([]);
  const [wls, setWls] = useState<Wordlist[]>([]);
  const [q, setQ] = useState("");
  const [launch, setLaunch] = useState<{ cmd: string; targets: string } | null>(null);
  const [consoleJob, setConsoleJob] = useState<string | null>(null);
  const [dismissed, setDismissed] = useState<Set<string>>(() => new Set(JSON.parse(localStorage.getItem("recce.sug.x") || "[]")));
  const [nmapArgs, setNmapArgs] = useState("");
  const [nmapLogs, setNmapLogs] = useState<NmapLog[]>([]);
  const [showAll, setShowAll] = useState(false);      // full catalog collapsed by default
  const jobs = useJobs();

  const loadLogs = () => getNmapLogs().then(setNmapLogs).catch(() => {});
  useEffect(() => {
    getCommands().then(setCat).catch(() => {});
    getScanContext().then(setCtx).catch(() => {});
    getScanSuggestions().then(setSug).catch(() => {});
    getWordlists().then(setWls).catch(() => {});
    loadLogs();
  }, []);

  // "Scan this host" from the host drawer lands here with a seed — open the enum
  // launch drawer prefilled to that host so the operator just hits Run.
  const seededHost = nav.scanSeed?.host;
  useEffect(() => {
    if (seededHost) setLaunch({ cmd: "enum", targets: seededHost });
  }, [seededHost]);

  // Header 'scan running' pill lands the operator here with a request to
  // open a specific job's terminal. nonce keeps the effect firing even when
  // the same jobId is requested twice (React only diffs on value identity).
  const consoleReq = nav.scanConsoleSeed?.jobId;
  const consoleReqNonce = nav.scanConsoleSeed?.nonce;
  useEffect(() => {
    if (consoleReq) setConsoleJob(consoleReq);
  }, [consoleReq, consoleReqNonce]);

  async function runNmap() {
    const a = nmapArgs.trim();
    if (!a) return;
    try {
      const r = await postNmapScan(a);
      setConsoleJob(r.id);              // stream output in the console
      setTimeout(loadLogs, 800);        // the .gnmap appears once nmap starts
      toast.show("nmap scan started — output streaming; results fold in when done");
    } catch (e) { toast.show(String(e)); }
  }
  async function resumeNmap(gnmap: string) {
    try {
      const r = await resumeNmapScan(gnmap);
      setConsoleJob(r.id);
      toast.show(`resuming ${gnmap}`);
    } catch (e) { toast.show(String(e)); }
  }

  const subnets = useMemo(() => [...new Set(data.hosts.map((h) => h.ip.split(".").slice(0, 3).join(".") + ".0/24"))], [data.hosts]);
  const defaultTargets = (cmd: string) =>
    cmd === "enum" ? subnets.join(" ")
      : (ctx[cmd]?.sample?.length ? ctx[cmd].sample.join(" ") : "");
  const openLaunch = (cmd: string) => setLaunch({ cmd, targets: defaultTargets(cmd) });

  const groups = useMemo(() => {
    const n = q.toLowerCase();
    const g: Record<string, string[]> = {};
    for (const [cmd, spec] of Object.entries(cat)) {
      if (n && !(cmd.includes(n) || (spec.label || "").toLowerCase().includes(n) || (spec.group || "").toLowerCase().includes(n))) continue;
      (g[spec.group || "other"] ||= []).push(cmd);
    }
    for (const k of Object.keys(g)) g[k].sort((a, b) => (ctx[b]?.count || 0) - (ctx[a]?.count || 0) || a.localeCompare(b));
    return g;
  }, [cat, ctx, q]);

  const activeSug = sug.filter((s) => !dismissed.has(s.key));
  const dismissSug = (k: string) => setDismissed((d) => { const n = new Set(d); n.add(k); localStorage.setItem("recce.sug.x", JSON.stringify([...n])); return n; });
  const running = jobs.filter((j) => j.status === "running");
  // Refresh the custom-nmap run list whenever a scan finishes (running count
  // drops): a just-completed scan then flips from "resume" to "complete" instead
  // of staying stale until a page reload.
  const runningN = running.length;
  useEffect(() => { loadLogs(); }, [runningN]);   // eslint-disable-line react-hooks/exhaustive-deps
  const cancelJob = (id: string) =>
    fetch(`/api/jobs/${id}/cancel`, { method: "POST" })
      .then((r) => toast.show(r.ok ? "scan cancelled" : "cancel failed"))
      .catch(() => toast.show("cancel failed"));

  // Next-step nudge: reflect where the engagement is in the enum -> vulns -> act flow,
  // so the tab points the way instead of being a flat wall of options.
  const nHosts = data.hosts.length;
  const anyVuln = data.hosts.some((h) => h.vuln_scanned);
  const anyFind = data.hosts.some((h) => Object.values(h.findings || {}).some(Boolean));
  const nudge = nHosts === 0
    ? { text: "Start here — run enum on your scope to discover hosts, ports & services.", cmd: "enum" }
    : !anyVuln
      ? { text: `${nHosts} host(s) enumerated. Next: run vulns to surface CVEs/KEV on the open ports.`, cmd: "vulns" }
      : anyFind
        ? { text: "Vuln scan done — triage in Findings or act in Exploit; run credsweep / web for deeper loot.", cmd: "" }
        : { text: "Enumerated + vuln-scanned. Go deeper: credsweep (authenticated) or sweep (every module).", cmd: "credsweep" };

  const totalCmds = Object.keys(cat).length;

  return (
    <>
      {/* Next-step nudge */}
      <div className="scan-nudge">
        <span className="nudge-dot" />
        <span style={{ flex: 1 }}>{nudge.text}</span>
        {nudge.cmd && cat[nudge.cmd] && (
          <button className="btn sm primary" onClick={() => openLaunch(nudge.cmd)}>▶ {nudge.cmd}</button>
        )}
      </div>

      {/* Quick launch */}
      <Panel title="Quick launch" sub="the core flows — review targets, then run">
        <div className="row wrap" style={{ gap: 8 }}>
          {QUICK.filter(([c]) => cat[c]).map(([c, label, blurb]) => (
            <button key={c} className="quick-card" onClick={() => openLaunch(c)}>
              <span className="qc-cmd mono">{c}</span>
              <span className="qc-label">{label}</span>
              <span className="qc-blurb muted">{blurb}</span>
            </button>
          ))}
        </div>
      </Panel>

      {/* Custom nmap — the tester's own scan, folded into the engagement */}
      <Panel title="Custom nmap" sub="run your own nmap — results fold into the engagement; interrupted scans resume">
        <div className="row" style={{ gap: 8 }}>
          <span className="mono muted">nmap</span>
          <input className="fin" style={{ flex: 1 }}
                 placeholder="-sV -p22,80,443 -T4 10.0.0.0/24   (flags + targets; recce adds output)"
                 value={nmapArgs}
                 onChange={(e) => setNmapArgs(e.target.value)}
                 onKeyDown={(e) => { if (e.key === "Enter") runNmap(); }} />
          <button className="btn sm primary" disabled={!nmapArgs.trim()} onClick={runNmap}>Run</button>
        </div>
        {nmapLogs.length > 0 && (
          <div style={{ marginTop: 10 }}>
            <div className="muted" style={{ fontSize: 12, marginBottom: 4 }}>Previous nmap runs</div>
            {nmapLogs.map((l) => (
              <div key={l.gnmap} className="row" style={{ gap: 8, alignItems: "center", padding: "2px 0" }}>
                <span className="mono" style={{ fontSize: 12 }}>{l.gnmap}</span>
                {l.complete
                  ? <span className="chip" title="finished — nothing to resume">complete</span>
                  : <button className="linkish" onClick={() => resumeNmap(l.gnmap)} title="continue this interrupted scan">↻ resume</button>}
              </div>
            ))}
          </div>
        )}
      </Panel>

      {/* Suggested next scans */}
      {activeSug.length > 0 && (
        <Panel title="Suggested next scans" sub="cross-service intel — what to run given what recce knows">
          {activeSug.slice(0, 8).map((s) => (
            <div key={s.key} className="row" style={{ gap: 8, padding: "7px 0", borderBottom: "1px solid color-mix(in srgb,var(--line) 55%,transparent)", alignItems: "baseline" }}>
              <span className={"chip " + (s.confidence === "high" ? "on" : "")}>{s.confidence}</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div>{s.reason}</div>
                <div className="mono muted" style={{ fontSize: 11 }}>{s.external_cmd || (s.command ? `recce ${s.command}${s.suggested_value ? ` (${s.field}=${s.suggested_value})` : ""}` : s.source)}</div>
              </div>
              {s.command && cat[s.command]
                ? <button className="btn sm" onClick={() => setLaunch({ cmd: s.command, targets: s.field === "targets" ? s.suggested_value : defaultTargets(s.command) })}>Run</button>
                : s.external_cmd ? <button className="btn sm" onClick={() => navigator.clipboard?.writeText(s.external_cmd!)}>Copy</button> : null}
              <button className="linkish" onClick={() => dismissSug(s.key)} title="dismiss">✕</button>
            </div>
          ))}
        </Panel>
      )}

      {/* Running jobs + console. Whole row is click-to-open-terminal so the
          operator doesn't have to aim at the small button; the cancel ✕
          stopPropagation'd so an accidental click on it doesn't ALSO open
          the terminal. */}
      {running.length > 0 && (
        <Panel title="Scanning now" sub={`${running.length} running · click a row for its terminal`}>
          {running.map((j) => (
            <div key={j.id} className="row click"
                 onClick={() => setConsoleJob(j.id)}
                 title="open terminal"
                 style={{ gap: 8, padding: "5px 0",
                          borderBottom: "1px solid color-mix(in srgb,var(--line) 55%,transparent)",
                          cursor: "pointer" }}>
              <span className="mono" style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{j.cmd}</span>
              {j.progress && j.progress.total != null && (
                <span className="meter-t" style={{ width: 80 }}><span className="meter-f" style={{ width: `${Math.min(100, (j.progress.done / Math.max(1, j.progress.total)) * 100)}%` }} /></span>
              )}
              <span className="muted mono" style={{ fontSize: 11 }}>{j.progress ? `${j.progress.done}${j.progress.total != null ? "/" + j.progress.total : ""}` : ""}</span>
              <button className="btn sm" onClick={(e) => { e.stopPropagation(); setConsoleJob(j.id); }}>terminal</button>
              <button className="btn sm danger" title="cancel scan"
                      onClick={(e) => { e.stopPropagation(); cancelJob(j.id); }}>✕</button>
            </div>
          ))}
        </Panel>
      )}

      {/* Recent scans — every past job with click-to-reopen-terminal, so the
          operator can pull up the full command + output of anything they
          launched this session without hunting through the jobs pill. */}
      {jobs.filter((j) => j.status !== "running").length > 0 && (
        <Panel title="Recent scans"
               sub="click any row to open its terminal (command + full output)">
          {jobs.filter((j) => j.status !== "running")
              .slice(0, 20)
              .map((j) => {
                const ok = j.status === "done";
                const label = j.status === "done" ? "done"
                            : j.status === "failed" ? "failed"
                            : j.status;
                return (
                  <div key={j.id} className="row click"
                       onClick={() => setConsoleJob(j.id)}
                       title="open terminal"
                       style={{ gap: 8, padding: "5px 0",
                                borderBottom: "1px solid color-mix(in srgb,var(--line) 55%,transparent)",
                                alignItems: "baseline", cursor: "pointer" }}>
                    <span className={"chip" + (ok ? " on" : "")}
                          style={{ fontSize: 10, minWidth: 44, textAlign: "center" }}>
                      {label}
                    </span>
                    <span className="mono" style={{ flex: 1, minWidth: 0,
                                                    overflow: "hidden",
                                                    textOverflow: "ellipsis",
                                                    whiteSpace: "nowrap" }}>
                      {j.cmd}
                    </span>
                    <span className="faint mono" style={{ fontSize: 11 }}>
                      {j.id.slice(0, 8)}
                    </span>
                  </div>
                );
              })}
        </Panel>
      )}

      {/* Full catalog — collapsed by default so the task-first flow above isn't
          buried under ~90 per-service module chips. Searching auto-expands. */}
      <Panel title="All commands"
             sub={!q && !showAll ? `${totalCmds} modules — most run inside enum/vulns` : undefined}
             actions={<div className="row" style={{ gap: 6 }}>
               <input className="namebox" style={{ width: 200 }} placeholder="search commands…"
                      value={q} onChange={(e) => setQ(e.target.value)} />
               {!q && <button className="btn sm" onClick={() => setShowAll((v) => !v)}>{showAll ? "Hide" : `Show all ${totalCmds}`}</button>}
             </div>}>
        {!q && !showAll ? (
          <div className="muted" style={{ fontSize: 12, padding: "2px 2px" }}>
            The core flows are in Quick launch above. Search for a specific module (e.g. <span className="mono">smb</span>, <span className="mono">certipy</span>, <span className="mono">redis</span>) or “Show all”.
          </div>
        ) : Object.keys(groups).length === 0 ? <Empty>No commands match.</Empty> :
          Object.entries(groups).sort().map(([grp, cmds]) => (
            <div key={grp} style={{ marginBottom: 10 }}>
              <div className="faint" style={{ fontSize: 10, textTransform: "uppercase", letterSpacing: ".06em", fontWeight: 700, margin: "4px 0" }}>{grp}</div>
              <div className="row wrap" style={{ gap: 6 }}>
                {cmds.map((c) => {
                  const cand = ctx[c]?.count || 0;
                  const det = ctx[c]?.detected;
                  const n = det != null ? det : cand;    // show DETECTED when known, else the predicate count
                  const tip = det != null && det !== cand
                    ? `${det} host(s) with ${c} detected · ${cand} candidate(s) to scan`
                    : `${n} host(s)`;
                  return (
                    <button key={c} className="cmd-chip" onClick={() => openLaunch(c)}
                            title={cat[c].tool_cmd ? `${cat[c].label}\n\ntool: ${cat[c].tool_cmd}` : cat[c].label}>
                      <span className="mono">{c}</span>
                      {n > 0 && <span className="cmd-n" title={tip}>{n}</span>}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
      </Panel>

      {launch && cat[launch.cmd] && (
        <ScanLaunchDrawer cmd={launch.cmd} spec={cat[launch.cmd]} defaultTargets={launch.targets}
          qualifyCount={ctx[launch.cmd]?.count} wordlists={wls}
          onClose={() => setLaunch(null)}
          onLaunched={(id) => { setLaunch(null); setConsoleJob(id); }} />
      )}
      {consoleJob && <JobConsole id={consoleJob} onClose={() => setConsoleJob(null)} />}
    </>
  );
}

// Terminal-style view of one scan job: shows the exact command that was
// launched at the top (as a `$ ...` prompt), the full streamed output below
// (replayed from the beginning for finished jobs — /api/jobs/{id}/events
// serves buffered lines too), and copy / download actions in the footer so
// the operator can lift the whole session into a report or ticket.
function JobConsole({ id, onClose }: { id: string; onClose: () => void }) {
  const [lines, setLines] = useState<string[]>([]);
  const [cmd, setCmd] = useState<string>("");
  const [returncode, setReturncode] = useState<number | null>(null);
  const [status, setStatus] = useState<"running" | "done" | "failed" | "cancelled" | "lost">("running");
  const [copied, setCopied] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const ref = useRef<HTMLPreElement>(null);

  // One-shot metadata fetch so the header + footer chips render immediately —
  // the SSE endpoint gives us lines and terminal state, but not cmd + rc.
  useEffect(() => {
    setLines([]); setStatus("running"); setCmd(""); setReturncode(null); setCopied(false);
    let cancel = false;
    fetch(`/api/jobs/${id}`).then((r) => r.ok ? r.json() : null)
      .then((j) => {
        if (cancel || !j) return;
        setCmd(j.cmd || "");
        if (j.status && j.status !== "running") setStatus(j.status);
        if (j.returncode != null) setReturncode(j.returncode);
      })
      .catch(() => {});
    let finished = false;
    const es = new EventSource(`/api/jobs/${id}/events`);
    es.onmessage = (m) => {
      try {
        const d = JSON.parse(m.data);
        if (d.line !== undefined) setLines((l) => [...l, d.line]);
        if (d.done) {
          finished = true;
          setStatus(d.status || "done");
          es.close();
          // Re-fetch to pick up returncode once the job settled.
          fetch(`/api/jobs/${id}`).then((r) => r.ok ? r.json() : null)
            .then((j) => { if (j && j.returncode != null) setReturncode(j.returncode); })
            .catch(() => {});
        }
      } catch { /* */ }
    };
    // A stream error before the job signalled done = the connection dropped;
    // surface it instead of leaving the header stuck on "running…" forever.
    es.onerror = () => { es.close(); if (!finished) setStatus("lost"); };
    return () => { cancel = true; es.close(); };
  }, [id]);
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [lines]);

  const statusChip: Record<typeof status, { text: string; className: string }> = {
    running: { text: "● running", className: "chip" },
    done: { text: "● done", className: "chip on" },
    failed: { text: "● failed", className: "chip" },
    cancelled: { text: "● cancelled", className: "chip" },
    lost: { text: "● stream lost", className: "chip" },
  };

  const copyAll = () => {
    const body = (cmd ? `$ ${cmd}\n` : "") + lines.join("\n");
    navigator.clipboard?.writeText(body).then(() => {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1200);
    }).catch(() => {});
  };

  const downloadAll = () => {
    const body = (cmd ? `$ ${cmd}\n` : "") + lines.join("\n") + "\n";
    const blob = new Blob([body], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `scan-${id.slice(0, 8)}.log`;
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  };

  const chip = statusChip[status];
  return (
    <div className={"console-drawer scan-console-drawer" + (expanded ? " expanded" : "")}>
      {/* Header — status + short id + expand/close. Copy/download live in
          the footer so the header stays scannable at a glance. Drag the
          top-left corner of the drawer to resize (native CSS `resize`);
          the expand button toggles a viewport-filling mode for reading
          long scan output. */}
      <div className="row" style={{ padding: "6px 12px", borderBottom: "1px solid var(--line)",
                                    alignItems: "center", gap: 8 }}>
        <span className={chip.className} style={{ fontSize: 11 }}>{chip.text}</span>
        <span className="faint mono" style={{ fontSize: 11 }}>job {id.slice(0, 8)}</span>
        {returncode != null && returncode !== 0 && (
          <span className="faint mono" style={{ fontSize: 11 }}>exit {returncode}</span>
        )}
        <span style={{ flex: 1 }} />
        <button className="icon-btn" onClick={() => setExpanded((v) => !v)}
                title={expanded ? "restore (or drag corner to resize)" : "expand to fullscreen"}>
          {expanded ? "⤡" : "⤢"}
        </button>
        <button className="icon-btn" onClick={onClose} title="close">✕</button>
      </div>
      {/* Prompt line — the exact command recce ran, so the operator sees
          '$ recce enum 10.0.0.0/24' the same way they'd see it in a shell. */}
      {cmd && (
        <div className="mono" style={{
          padding: "6px 12px", borderBottom: "1px solid var(--line)",
          background: "var(--surface2)", fontSize: 12,
          overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
        }} title={cmd}>
          <span className="faint">$ </span>{cmd}
        </div>
      )}
      <pre ref={ref} className="console-out">{lines.join("\n") || (status === "running" ? "waiting for output…" : "(no output)")}</pre>
      {/* Footer — line count + copy/download. Deliberately small so the
          terminal above keeps its full-height feel. */}
      <div className="row" style={{ padding: "4px 12px",
                                    borderTop: "1px solid var(--line)",
                                    alignItems: "center", gap: 8, fontSize: 11 }}>
        <span className="faint">{lines.length} line{lines.length === 1 ? "" : "s"}</span>
        <span style={{ flex: 1 }} />
        <button className="linkish" onClick={copyAll} disabled={lines.length === 0}>
          {copied ? "✓ copied" : "copy"}
        </button>
        <button className="linkish" onClick={downloadAll} disabled={lines.length === 0}>
          download
        </button>
      </div>
    </div>
  );
}
