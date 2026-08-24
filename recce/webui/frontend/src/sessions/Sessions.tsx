import { useEffect, useState } from "react";
import { SessionInfo, ListenerInfo, getSessions, getListeners, startListener, stopListener,
  lootCred, getTranscript, upgradeSession, runEnum, downloadFromShell, uploadToShell,
  persistSession, getPersistence, removeAllPersistence, Persistence, patchSession,
  spawnSession,
  PortFwd, startPortFwd, stopPortFwd, listPortFwds,
  TunnelStatus, startTunnel, stopTunnel, tunnelStatus } from "../api";
import { ShellTerminal } from "./Terminal";
import { PayloadCatalog, StabilizeGuide, PostExploitRef, PivotGuide, ToolCatalog } from "./Payloads";
import { bytesToB64 } from "../util";

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
export function Sessions({ tester, focus, onScanHost, onViewHost }: {
  tester: string; focus?: string | null;
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
  const toggleGroup = (ip: string) => setCollapsed(s => {
    const n = new Set(s);
    n.has(ip) ? n.delete(ip) : n.add(ip);
    return n;
  });

  const hostGroups: [string, SessionInfo[]][] = (() => {
    const m = new Map<string, SessionInfo[]>();
    sessions.forEach(s => {
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

  return (
    <div className="sessions-view">
      {persist.length > 0 && (
        <div className="persist-banner">
          <span>⚠ <b>{persist.length}</b> active persistence artifact(s) installed across{" "}
            {new Set(persist.map((p) => p.host_ip)).size} host(s) — <b>remove before you leave the engagement</b></span>
          <button className="run danger-btn" onClick={sweepPersistence}>Remove all</button>
        </div>
      )}
      <section className="panel">
        <div className="panel-h">
          <h3>Listeners</h3>
          <span className="muted">catch a reverse shell on the shared server</span>
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
        </div>
        {sessions.length === 0 && (
          <div className="empty">
            No shells yet. Open a listener above, run its payload on a target, and the caught
            shell lands here — live for the whole team, tied to its host.
          </div>
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
                  {onViewHost && (
                    <button className="linkish sess-group-action" onClick={(e) => { e.stopPropagation(); onViewHost(ip); }}
                            title="open host detail drawer">detail</button>
                  )}
                  {onScanHost && (
                    <button className="linkish sess-group-action" onClick={(e) => { e.stopPropagation(); onScanHost(ip); }}
                            title="jump to Scan tab with this host pre-filled">scan</button>
                  )}
                </div>
                {!isCollapsed && (
                  <div className="sess-group-items">
                    {group.map((s, idx) => (
                      <button key={s.id} className={"session-item" + (s.id === open ? " sel" : "")}
                              onClick={() => setOpen(s.id === open ? null : s.id)}>
                        <span className={"sess-dot " + (s.status === "live" ? "live" : "stale")} />
                        <span className="mono sess-id" title={s.id}>{s.id.slice(0, 8)}</span>
                        <span className="badge">{s.status}</span>
                        {s.pty && <span className="badge pty" title="robust PTY (auto-reconnect stager)">PTY</span>}
                        {s.label && <span className="sess-label" title={s.label}>{s.label}</span>}
                        {s.driver && <span className="muted">▸ {s.driver}</span>}
                        {s.attached.length > 0 && <span className="muted">👁 {s.attached.length}</span>}
                        <span className="muted sess-meta">{relTime(s.created)}{s.bytes > 0 ? ` · ${fmtBytes(s.bytes)}` : ""}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>

      {openSession && (
        <section className="panel">
          <div className="panel-h">
            <h3>Terminal — <span className="mono">{openSession.host_ip}</span>
              <span className="muted" style={{fontSize: "0.8em", marginLeft: 8}}>{openSession.id.slice(0, 8)}</span>
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
          <SessionTools session={openSession} />
        </section>
      )}
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
