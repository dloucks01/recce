import { useEffect, useState } from "react";
import { SessionInfo, ListenerInfo, getSessions, getListeners, startListener, stopListener,
  lootCred, getTranscript, upgradeSession } from "./api";
import { ShellTerminal } from "./Terminal";
import { PayloadCatalog } from "./Payloads";

// The Sessions tab: open listeners, watch caught shells land (grouped by host), and drive
// them collaboratively. The whole team sees the same list on the one shared server.
export function Sessions({ tester, focus }: { tester: string; focus?: string | null }) {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [listeners, setListeners] = useState<ListenerInfo[]>([]);
  const [open, setOpen] = useState<string | null>(null);
  const [port, setPort] = useState("4444");
  const [tls, setTls] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [payloadsFor, setPayloadsFor] = useState<string | null>(null);

  // open a specific session when jumped here from the host drawer
  useEffect(() => { if (focus) setOpen(focus); }, [focus]);

  async function refresh() {
    try {
      const [s, l] = await Promise.all([getSessions(), getListeners()]);
      setSessions(s);
      setListeners(l);
    } catch { /* transient */ }
  }
  useEffect(() => {
    refresh();
    const id = window.setInterval(refresh, 2000);
    return () => window.clearInterval(id);
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

  return (
    <div className="sessions-view">
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
          <span className="muted">{sessions.filter((s) => s.status === "live").length} live · {sessions.length} total</span>
        </div>
        {sessions.length === 0 && (
          <div className="empty">
            No shells yet. Open a listener above, run its payload on a target, and the caught
            shell lands here — live for the whole team, tied to its host.
          </div>
        )}
        <div className="session-list">
          {sessions.map((s) => (
            <button key={s.id} className={"session-item" + (s.id === open ? " sel" : "")}
                    onClick={() => setOpen(s.id === open ? null : s.id)}>
              <span className={"sess-dot " + (s.status === "live" ? "live" : "stale")} />
              <span className="mono host">{s.host_ip}</span>
              <span className="badge">{s.status}</span>
              {s.pty && <span className="badge pty" title="robust PTY (auto-reconnect stager)">PTY</span>}
              {s.driver && <span className="muted">▸ {s.driver}</span>}
              {s.attached.length > 0 && <span className="muted">👁 {s.attached.length}</span>}
            </button>
          ))}
        </div>
      </section>

      {openSession && (
        <section className="panel">
          <div className="panel-h">
            <h3>Terminal — <span className="mono">{openSession.host_ip}</span></h3>
            <button className="linkish" onClick={() => setOpen(null)}>close</button>
          </div>
          <ShellTerminal key={openSession.id} session={openSession} tester={tester} />
          <SessionTools session={openSession} />
        </section>
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
      setMsg(`✓ credential looted → Loot + spray plan`);
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
  async function upgrade() {
    try {
      const r = await upgradeSession(session.id);
      setMsg(`⤴ upgrading to a robust PTY shell — reconnecting via ${r.callback}…`);
    } catch (e) {
      setMsg(String(e instanceof Error ? e.message : e));
    }
  }
  return (
    <div className="session-tools">
      {!session.pty && session.status === "live" && (
        <div className="upgrade-row">
          <button className="run upgrade-btn" onClick={upgrade}>⤴ Upgrade to robust PTY</button>
          <span className="muted small">auto-pivots this raw shell into a self-healing, full-PTY session</span>
        </div>
      )}
      <div className="loot-cred">
        <span className="muted small">Loot a credential from this shell:</span>
        <input className="scan-in" placeholder="username" value={u} onChange={(e) => setU(e.target.value)} />
        <input className="scan-in" placeholder="secret" value={p} onChange={(e) => setP(e.target.value)} />
        <select value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="password">password</option>
          <option value="nthash">NT hash</option>
          <option value="hash">hash</option>
        </select>
        <button className="toggle" onClick={loot} disabled={!u && !p}>＋ Loot</button>
        <button className="toggle" onClick={saveTranscript}>⭳ Transcript</button>
      </div>
      {msg && <div className="ranmsg">{msg}</div>}
    </div>
  );
}
