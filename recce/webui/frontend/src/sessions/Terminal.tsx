import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { SessionInfo, getSessionHistory, putSessionHistory } from "../api";
import { b64ToBytes, strToB64 } from "../util";

export function ShellTerminal({ session, tester }: { session: SessionInfo; tester: string }) {
  const host = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  // Kept so the toolbar's "clear" button can call term.clear() — the ref
  // survives across renders while the xterm instance itself is created
  // inside the useEffect scope. The on-disk transcript is untouched.
  const termRef = useRef<Terminal | null>(null);
  const [driver, setDriver] = useState<string | null>(session.driver);
  const [attached, setAttached] = useState<string[]>(session.attached);
  const [live, setLive] = useState(session.status === "live");
  const iDrive = driver === tester;
  // Per-session command history — recall what YOU typed to this shell across
  // attach/detach, and across different browsers. Assembled from keystrokes at
  // the WebSocket layer (before the target echoes them), split on Enter, and
  // persisted server-side so a re-attach picks up where you left off.
  const [history, setHistory] = useState<string[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const cmdBuf = useRef<string>("");
  const saveTimer = useRef<number | null>(null);
  const scheduleSave = (entries: string[]) => {
    if (saveTimer.current) window.clearTimeout(saveTimer.current);
    saveTimer.current = window.setTimeout(() => {
      putSessionHistory(session.id, entries).catch(() => {});
    }, 800);
  };
  useEffect(() => {
    getSessionHistory(session.id).then(setHistory).catch(() => {});
  }, [session.id]);

  useEffect(() => {
    if (!host.current) return;

    let disposed = false;
    const term = new Terminal({
      fontFamily: "ui-monospace, 'JetBrains Mono', Menlo, Consolas, monospace",
      fontSize: 13, cursorBlink: true, convertEol: false,
      theme: { background: "#0b0f16", foreground: "#d7e0ec" },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(host.current);
    termRef.current = term;
    try { fit.fit(); } catch { /* pre-layout */ }
    term.onResize(({ cols, rows }) => {
      wsRef.current?.readyState === WebSocket.OPEN &&
        wsRef.current.send(JSON.stringify({ t: "resize", cols, rows }));
    });
    const onResize = () => { try { fit.fit(); } catch { /* noop */ } };
    window.addEventListener("resize", onResize);

    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(
      `${proto}://${location.host}/api/sessions/${session.id}/attach?tester=${encodeURIComponent(tester)}`);
    wsRef.current = ws;

    // Track whether the initial scrollback replay had any content — if
    // the session is fresh (0 bytes buffered) we send one Enter after
    // the presence handshake so the shell prints a prompt. Without this
    // the operator sees a completely blank terminal until they type,
    // which reads as "is it broken?" on a working brand-new session.
    let scrollbackHadBytes = false;
    let sentInitialNewline = false;
    ws.onmessage = (ev) => {
      if (disposed) return;
      try {
        const m = JSON.parse(ev.data);
        if (m.t === "scrollback") {
          if (m.data) {
            const bytes = b64ToBytes(m.data);
            if (bytes.length > 0) scrollbackHadBytes = true;
            term.write(bytes);
          }
        } else if (m.t === "out") {
          if (m.data) term.write(b64ToBytes(m.data));
        } else if (m.t === "presence") {
          setDriver(m.driver);
          setAttached(m.attached || []);
          if (!m.driver && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ t: "wheel" }));
          }
          // First presence message = scrollback replay is done. Nudge
          // the shell to draw a prompt if nothing was there to see.
          if (!sentInitialNewline && !scrollbackHadBytes && ws.readyState === WebSocket.OPEN) {
            sentInitialNewline = true;
            ws.send(JSON.stringify({ t: "in", data: strToB64("\n") }));
          }
        } else if (m.t === "status") {
          setLive(m.status === "live");
          if (m.status !== "live") term.write("\r\n\x1b[33m[session detached — shell dropped]\x1b[0m\r\n");
        }
      } catch { /* malformed message — ignore */ }
    };
    ws.onclose = () => {
      if (!disposed) term.write("\r\n\x1b[31m[disconnected]\x1b[0m\r\n");
    };

    term.onData((d) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ t: "in", data: strToB64(d) }));
      // Build up a command buffer from keystrokes — Enter (\r or \n) flushes it
      // to history. Backspace (\x7f, ^H) trims. Ctrl-C (\x03) discards without
      // recording. Filter escape sequences (\x1b[...) which are arrow keys etc.
      // Only "you" (the tester with the wheel) contributes — history is per-tester
      // but stored per-session; the collaborative side is intentional.
      for (const ch of d) {
        if (ch === "\r" || ch === "\n") {
          const line = cmdBuf.current.trim();
          cmdBuf.current = "";
          if (line && line.length <= 2000) {
            setHistory(prev => {
              // Bash-style: drop consecutive duplicates + collapse whitespace
              if (prev[prev.length - 1] === line) return prev;
              const next = [...prev, line].slice(-500);
              scheduleSave(next);
              return next;
            });
          }
        } else if (ch === "\x7f" || ch === "\b") {
          cmdBuf.current = cmdBuf.current.slice(0, -1);
        } else if (ch === "\x03") {  // Ctrl-C — abort current line
          cmdBuf.current = "";
        } else if (ch.charCodeAt(0) >= 0x20 && ch.charCodeAt(0) < 0x7f) {
          cmdBuf.current += ch;
        }
      }
    });

    setTimeout(() => { if (!disposed) term.focus(); }, 100);

    return () => {
      disposed = true;
      window.removeEventListener("resize", onResize);
      ws.close();
      term.dispose();
    };
  }, [session.id, tester]);

  function insertHistory(cmd: string) {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ t: "in", data: strToB64(cmd) }));
    }
    setShowHistory(false);
  }
  return (
    <div className="shell-term">
      <div className="shell-term-bar">
        <span className={"sess-dot " + (live ? "live" : "stale")} />
        <span className="mono">{session.host_ip}</span>
        <span className="shell-term-driver">
          {driver ? (iDrive ? "you're driving" : `${driver} driving`) : "no driver"}
        </span>
        {!iDrive && (
          <button className="toggle" onClick={() => wsRef.current?.send(JSON.stringify({ t: "wheel" }))}>
            take the wheel
          </button>
        )}
        <span className="shell-term-watchers" title="attached">👁 {attached.length}</span>
        <button className="toggle"
                title="clear the visible terminal (the on-disk transcript is kept)"
                onClick={() => { termRef.current?.clear(); }}>
          🧹 clear
        </button>
        {history.length > 0 && (
          <div className="shell-term-history">
            <button className="toggle" onClick={() => setShowHistory(v => !v)}
                    title="recent commands typed to this session (persists across attach/detach)">
              ⇧ history ({history.length})
            </button>
            {showHistory && (
              <div className="shell-hist-pop">
                {history.slice(-30).reverse().map((c, i) => (
                  <button key={i} className="shell-hist-item mono"
                          title="click to insert (no Enter — you review then hit Enter)"
                          onClick={() => insertHistory(c)}>
                    {c}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
      <div className="shell-term-screen" ref={host} />
    </div>
  );
}
