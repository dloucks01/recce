import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { SessionInfo } from "./api";

const b64ToBytes = (b64: string) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const strToB64 = (s: string) => btoa(String.fromCharCode(...new TextEncoder().encode(s)));

// A live, collaborative terminal over the session WebSocket. Everyone attached sees the
// same output; only the driver's keystrokes reach the target. "Take the wheel" hands off.
export function ShellTerminal({ session, tester }: { session: SessionInfo; tester: string }) {
  const host = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const [driver, setDriver] = useState<string | null>(session.driver);
  const [attached, setAttached] = useState<string[]>(session.attached);
  const [live, setLive] = useState(session.status === "live");
  const iDrive = driver === tester;

  useEffect(() => {
    const term = new Terminal({
      fontFamily: "ui-monospace, 'JetBrains Mono', Menlo, Consolas, monospace",
      fontSize: 13, cursorBlink: true, convertEol: false,
      theme: { background: "#0b0f16", foreground: "#d7e0ec" },
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(host.current!);
    try { fit.fit(); } catch { /* pre-layout */ }
    // propagate terminal size to the target PTY so full-screen apps (vim/nano/less) work
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

    ws.onmessage = (ev) => {
      const m = JSON.parse(ev.data);
      if (m.t === "scrollback" || m.t === "out") {
        if (m.data) term.write(b64ToBytes(m.data));
      } else if (m.t === "presence") {
        setDriver(m.driver);
        setAttached(m.attached || []);
        if (!m.driver && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ t: "wheel" }));
        }
      } else if (m.t === "status") {
        setLive(m.status === "live");
        if (m.status !== "live") term.write("\r\n\x1b[33m[session detached — shell dropped]\x1b[0m\r\n");
      }
    };
    ws.onclose = () => term.write("\r\n\x1b[31m[disconnected]\x1b[0m\r\n");

    // keystrokes → server (server enforces driver-only, this is just UX)
    term.onData((d) => {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ t: "in", data: strToB64(d) }));
    });

    // focus the terminal so keyboard input works immediately
    setTimeout(() => term.focus(), 100);

    return () => {
      window.removeEventListener("resize", onResize);
      ws.close();
      term.dispose();
    };
  }, [session.id, tester]);

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
      </div>
      <div className="shell-term-screen" ref={host} />
    </div>
  );
}
