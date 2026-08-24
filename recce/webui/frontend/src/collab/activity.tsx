import { useState } from "react";
import { useEscape, useResizableDrawer } from "../ui";
import { useCollab } from "./CollabContext";
import { IP_RE, KIND_ICON, when } from "./_shared";

export function ActivityButton({ onOpenHost }: { onOpenHost?: (ip: string) => void }) {
  const { c } = useCollab();
  const [open, setOpen] = useState(false);
  const { width, startResize } = useResizableDrawer("recce.actw", 440);
  useEscape(() => setOpen(false), open);
  return (
    <>
      <button className="theme-tog activity-btn" onClick={() => setOpen(true)}
              title="team activity feed" aria-label="activity">⚡</button>
      {open && (
        <>
          <div className="drawer-backdrop" onClick={() => setOpen(false)} />
          <div className="drawer activity-drawer" style={{ width }}>
            <div className="drawer-resize" onMouseDown={startResize} title="drag to resize" />
            <button className="drawer-x" onClick={() => setOpen(false)}>✕</button>
            <div className="dh"><div className="dh-ip">Team activity</div>
              <div className="dh-name">{c.online.length} online · newest first</div></div>
            <ul className="actfeed">
              {c.activity.length === 0 && <li className="muted">No activity yet.</li>}
              {c.activity.map((a, i) => {
                const ip = onOpenHost ? (IP_RE.exec(a.text)?.[0] || "") : "";
                return (
                  <li key={i} className={ip ? "clk" : ""} title={ip ? `open ${ip}` : ""}
                      onClick={ip ? () => { onOpenHost!(ip); setOpen(false); } : undefined}>
                    <span className="af-i">{KIND_ICON[a.kind] || "•"}</span>
                    <span className="af-t">{a.text}</span>
                    <span className="af-when">{when(a.ts)}</span>
                  </li>
                );
              })}
            </ul>
          </div>
        </>
      )}
    </>
  );
}
