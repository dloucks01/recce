// Persistent right-hand team rail: roster (online + durable offline), a flat
// activity feed, and team chat. Collaboration lives here always, not as a tab.
import { useState } from "react";
import { useCollab } from "./collab";
import { seenAgo, timeAgo } from "./collab/_shared";
import { Avatar } from "./kit";
import { ChatPanel } from "./ChatPanel";
import { Empty } from "./kit";

const ACT_ICON: Record<string, string> = {
  assign: "👤", add: "➕", tick: "✓", note: "📝", scan: "🔍", import: "📥",
  label: "🏷", dismiss: "✗", chat: "💬", session: "⌨", status: "🔀", priority: "🔥", review: "✓",
};

export function TeamRail() {
  const { c, me } = useCollab();
  const [tab, setTab] = useState<"roster" | "activity" | "chat">("roster");

  const team = (() => {
    const m = new Map<string, { online: boolean; lastSeen: string }>();
    (c.roster || []).forEach((t) => { if (t.name) m.set(t.name, { online: c.online.includes(t.name), lastSeen: t.last_seen }); });
    c.online.forEach((n) => { if (n && !m.has(n)) m.set(n, { online: true, lastSeen: "" }); });
    return [...m.entries()].map(([name, v]) => ({ name, ...v }))
      .sort((a, b) => (b.online ? 1 : 0) - (a.online ? 1 : 0) || a.name.localeCompare(b.name));
  })();

  return (
    <aside className="rail">
      <div className="rail-tabs">
        {([["roster", "👥", "Team"], ["activity", "⚡", "Activity"], ["chat", "💬", "Chat"]] as const).map(([id, ti, tl]) => (
          <button key={id} className={"rail-tab" + (tab === id ? " active" : "")} onClick={() => setTab(id)}>
            <span className="ti">{ti}</span><span className="tl">{tl}</span>
          </button>
        ))}
      </div>

      {tab === "roster" && (
        <div className="rail-body pad">
          <div className="row" style={{ justifyContent: "space-between", marginBottom: 6 }}>
            <span className="faint" style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: ".05em", fontWeight: 700 }}>Roster</span>
            <span className="mono faint" style={{ fontSize: 11 }}>{team.filter((t) => t.online).length}/{team.length} online</span>
          </div>
          {team.length === 0 ? <Empty>Set your name (top-right) to join.</Empty> :
            team.map((t) => (
              <div key={t.name} className={"rl" + (t.online ? "" : " off")}>
                <span className="dot" style={{ background: t.online ? "var(--ok)" : "var(--faint)" }} />
                <Avatar name={t.name} online={t.online} />
                <span className="nm">{t.name === me ? "You" : t.name}</span>
                {!t.online && <span className="when">{seenAgo(t.lastSeen)}</span>}
              </div>
            ))}
        </div>
      )}

      {tab === "activity" && (
        <div className="rail-body pad">
          {c.activity.length === 0 ? <Empty>No activity yet.</Empty> :
            c.activity.slice(0, 60).map((a, i) => (
              <div key={i} className={"act " + a.kind}>
                <span>{ACT_ICON[a.kind] || "◦"}</span>
                <span className="txt"><span className="who">{a.tester}</span> {a.text}</span>
                <span className="tm">{timeAgo(a.ts)}</span>
              </div>
            ))}
        </div>
      )}

      {tab === "chat" && (
        <div className="rail-body">
          <ChatPanel tester={me} />
        </div>
      )}
    </aside>
  );
}
