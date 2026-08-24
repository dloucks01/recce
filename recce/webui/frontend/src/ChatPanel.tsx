import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { useCollab } from "./collab";

// Render message text with @mentions highlighted. Any @token that matches a
// known online tester (case-insensitive) becomes a chip; otherwise it's plain
// text. Keeps a stable key so React doesn't repaint on every render.
function renderText(text: string, online: string[], me: string): React.ReactNode[] {
  if (!text) return [];
  // Match @ followed by word chars OR quoted-name spaces. Simple form for now.
  const parts = text.split(/(@\w+)/g);
  return parts.map((p, i) => {
    if (!p.startsWith("@")) return p;
    const name = p.slice(1);
    const match = online.find((o) => o.toLowerCase() === name.toLowerCase());
    if (match) return <span key={i} className={"chat-mention" + (match === me ? " me" : "")}>@{match}</span>;
    return p;
  });
}

const hue = (name: string): number => {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = ((h << 5) - h + name.charCodeAt(i)) | 0;
  return (h % 360 + 360) % 360;
};
const initials = (name: string): string =>
  name.split(" ").map((w) => w[0]).join("").toUpperCase().slice(0, 2);

export function ChatPanel({ tester }: { tester: string }) {
  const { chat, sendChat, markChatRead, c } = useCollab();
  const [text, setText] = useState("");
  const [sending, setSending] = useState(false);
  const [mentionQuery, setMentionQuery] = useState<string | null>(null);
  const [mentionIdx, setMentionIdx] = useState(0);
  const chatRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (chatRef.current) chatRef.current.scrollTop = chatRef.current.scrollHeight;
    markChatRead();
  }, [chat, markChatRead]);

  // Online tester list drives both mention detection and autocomplete.
  const online = useMemo(() => c.online.filter((n) => n && n !== tester), [c.online, tester]);
  const suggestions = useMemo(() => {
    if (mentionQuery === null) return [];
    const q = mentionQuery.toLowerCase();
    return online.filter((n) => n.toLowerCase().startsWith(q)).slice(0, 6);
  }, [mentionQuery, online]);

  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const v = e.target.value;
    setText(v);
    // Detect an open @-token — the @ at or before the caret with only word chars
    // after it. When we see one, open the popup and update the query.
    const caret = e.target.selectionStart ?? v.length;
    const upto = v.slice(0, caret);
    const m = upto.match(/@(\w*)$/);
    if (m) { setMentionQuery(m[1]); setMentionIdx(0); }
    else setMentionQuery(null);
  };

  const insertMention = useCallback((name: string) => {
    const el = inputRef.current;
    if (!el) return;
    const caret = el.selectionStart ?? text.length;
    const upto = text.slice(0, caret);
    const rest = text.slice(caret);
    const replaced = upto.replace(/@\w*$/, `@${name} `);
    const nextText = replaced + rest;
    setText(nextText);
    setMentionQuery(null);
    requestAnimationFrame(() => {
      el.focus();
      const nc = replaced.length;
      el.setSelectionRange(nc, nc);
    });
  }, [text]);

  const handleSend = useCallback(async () => {
    if (!text.trim() || sending) return;
    setSending(true);
    try {
      await sendChat(text, "", null);
      setText("");
      setMentionQuery(null);
    } catch (e) {
      console.error("Chat send failed:", e);
    } finally { setSending(false); }
  }, [text, sending, sendChat]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (mentionQuery !== null && suggestions.length > 0) {
      if (e.key === "ArrowDown") { e.preventDefault(); setMentionIdx((i) => (i + 1) % suggestions.length); return; }
      if (e.key === "ArrowUp") { e.preventDefault(); setMentionIdx((i) => (i - 1 + suggestions.length) % suggestions.length); return; }
      if (e.key === "Enter" || e.key === "Tab") { e.preventDefault(); insertMention(suggestions[mentionIdx]); return; }
      if (e.key === "Escape") { e.preventDefault(); setMentionQuery(null); return; }
    }
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleSend(); }
  };

  return (
    <div className="chat-panel-full">
      <div className="chat-messages" ref={chatRef}>
        {chat.length === 0 ? (
          <div className="empty-state">No messages yet. Start a conversation — @-mention a teammate to notify them.</div>
        ) : (
          chat.map((m) => (
            <div key={m.id} className={`chat-msg ${m.tester === tester ? "mine" : ""}`}>
              <span className="chat-avatar" style={{ background: `hsl(${hue(m.tester)} 55% 45%)` }}>
                {initials(m.tester)}
              </span>
              <div className="chat-content">
                <div className="chat-header">
                  <span className="chat-tester">{m.tester === tester ? "You" : m.tester}</span>
                  <span className="chat-time">{new Date(m.ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
                </div>
                {m.text && <div className="chat-text">{renderText(m.text, [tester, ...online], tester)}</div>}
                {m.image && <img src={m.image} alt="chat" className="chat-image" />}
              </div>
            </div>
          ))
        )}
      </div>

      <div className="chat-input-box">
        <div className="chat-input-wrap">
          <textarea
            ref={inputRef}
            value={text}
            onChange={handleChange}
            onKeyDown={handleKeyDown}
            placeholder="Type a message… @-mention to notify (Shift+Enter for new line)"
            className="chat-input"
            disabled={sending}
          />
          {mentionQuery !== null && suggestions.length > 0 && (
            <div className="mention-popup">
              {suggestions.map((name, i) => (
                <button key={name}
                        className={"mention-item" + (i === mentionIdx ? " sel" : "")}
                        onMouseDown={(e) => { e.preventDefault(); insertMention(name); }}>
                  <span className="mention-avatar" style={{ background: `hsl(${hue(name)} 55% 45%)` }}>
                    {initials(name)}
                  </span>
                  <span>{name}</span>
                </button>
              ))}
            </div>
          )}
        </div>
        <button className="chat-send" onClick={handleSend}
                disabled={!text.trim() || sending} title="Send (Enter)">
          {sending ? "…" : "Send"}
        </button>
      </div>
    </div>
  );
}
