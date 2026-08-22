import { useState, useEffect, useRef, useCallback } from "react";
import { useCollab } from "./collab";

export function ChatPanel({ tester }: { tester: string }) {
  const { chat, sendChat, unread, markChatRead } = useCollab();
  const [text, setText] = useState("");
  const [sending, setSending] = useState(false);
  const chatRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (chatRef.current) {
      chatRef.current.scrollTop = chatRef.current.scrollHeight;
    }
    markChatRead();
  }, [chat, markChatRead]);

  const handleSend = useCallback(async () => {
    if (!text.trim() || sending) return;
    setSending(true);
    try {
      await sendChat(text, "", null);
      setText("");
    } catch (e) {
      console.error("Chat send failed:", e);
    } finally {
      setSending(false);
    }
  }, [text, sending, sendChat]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const hue = (name: string): number => {
    let h = 0;
    for (let i = 0; i < name.length; i++) {
      h = ((h << 5) - h + name.charCodeAt(i)) | 0;
    }
    return (h % 360 + 360) % 360;
  };

  const initials = (name: string): string => {
    return name.split(" ").map((w) => w[0]).join("").toUpperCase().slice(0, 2);
  };

  return (
    <div className="chat-panel-full">
      <div className="chat-messages" ref={chatRef}>
        {chat.length === 0 ? (
          <div className="empty-state">No messages yet. Start a conversation!</div>
        ) : (
          chat.map((m) => (
            <div key={m.id} className={`chat-msg ${m.tester === tester ? "mine" : ""}`}>
              <span
                className="chat-avatar"
                style={{ background: `hsl(${hue(m.tester)} 55% 45%)` }}
              >
                {initials(m.tester)}
              </span>
              <div className="chat-content">
                <div className="chat-header">
                  <span className="chat-tester">{m.tester === tester ? "You" : m.tester}</span>
                  <span className="chat-time">{new Date(m.ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
                </div>
                {m.text && <div className="chat-text">{m.text}</div>}
                {m.image && <img src={m.image} alt="chat" className="chat-image" />}
              </div>
            </div>
          ))
        )}
      </div>

      <div className="chat-input-box">
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Type a message... (Shift+Enter for new line)"
          className="chat-input"
          disabled={sending}
        />
        <button
          className="chat-send"
          onClick={handleSend}
          disabled={!text.trim() || sending}
          title="Send (Ctrl+Enter)"
        >
          {sending ? "…" : "Send"}
        </button>
      </div>
    </div>
  );
}
