import { useState, useEffect, useRef, useCallback, useMemo } from "react";
import { useCollab } from "./collab";
import { hue, initials, fmtSize } from "./collab/_shared";

// Inline team-chat panel (sidebar 💬 tab). This is the merged chat: the rich
// feature set that used to live in the (unwired) collab/chat.tsx drawer —
// file/image attachments, drag-drop, paste, and message search — plus the
// @-mention autocomplete + highlighting from the old plain panel. One panel,
// every capability the backend supports.

const CHAT_ATTACH_MAX = 20_000_000;   // client courtesy check; the server is authoritative

type Pending = { dataUrl: string; name: string; size: number; isImage: boolean };

// Wrap query matches in <mark> for search highlighting.
function withHighlight(text: string, q: string, keyBase: string): React.ReactNode {
  if (!q) return text;
  const re = new RegExp(`(${q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})`, "ig");
  return text.split(re).map((p, i) =>
    p.toLowerCase() === q ? <mark key={`${keyBase}-${i}`}>{p}</mark> : p);
}

// Render message text with @mentions as chips and (when searching) query
// matches highlighted. Mentions win over highlight on the same token.
function renderText(text: string, names: string[], me: string, q: string): React.ReactNode[] {
  if (!text) return [];
  const parts = text.split(/(@\w+)/g);
  return parts.map((p, i) => {
    if (p.startsWith("@")) {
      const match = names.find((o) => o.toLowerCase() === p.slice(1).toLowerCase());
      if (match) return <span key={i} className={"chat-mention" + (match === me ? " me" : "")}>@{match}</span>;
    }
    return <span key={i}>{withHighlight(p, q, String(i))}</span>;
  });
}

export function ChatPanel({ tester }: { tester: string }) {
  const { chat, sendChat, markChatRead, c } = useCollab();
  const [text, setText] = useState("");
  const [pending, setPending] = useState<Pending | null>(null);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [q, setQ] = useState("");
  const [mentionQuery, setMentionQuery] = useState<string | null>(null);
  const [mentionIdx, setMentionIdx] = useState(0);
  const chatRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (chatRef.current && !q) chatRef.current.scrollTop = chatRef.current.scrollHeight;
    markChatRead();
  }, [chat, markChatRead, q]);

  const online = useMemo(() => c.online.filter((n) => n && n !== tester), [c.online, tester]);
  const suggestions = useMemo(() => {
    if (mentionQuery === null) return [];
    const ql = mentionQuery.toLowerCase();
    return online.filter((n) => n.toLowerCase().startsWith(ql)).slice(0, 6);
  }, [mentionQuery, online]);

  const ql = q.trim().toLowerCase();
  const shown = ql ? chat.filter((m) => `${m.text} ${m.tester}`.toLowerCase().includes(ql)) : chat;

  // --- attachments ---------------------------------------------------------
  function readAttachment(file: File) {
    setErr("");
    if (file.size > CHAT_ATTACH_MAX) { setErr(`"${file.name}" is too large (max ~20 MB)`); return; }
    const r = new FileReader();
    r.onload = () => setPending({ dataUrl: String(r.result || ""), name: file.name,
                                  size: file.size, isImage: file.type.startsWith("image/") });
    r.onerror = () => setErr(`could not read "${file.name}"`);
    r.readAsDataURL(file);
  }
  function onPaste(e: React.ClipboardEvent<HTMLTextAreaElement>) {
    const item = Array.from(e.clipboardData.items).find((i) => i.type.startsWith("image/"));
    if (item) { const f = item.getAsFile(); if (f) readAttachment(f); e.preventDefault(); }
  }
  function onDragOver(e: React.DragEvent) {
    if (Array.from(e.dataTransfer.types).includes("Files")) { e.preventDefault(); setDragging(true); }
  }
  function onDragLeave(e: React.DragEvent) { e.preventDefault(); setDragging(false); }
  function onDrop(e: React.DragEvent) {
    e.preventDefault(); setDragging(false);
    const f = e.dataTransfer.files?.[0];
    if (f) readAttachment(f);
  }

  // --- @mention autocomplete ----------------------------------------------
  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const v = e.target.value;
    setText(v);
    const caret = e.target.selectionStart ?? v.length;
    const m = v.slice(0, caret).match(/@(\w*)$/);
    if (m) { setMentionQuery(m[1]); setMentionIdx(0); }
    else setMentionQuery(null);
  };
  const insertMention = useCallback((name: string) => {
    const el = inputRef.current;
    if (!el) return;
    const caret = el.selectionStart ?? text.length;
    const replaced = text.slice(0, caret).replace(/@\w*$/, `@${name} `);
    const nextText = replaced + text.slice(caret);
    setText(nextText);
    setMentionQuery(null);
    requestAnimationFrame(() => { el.focus(); el.setSelectionRange(replaced.length, replaced.length); });
  }, [text]);

  // --- send ---------------------------------------------------------------
  const send = useCallback(async () => {
    if ((!text.trim() && !pending) || busy) return;
    setBusy(true); setErr("");
    try {
      const b64 = pending ? pending.dataUrl.split(",")[1] || "" : "";
      if (pending && pending.isImage) await sendChat(text.trim(), b64);
      else if (pending) await sendChat(text.trim(), "", { data: b64, name: pending.name });
      else await sendChat(text.trim(), "");
      setText(""); setPending(null); setMentionQuery(null);
    } catch (e) { setErr(String(e instanceof Error ? e.message : e)); }
    finally { setBusy(false); }
  }, [text, pending, busy, sendChat]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (mentionQuery !== null && suggestions.length > 0) {
      if (e.key === "ArrowDown") { e.preventDefault(); setMentionIdx((i) => (i + 1) % suggestions.length); return; }
      if (e.key === "ArrowUp") { e.preventDefault(); setMentionIdx((i) => (i - 1 + suggestions.length) % suggestions.length); return; }
      if (e.key === "Enter" || e.key === "Tab") { e.preventDefault(); insertMention(suggestions[mentionIdx]); return; }
      if (e.key === "Escape") { e.preventDefault(); setMentionQuery(null); return; }
    }
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); }
  };

  const allNames = useMemo(() => [tester, ...online], [tester, online]);

  return (
    <div className={"chat-panel-full" + (dragging ? " dragging" : "")}
         onDragOver={onDragOver} onDragLeave={onDragLeave} onDrop={onDrop}>
      <div className="chat-search">
        <input placeholder="🔍 search messages…" value={q} onChange={(e) => setQ(e.target.value)} />
        {q && <button className="chat-search-x" onClick={() => setQ("")} title="clear">✕</button>}
        {ql && <span className="chat-search-n">{shown.length} of {chat.length}</span>}
      </div>

      <div className="chat-messages" ref={chatRef}>
        {chat.length === 0 ? (
          <div className="empty-state">No messages yet. Start a conversation — @-mention a teammate to notify them, or attach a file.</div>
        ) : shown.length === 0 ? (
          <div className="empty-state">No messages match “{q.trim()}”.</div>
        ) : (
          shown.map((m) => (
            <div key={m.id} className={`chat-msg ${m.tester === tester ? "mine" : ""}`}>
              <span className="chat-avatar" style={{ background: `hsl(${hue(m.tester)} 55% 45%)` }}>
                {initials(m.tester)}
              </span>
              <div className="chat-content">
                <div className="chat-header">
                  <span className="chat-tester">{m.tester === tester ? "You" : m.tester}</span>
                  <span className="chat-time">{new Date(m.ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>
                </div>
                {m.text && <div className="chat-text">{renderText(m.text, allNames, tester, ql)}</div>}
                {m.image && (
                  <a href={`/api/chat/media/${m.image}`} target="_blank" rel="noopener">
                    <img className="chat-image" src={`/api/chat/media/${m.image}`} alt="shared" loading="lazy" />
                  </a>
                )}
                {m.file && (
                  <a className="cm-file" href={`/api/chat/file/${m.file.stored}?dl=${encodeURIComponent(m.file.name)}`}
                     target="_blank" rel="noopener" title={`download ${m.file.name}`}>
                    <span className="cm-file-ic">📄</span>
                    <span className="cm-file-name">{m.file.name}</span>
                    <span className="cm-file-size">{fmtSize(m.file.size)}</span>
                  </a>
                )}
              </div>
            </div>
          ))
        )}
      </div>

      {dragging && <div className="chat-dropzone">Drop to attach</div>}
      {pending && (
        <div className="chat-preview">
          {pending.isImage
            ? <img src={pending.dataUrl} alt="pending attachment" />
            : <div className="chat-preview-file">
                <span className="cm-file-ic">📄</span>
                <span className="cm-file-name">{pending.name}</span>
                <span className="cm-file-size">{fmtSize(pending.size)}</span>
              </div>}
          <button className="tagbtn" onClick={() => setPending(null)}>remove</button>
        </div>
      )}
      {err && <div className="ranmsg warn-msg">{err}</div>}

      <div className="chat-input-box">
        <input ref={fileRef} type="file" hidden
               onChange={(e) => { const f = e.target.files?.[0]; if (f) readAttachment(f); e.target.value = ""; }} />
        <button className="chat-attach-btn" title="attach a file" aria-label="attach a file"
                onClick={() => fileRef.current?.click()} disabled={busy} type="button">📎</button>
        <div className="chat-input-wrap">
          <textarea
            ref={inputRef}
            value={text}
            onChange={handleChange}
            onKeyDown={handleKeyDown}
            onPaste={onPaste}
            placeholder="Message the team… @-mention to notify · paste/drop/📎 to attach (Shift+Enter = newline)"
            className="chat-input"
            disabled={busy}
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
        <button className="chat-send" onClick={send}
                disabled={busy || (!text.trim() && !pending)} title="Send (Enter)">
          {busy ? "…" : "Send"}
        </button>
      </div>
    </div>
  );
}
