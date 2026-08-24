import { useEffect, useRef, useState } from "react";
import { useEscape, useResizableDrawer } from "../ui";
import { useCollab } from "./CollabContext";
import { fmtSize, hue, initials, when } from "./_shared";

// Wrap occurrences of the (lowercased) query in <mark> for search highlighting.
function highlight(text: string, q: string): React.ReactNode {
  if (!q) return text;
  const re = new RegExp(`(${q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")})`, "ig");
  return text.split(re).map((p, i) => (p.toLowerCase() === q ? <mark key={i}>{p}</mark> : p));
}

const CHAT_ATTACH_MAX = 20_000_000;   // client-side courtesy check; the server is authoritative

type Pending = { dataUrl: string; name: string; size: number; isImage: boolean };

export function ChatButton() {
  const { chat, unread, sendChat, markChatRead, me } = useCollab();
  const [open, setOpen] = useState(false);
  const [text, setText] = useState("");
  const [pending, setPending] = useState<Pending | null>(null);
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [q, setQ] = useState("");
  const endRef = useRef<HTMLDivElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);
  const { width, startResize } = useResizableDrawer("recce.chatw", 440);
  useEscape(() => (q ? setQ("") : setOpen(false)), open);
  useEffect(() => { if (open) markChatRead(); }, [open, chat.length, markChatRead]);
  useEffect(() => { if (open && !q) endRef.current?.scrollIntoView({ block: "end" }); }, [open, chat.length, q]);
  const ql = q.trim().toLowerCase();
  const shown = ql ? chat.filter((m) => `${m.text} ${m.tester}`.toLowerCase().includes(ql)) : chat;

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
    if (item) {
      const file = item.getAsFile();
      if (file) readAttachment(file);
      e.preventDefault();
    }
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
  async function send() {
    if ((!text.trim() && !pending) || busy) return;
    setBusy(true); setErr("");
    try {
      const b64 = pending ? pending.dataUrl.split(",")[1] || "" : "";
      if (pending && pending.isImage) await sendChat(text.trim(), b64);
      else if (pending) await sendChat(text.trim(), "", { data: b64, name: pending.name });
      else await sendChat(text.trim(), "");
      setText(""); setPending(null);
    } catch (e) { setErr(String(e instanceof Error ? e.message : e)); }
    finally { setBusy(false); }
  }
  return (
    <>
      <button className="theme-tog chat-btn" onClick={() => setOpen(true)} title="team chat" aria-label="team chat">
        💬{unread > 0 && <span className="chat-badge">{unread > 9 ? "9+" : unread}</span>}
      </button>
      {open && (
        <>
          <div className="drawer-backdrop" onClick={() => setOpen(false)} />
          <div className={"drawer chat-drawer" + (dragging ? " dragging" : "")} style={{ width }}
               onDragOver={onDragOver} onDragLeave={onDragLeave} onDrop={onDrop}>
            <div className="drawer-resize" onMouseDown={startResize} title="drag to resize" />
            <button className="drawer-x" onClick={() => setOpen(false)}>✕</button>
            <div className="dh"><div className="dh-ip">Team chat</div>
              <div className="dh-name">shared with everyone on this engagement</div></div>
            <div className="chat-search">
              <input placeholder="🔍 search messages…" value={q} onChange={(e) => setQ(e.target.value)} />
              {q && <button className="chat-search-x" onClick={() => setQ("")} title="clear">✕</button>}
              {ql && <span className="chat-search-n">{shown.length} of {chat.length}</span>}
            </div>
            <div className="chatlog">
              {chat.length === 0 && <div className="chat-empty">No messages yet — say hi 👋</div>}
              {chat.length > 0 && shown.length === 0 && <div className="chat-empty">No messages match “{q.trim()}”.</div>}
              {shown.map((m) => (
                <div key={m.id} className={"chatmsg" + (m.tester === me ? " mine" : "")}>
                  <span className="avatar sm" style={{ background: `hsl(${hue(m.tester)} 55% 45%)` }}>{initials(m.tester)}</span>
                  <div className="cm-body">
                    <div className="cm-head"><b>{m.tester === me ? "you" : m.tester}</b>
                      <span className="cm-when">{when(m.ts)}</span></div>
                    {m.text && <div className="cm-text">{highlight(m.text, ql)}</div>}
                    {m.image && (
                      <a href={`/api/chat/media/${m.image}`} target="_blank" rel="noopener">
                        <img className="cm-img" src={`/api/chat/media/${m.image}`} alt="shared" loading="lazy" />
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
              ))}
              <div ref={endRef} />
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
            <div className="chat-input">
              <input ref={fileRef} type="file" hidden
                     onChange={(e) => { const f = e.target.files?.[0]; if (f) readAttachment(f); e.target.value = ""; }} />
              <button className="chat-attach-btn" title="attach a file" aria-label="attach a file"
                      onClick={() => fileRef.current?.click()} disabled={busy} type="button">📎</button>
              <textarea placeholder="Message the team… (paste, drop, or attach a file)" value={text}
                        onChange={(e) => setText(e.target.value)} onPaste={onPaste}
                        onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } }} />
              <button className="btn primary" onClick={send} disabled={busy || (!text.trim() && !pending)}>Send</button>
            </div>
          </div>
        </>
      )}
    </>
  );
}
