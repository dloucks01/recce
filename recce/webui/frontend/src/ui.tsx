import { useEffect, useRef, useState } from "react";
import { SEVS } from "./api";

export function Stat(
  { k, v, sub, cls, onClick }:
  { k: string; v: string; sub?: string; cls?: string; onClick?: () => void }
) {
  return (
    <div className={"stat" + (cls ? " " + cls : "") + (onClick ? " click" : "")} onClick={onClick}>
      <div className="k">{k}</div>
      <div className="v">{v} {sub && <small>{sub}</small>}</div>
    </div>
  );
}

export function SevTag({ severity }: { severity: string }) {
  return (
    <span className="sev-cell">
      <span className={"stripe s-" + severity} />
      <span className={"sev-tag s-" + severity}>{severity.slice(0, 4)}</span>
    </span>
  );
}

export function SevBar({ findings }: { findings: Record<string, number> }) {
  const total = SEVS.reduce((n, s) => n + (findings[s] || 0), 0);
  if (total === 0) return <span className="clean">clean</span>;
  return (
    <div className="sevbar">
      <div className="bar">
        {SEVS.map((s) => {
          const c = findings[s] || 0;
          return c ? <span key={s} className={"seg s-" + s} style={{ flex: c }} title={`${c} ${s}`} /> : null;
        })}
      </div>
      <div className="counts">
        {SEVS.map((s) => (findings[s] ? <span key={s} className={"c s-" + s}>{findings[s]}</span> : null))}
      </div>
    </div>
  );
}

// Inline, collapsible note editor. Saves on blur; shows who's typing is out of scope,
// but the saved note is shared + attributed server-side and broadcast to everyone.
export function NoteCell({ value, onSave }: { value: string; onSave: (t: string) => void }) {
  const [open, setOpen] = useState(false);
  const [text, setText] = useState(value);
  useEffect(() => { setText(value); }, [value]);
  if (!open) {
    return value
      ? <button className="note-chip has" onClick={() => setOpen(true)} title={value}>📝 {value.length > 40 ? value.slice(0, 40) + "…" : value}</button>
      : <button className="note-chip" onClick={() => setOpen(true)}>+ note</button>;
  }
  return (
    <div className="note-edit">
      <textarea
        value={text}
        autoFocus
        placeholder="note for the team…"
        onChange={(e) => setText(e.target.value)}
        onBlur={() => { setOpen(false); if (text !== value) onSave(text); }}
        onKeyDown={(e) => {
          if (e.key === "Escape") { setText(value); setOpen(false); }
          if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) { e.currentTarget.blur(); }
        }}
      />
    </div>
  );
}

// Bounded rendering: only `page` items exist until the sentinel scrolls into view.
// Returns the slice to render + a sentinel element to place after the list.
export function useBounded<T>(items: T[], page = 120, deps: unknown[] = []) {
  const [limit, setLimit] = useState(page);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => { setLimit(page); /* reset on filter change */ }, deps);
  useEffect(() => {
    const el = ref.current;
    if (!el || limit >= items.length) return;
    const io = new IntersectionObserver(
      (es) => { if (es[0].isIntersecting) setLimit((l) => Math.min(l + page, items.length)); },
      { rootMargin: "400px" }
    );
    io.observe(el);
    return () => io.disconnect();
  }, [limit, items.length, page]);
  const sentinel = limit < items.length ? <div className="sentinel" ref={ref} /> : null;
  return { shown: items.slice(0, limit), limit: Math.min(limit, items.length), total: items.length, sentinel };
}

export function Chips(
  { value, onChange, options }:
  { value: string; onChange: (v: string) => void; options: string[] }
) {
  return (
    <div className="chips">
      {options.map((s) => (
        <button key={s} className={"chip" + (value === s ? " sel" : "")} onClick={() => onChange(s)}>
          {s === "all" ? "All" : s[0].toUpperCase() + s.slice(1)}
        </button>
      ))}
    </div>
  );
}
