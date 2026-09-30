import { useCallback, useEffect, useRef, useState } from "react";
import { SEVS } from "./api";

// Close an overlay on Escape. `active` gates it so a closed overlay doesn't listen.
export function useEscape(onEsc: () => void, active = true) {
  useEffect(() => {
    if (!active) return;
    const h = (e: KeyboardEvent) => { if (e.key === "Escape") onEsc(); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [onEsc, active]);
}

// A right-edge drawer you can drag-resize by its left edge; width persists per key.
export function useResizableDrawer(storageKey: string, defaultW = 440) {
  const [width, setWidth] = useState(() => {
    const w = Number(localStorage.getItem(storageKey));
    return w >= 320 ? w : defaultW;
  });
  useEffect(() => { localStorage.setItem(storageKey, String(Math.round(width))); }, [storageKey, width]);
  const startResize = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    const onMove = (ev: MouseEvent) =>
      setWidth(Math.min(Math.max(320, window.innerWidth - ev.clientX), window.innerWidth - 60));
    const onUp = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      document.body.style.userSelect = "";
    };
    document.body.style.userSelect = "none";
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  }, []);
  return { width, startResize };
}

/**
 * Shared modal shell. Every modal in the app should wrap its body in this
 * component so overlay behavior, Escape-to-close, header styling, and close
 * button are consistent. Contents render inside `.modal-body`; footer buttons
 * go in a `.modal-actions` div at the end of children (already convention).
 *
 * `size` picks a width preset: sm (400px), md (600px, default), lg (860px).
 * `subtitle` shows a muted one-liner under the h2.
 */
export function Modal(
  { title, subtitle, onClose, size = "md", children, headerActions, ariaLabel }:
  {
    title: string;
    subtitle?: string;
    onClose: () => void;
    size?: "sm" | "md" | "lg";
    children: React.ReactNode;
    headerActions?: React.ReactNode;
    ariaLabel?: string;
  }
) {
  useEscape(onClose);
  return (
    <>
      <div className="modal-overlay" onClick={onClose} />
      <div className={`modal modal-${size}`} role="dialog"
           aria-modal="true" aria-label={ariaLabel || title}>
        <div className="modal-header">
          <div className="modal-title-block">
            <h2>{title}</h2>
            {subtitle && <p className="modal-subtitle">{subtitle}</p>}
          </div>
          <div className="modal-header-actions">
            {headerActions}
            <button className="modal-close" onClick={onClose}
                    aria-label="Close" title="Close (Esc)">×</button>
          </div>
        </div>
        <div className="modal-body">
          {children}
        </div>
      </div>
    </>
  );
}


/**
 * Shimmer skeleton placeholder for content that's still loading. Use in
 * place of a plain "Loading…" string when the shape of the content is
 * predictable (a table has rows, a card has a title + body). Matches the
 * theme via var(--surface2) / var(--line) — no explicit colors.
 *
 * `variant`: 'line' (default; one-line-of-text), 'block' (a card body),
 * 'row' (a table row shape).
 */
export function Skeleton(
  { variant = "line", width = "100%", height, count = 1 }:
  { variant?: "line" | "block" | "row"; width?: string; height?: string; count?: number }
) {
  const items = Array.from({ length: count });
  const heights = { line: "14px", block: "80px", row: "44px" };
  const h = height || heights[variant];
  return (
    <>
      {items.map((_, i) => (
        <div key={i} className={`skeleton skeleton-${variant}`}
             style={{ width, height: h }} aria-hidden="true" />
      ))}
    </>
  );
}


export function Stat(
  { k, v, sub, cls, onClick, title }:
  { k: string; v: string; sub?: string; cls?: string; onClick?: () => void; title?: string }
) {
  return (
    <div className={"stat" + (cls ? " " + cls : "") + (onClick ? " click" : "")} onClick={onClick} title={title}>
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
