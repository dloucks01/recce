// Shared UI primitives for the rebuilt workbench. Every view composes these so
// the look stays consistent (flat, dense) without per-view CSS. Styling lives in
// styles/app.css; these just wire structure + the design tokens.
import { ReactNode } from "react";
import { hue, initials } from "./collab/_shared";

export function Avatar({ name, sm, online }: { name: string; sm?: boolean; online?: boolean }) {
  return (
    <span className={"avatar" + (sm ? " sm" : "")} style={{ background: `hsl(${hue(name)} 55% 45%)`, opacity: online === false ? 0.55 : 1 }}>
      {initials(name)}
    </span>
  );
}

export function Sev({ s }: { s: string }) {
  const sev = (s || "info").toLowerCase();
  return <span className={"sev " + sev}>{sev.slice(0, 4)}</span>;
}

export function Panel({ title, sub, actions, children, style }:
  { title?: ReactNode; sub?: ReactNode; actions?: ReactNode; children: ReactNode; style?: React.CSSProperties }) {
  return (
    <section className="panel" style={style}>
      {(title || actions) && (
        <div className="panel-h">
          <div className="row" style={{ gap: 8, alignItems: "baseline", flexWrap: "wrap" }}>
            {title && <h3>{title}</h3>}
            {sub && <span className="sub">{sub}</span>}
          </div>
          {actions && <div className="row" style={{ gap: 6 }}>{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function StatRow({ items }: { items: { k: string; v: ReactNode; cls?: string }[] }) {
  return (
    <div className="statrow">
      {items.map((it, i) => (
        <div className="stat" key={i}>
          <div className="k">{it.k}</div>
          <div className={"v" + (it.cls ? " " + it.cls : "")}>{it.v}</div>
        </div>
      ))}
    </div>
  );
}

export function Meter({ label, now, total, ok }:
  { label: string; now: number; total: number; ok?: boolean }) {
  const pct = total > 0 ? Math.min(100, Math.round((100 * now) / total)) : 0;
  return (
    <div className="meter">
      <div className="meter-h"><span className="mn">{label}</span>
        <span className="mono">{now}{total ? ` / ${total}` : ""}</span></div>
      <div className="meter-t"><div className={"meter-f" + (ok ? " ok" : "")} style={{ width: `${pct}%` }} /></div>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function Chip({ label, on, onClick, title, count }:
  { label: ReactNode; on?: boolean; onClick?: () => void; title?: string; count?: number }) {
  return (
    <button className={"chip" + (onClick ? " click" : "") + (on ? " on" : "")} onClick={onClick} title={title}>
      {label}{count != null && <span className="mono" style={{ opacity: .7 }}>{count}</span>}
    </button>
  );
}
