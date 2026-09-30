// Cmd-K command palette — jump to any section, host, finding, or session.
import { useEffect, useMemo, useState } from "react";
import { Finding, Host, SessionInfo, getSessions } from "./api";
import { SECTIONS } from "./sections/registry";
import { SectionId } from "./nav";

type Item = { label: string; kind: string; run: () => void };

export function CommandPalette({ hosts, findings, onClose, go, openHost, toFindings }:
  {
    hosts: Host[]; findings: Finding[]; onClose: () => void;
    go: (s: SectionId) => void; openHost: (ip: string) => void; toFindings: (o?: { host?: string; sev?: string }) => void;
  }) {
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  useEffect(() => { getSessions().then(setSessions).catch(() => {}); }, []);

  const items = useMemo<Item[]>(() => {
    const out: Item[] = SECTIONS.map((s) => ({ label: `Go to ${s.label}`, kind: "section", run: () => go(s.id) }));
    hosts.slice(0, 400).forEach((h) => out.push({ label: `${h.ip}${h.hostname ? " · " + h.hostname : ""}`, kind: "host", run: () => openHost(h.ip) }));
    findings.filter((f) => f.tier !== "lead").slice(0, 400).forEach((f) => out.push({ label: f.title, kind: f.severity, run: () => toFindings({ host: f.ip }) }));
    sessions.forEach((s) => out.push({ label: `${s.name || s.id.slice(0, 8)} · ${s.host_ip}`, kind: "session", run: () => go("sessions") }));
    return out;
  }, [hosts, findings, sessions]);

  const shown = useMemo(() => {
    const n = q.toLowerCase().trim();
    const f = n ? items.filter((i) => i.label.toLowerCase().includes(n) || i.kind.includes(n)) : items;
    return f.slice(0, 60);
  }, [items, q]);
  useEffect(() => setSel(0), [q]);

  const pick = (i: number) => { const it = shown[i]; if (it) { it.run(); onClose(); } };
  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(s + 1, shown.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
    else if (e.key === "Enter") { e.preventDefault(); pick(sel); }
    else if (e.key === "Escape") { e.preventDefault(); onClose(); }
  };

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="cp" onClick={(e) => e.stopPropagation()}>
        <input className="cp-input" autoFocus placeholder="Jump to a section, host, finding, or session…"
               value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={onKey} />
        <div className="cp-list">
          {shown.length === 0 ? <div className="cp-empty">No matches.</div> :
            shown.map((it, i) => (
              <button key={i} className={"cp-row" + (i === sel ? " sel" : "")} onMouseEnter={() => setSel(i)} onClick={() => pick(i)}
                      style={{ display: "flex", alignItems: "center", gap: 10, width: "100%", background: i === sel ? "var(--surface2)" : "none", border: "none", padding: "7px 14px", cursor: "pointer", textAlign: "left" }}>
                <span className="cp-label" style={{ flex: 1 }}>{it.label}</span>
                <span className="cp-kind">{it.kind}</span>
              </button>
            ))}
        </div>
        <div className="cp-hint">↑↓ navigate · ↵ open · esc close</div>
      </div>
    </div>
  );
}
