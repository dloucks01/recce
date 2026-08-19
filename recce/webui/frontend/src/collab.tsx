import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import {
  Collab, TRIAGE_LABELS, getCollab, pingPresence, postAssign, postLabel, postPortStatus,
  postDismiss, addFinding, addCredential, addHostScope, addAccess,
} from "./api";

const EMPTY: Collab = { assignments: {}, labels: {}, port_status: {}, dismissed: {}, activity: [], online: [] };

type Ctx = {
  c: Collab;
  refresh: () => void;
  me: string;
  assign: (ip: string, tester: string) => void;
  label: (ip: string, label: string, on: boolean) => void;
  portStatus: (ip: string, port: number, status: string) => void;
  dismiss: (key: string, on: boolean) => void;
};
const CollabCtx = createContext<Ctx | null>(null);
export const useCollab = () => useContext(CollabCtx)!;
const me = () => localStorage.getItem("recce.tester") || "someone";

export function CollabProvider({ children }: { children: React.ReactNode }) {
  const [c, setC] = useState<Collab>(EMPTY);
  const refresh = useCallback(() => { getCollab().then(setC).catch(() => {}); }, []);
  useEffect(() => {
    refresh();
    pingPresence().then(refresh);
    const poll = window.setInterval(refresh, 15000);
    const beat = window.setInterval(() => pingPresence(), 20000);
    return () => { window.clearInterval(poll); window.clearInterval(beat); };
  }, [refresh]);

  // optimistic local update, then reconcile from the server broadcast
  const opt = (fn: (d: Collab) => Collab, call: Promise<unknown>) => {
    setC((d) => fn(structuredClone(d)));
    Promise.resolve(call).then(refresh).catch(refresh);
  };
  const value: Ctx = {
    c, refresh, me: me(),
    assign: (ip, tester) => opt((d) => { if (tester) d.assignments[ip] = tester; else delete d.assignments[ip]; return d; }, postAssign(ip, tester)),
    label: (ip, l, on) => opt((d) => { const s = new Set(d.labels[ip] || []); on ? s.add(l) : s.delete(l); d.labels[ip] = [...s]; return d; }, postLabel(ip, l, on)),
    portStatus: (ip, port, status) => opt((d) => { const k = `${ip}:${port}`; if (status) d.port_status[k] = status; else delete d.port_status[k]; return d; }, postPortStatus(ip, port, status)),
    dismiss: (key, on) => opt((d) => { if (on) d.dismissed[key] = me(); else delete d.dismissed[key]; return d; }, postDismiss(key, on)),
  };
  return <CollabCtx.Provider value={value}>{children}</CollabCtx.Provider>;
}

/* ------------------------------- presence -------------------------------- */
const initials = (n: string) => n.trim().slice(0, 2).toUpperCase() || "?";
const hue = (n: string) => { let h = 0; for (const ch of n) h = (h * 31 + ch.charCodeAt(0)) % 360; return h; };

export function PresenceBar() {
  const { c, me } = useCollab();
  if (!c.online.length) return null;
  return (
    <div className="presence" title={`online: ${c.online.join(", ")}`}>
      {c.online.slice(0, 6).map((n) => (
        <span key={n} className={"avatar" + (n === me ? " me" : "")}
              style={{ background: `hsl(${hue(n)} 55% 45%)` }} title={n}>{initials(n)}</span>
      ))}
      {c.online.length > 6 && <span className="avatar more">+{c.online.length - 6}</span>}
    </div>
  );
}

/* ---------------------------- activity drawer ---------------------------- */
const KIND_ICON: Record<string, string> = {
  assign: "👤", add: "＋", access: "🔓", dismiss: "🚫", tick: "✓", note: "✎",
};
export function ActivityButton() {
  const { c } = useCollab();
  const [open, setOpen] = useState(false);
  return (
    <>
      <button className="theme-tog activity-btn" onClick={() => setOpen(true)}
              title="team activity feed" aria-label="activity">⚡</button>
      {open && (
        <>
          <div className="drawer-backdrop" onClick={() => setOpen(false)} />
          <div className="drawer activity-drawer">
            <button className="drawer-x" onClick={() => setOpen(false)}>✕</button>
            <div className="dh"><div className="dh-ip">Team activity</div>
              <div className="dh-name">{c.online.length} online · newest first</div></div>
            <ul className="actfeed">
              {c.activity.length === 0 && <li className="muted">No activity yet.</li>}
              {c.activity.map((a, i) => (
                <li key={i}>
                  <span className="af-i">{KIND_ICON[a.kind] || "•"}</span>
                  <span className="af-t">{a.text}</span>
                  <span className="af-when">{when(a.ts)}</span>
                </li>
              ))}
            </ul>
          </div>
        </>
      )}
    </>
  );
}
function when(ts: number) {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

/* -------------------------- assignment + labels -------------------------- */
export function AssignControl({ ip }: { ip: string }) {
  const { c, me, assign } = useCollab();
  const owner = c.assignments[ip] || "";
  if (owner) {
    return (
      <span className={"owner" + (owner === me ? " mine" : "")} title={`claimed by ${owner}`}
            onClick={(e) => { e.stopPropagation(); assign(ip, ""); }}>
        <span className="avatar sm" style={{ background: `hsl(${hue(owner)} 55% 45%)` }}>{initials(owner)}</span>
        {owner === me ? "you" : owner} <span className="rel">✕</span>
      </span>
    );
  }
  return (
    <button className="claim" onClick={(e) => { e.stopPropagation(); assign(ip, me); }}
            title="claim this host">claim</button>
  );
}

export function LabelChips({ ip }: { ip: string }) {
  const { c, label } = useCollab();
  const on = new Set(c.labels[ip] || []);
  return (
    <span className="labelchips" onClick={(e) => e.stopPropagation()}>
      {TRIAGE_LABELS.map((l) => (
        <button key={l} className={"lchip l-" + l + (on.has(l) ? " on" : "")}
                onClick={() => label(ip, l, !on.has(l))} title={l}>{l}</button>
      ))}
    </span>
  );
}

/* ----------------------------- per-port status --------------------------- */
const PSTATES: [string, string, string][] = [["todo", "☐", "not started"], ["wip", "◐", "in progress"], ["done", "☑", "done"]];
export function PortStatus({ ip, port }: { ip: string; port: number }) {
  const { c, portStatus } = useCollab();
  const cur = c.port_status[`${ip}:${port}`] || "todo";
  return (
    <span className="portstatus">
      {PSTATES.map(([v, glyph, label]) => (
        <button key={v} className={"psbtn ps-" + v + (cur === v ? " on" : "")}
                onClick={(e) => { e.stopPropagation(); portStatus(ip, port, cur === v ? "" : v); }}
                title={label}>{glyph}</button>
      ))}
    </span>
  );
}

/* ------------------------------- add modal ------------------------------- */
type AddKind = "finding" | "credential" | "host" | "access";
export function AddMenu({ onDone }: { onDone: (msg: string) => void }) {
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState<AddKind | null>(null);
  const { refresh } = useCollab();
  return (
    <>
      <button className="import-btn add-btn" onClick={() => setOpen((v) => !v)}
              title="add a finding / credential / host / access by hand">＋ Add ▾</button>
      {open && (
        <>
          <div className="exp-backdrop" onClick={() => setOpen(false)} />
          <div className="exp-menu add-menu">
            {(["finding", "credential", "host", "access"] as AddKind[]).map((k) => (
              <button key={k} onClick={() => { setKind(k); setOpen(false); }}>
                {{ finding: "🐞 Finding", credential: "🔑 Credential", host: "🖥 Host / scope", access: "🔓 Access / foothold" }[k]}
              </button>
            ))}
          </div>
        </>
      )}
      {kind && <AddModal kind={kind} onClose={() => setKind(null)}
                         onDone={(m) => { onDone(m); refresh(); setKind(null); }} />}
    </>
  );
}

function AddModal({ kind, onClose, onDone }:
  { kind: AddKind; onClose: () => void; onDone: (msg: string) => void }) {
  const [f, setF] = useState<Record<string, string>>({ severity: "medium", kind: "password" });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const set = (k: string) => (e: { target: { value: string } }) => setF((p) => ({ ...p, [k]: e.target.value }));
  async function go() {
    setBusy(true); setErr(null);
    try {
      if (kind === "finding") { await addFinding({ ip: f.ip, port: f.port, title: f.title, severity: f.severity, cve: f.cve, output: f.output }); onDone(`Added finding on ${f.ip}`); }
      else if (kind === "credential") { await addCredential({ username: f.username, secret: f.secret, kind: f.kind, domain: f.domain, origin_ip: f.origin_ip, notes: f.notes }); onDone("Added credential"); }
      else if (kind === "host") { const r = await addHostScope(f.targets); onDone(`Added ${r.added} host(s)`); }
      else { await addAccess(f.ip, f.note); onDone(`Recorded access on ${f.ip}`); }
    } catch (e) { setErr(String(e instanceof Error ? e.message : e)); setBusy(false); }
  }
  const T: Record<AddKind, string> = { finding: "Add a finding", credential: "Add a credential", host: "Add a host / scope", access: "Record access" };
  return (
    <>
      <div className="modal-backdrop" onClick={onClose} />
      <div className="modal" role="dialog">
        <div className="modal-h"><h3>{T[kind]}</h3><button className="drawer-x" onClick={onClose}>✕</button></div>
        <div className="addform">
          {kind === "finding" && <>
            <L t="Host IP"><input className="scan-in" placeholder="10.0.0.5" value={f.ip || ""} onChange={set("ip")} autoFocus /></L>
            <div className="frow">
              <L t="Port"><input className="scan-in" placeholder="445" value={f.port || ""} onChange={set("port")} /></L>
              <L t="Severity"><select value={f.severity} onChange={set("severity")}>{["critical", "high", "medium", "low", "info"].map((s) => <option key={s}>{s}</option>)}</select></L>
            </div>
            <L t="Title"><input className="scan-in" placeholder="What did you find?" value={f.title || ""} onChange={set("title")} /></L>
            <L t="CVE (optional)"><input className="scan-in" placeholder="CVE-2021-44228" value={f.cve || ""} onChange={set("cve")} /></L>
            <L t="Evidence / notes"><textarea className="imp-paste" value={f.output || ""} onChange={set("output")} /></L>
          </>}
          {kind === "credential" && <>
            <div className="frow">
              <L t="Username"><input className="scan-in" value={f.username || ""} onChange={set("username")} autoFocus /></L>
              <L t="Kind"><select value={f.kind} onChange={set("kind")}>{["password", "nthash", "hash", "blank"].map((s) => <option key={s}>{s}</option>)}</select></L>
            </div>
            <L t="Secret"><input className="scan-in" value={f.secret || ""} onChange={set("secret")} /></L>
            <div className="frow">
              <L t="Domain"><input className="scan-in" placeholder="corp.local" value={f.domain || ""} onChange={set("domain")} /></L>
              <L t="From host"><input className="scan-in" placeholder="10.0.0.5" value={f.origin_ip || ""} onChange={set("origin_ip")} /></L>
            </div>
            <L t="Notes"><input className="scan-in" value={f.notes || ""} onChange={set("notes")} /></L>
          </>}
          {kind === "host" && <L t="IPs / ranges / CIDRs">
            <input className="scan-in" placeholder="10.0.0.5 10.0.0.10-20 10.0.1.0/24" value={f.targets || ""} onChange={set("targets")} autoFocus /></L>}
          {kind === "access" && <>
            <L t="Host IP"><input className="scan-in" placeholder="10.0.0.5" value={f.ip || ""} onChange={set("ip")} autoFocus /></L>
            <L t="How you got in"><input className="scan-in" placeholder="SYSTEM via PrintNightmare" value={f.note || ""} onChange={set("note")} /></L>
          </>}
        </div>
        {err && <div className="ranmsg warn-msg">{err}</div>}
        <div className="modal-actions">
          <button className="toggle" onClick={onClose} disabled={busy}>Cancel</button>
          <button className="run" onClick={go} disabled={busy}>{busy ? "Adding…" : "Add"}</button>
        </div>
      </div>
    </>
  );
}
function L({ t, children }: { t: string; children: React.ReactNode }) {
  return <label className="imp-field">{t}{children}</label>;
}
