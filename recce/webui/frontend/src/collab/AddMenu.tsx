import { useState } from "react";
import { addFinding, addCredential, addHostScope, addAccess } from "../api";
import { useEscape } from "../ui";
import { useCollab } from "./CollabContext";

type AddKind = "finding" | "credential" | "host" | "access";

export function AddMenu({ onDone }: { onDone: (msg: string) => void }) {
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState<AddKind | null>(null);
  const { refresh } = useCollab();
  return (
    <>
      <button className="btn add-btn" onClick={() => setOpen((v) => !v)}
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
  useEscape(onClose, !busy);
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
