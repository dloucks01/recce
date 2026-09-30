// Scan launch drawer — the form for one chosen command. Renders the command's
// own flag catalog (bool/text/int/list/wordlist), targets (prefilled with the
// hosts that qualify), profile/creds/lhost only when the command needs them,
// then POSTs /api/scan and hands back the job id to stream.
import { useState } from "react";
import { CmdSpec, RunReq, Wordlist, postCommand } from "./api";
import { copyText } from "./util";

const PROFILES = ["", "quick", "normal", "thorough"];

export function ScanLaunchDrawer({ cmd, spec, defaultTargets, qualifyCount, wordlists, onClose, onLaunched }:
  {
    cmd: string; spec: CmdSpec; defaultTargets: string; qualifyCount?: number;
    wordlists: Wordlist[]; onClose: () => void; onLaunched: (id: string) => void;
  }) {
  const [targets, setTargets] = useState(defaultTargets);
  const [profile, setProfile] = useState("");
  const [username, setU] = useState(""); const [password, setP] = useState(""); const [domain, setD] = useState("");
  const [lhost, setLhost] = useState("");
  const [bools, setBools] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(spec.flags.filter((f) => (f.kind || "bool") === "bool").map((f) => [f.name, !!f.active])));
  const [vals, setVals] = useState<Record<string, string>>({});
  const [thenSweep, setThenSweep] = useState(true);   // enum: auto deep-sweep after discovery
  const [resume, setResume] = useState(false);        // enum/scan: skip finished hosts
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const wlByKind = (kind?: string) => wordlists.filter((w) => !kind || w.kind === kind);

  async function launch() {
    setBusy(true); setErr("");
    const req: RunReq = { command: cmd };
    if (spec.targets !== "none") req.targets = targets.trim();
    if (spec.profile && profile) req.profile = profile;
    if (spec.creds) { req.username = username; req.password = password; req.domain = domain; }
    if (spec.lhost && lhost) req.lhost = lhost;
    const activeFlags = Object.entries(bools).filter(([, v]) => v).map(([n]) => n);
    if (activeFlags.length) req.flags = activeFlags;
    const fv = Object.fromEntries(Object.entries(vals).filter(([, v]) => v.trim()));
    if (Object.keys(fv).length) req.flag_values = fv;
    if (cmd === "enum" && thenSweep) req.then_sweep = true;
    if ((cmd === "enum" || cmd === "scan") && resume) req.resume = true;
    try { const { id } = await postCommand(req); onLaunched(id); }
    catch (e) { setErr(String(e instanceof Error ? e.message : e)); }
    finally { setBusy(false); }
  }

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label={`launch ${cmd}`}>
        <div className="drawer-head">
          <div>
            <div style={{ fontWeight: 700 }}>{spec.label || cmd}</div>
            <div className="muted mono" style={{ fontSize: 12 }}>recce {cmd}{qualifyCount ? ` · ${qualifyCount} hosts qualify` : ""}</div>
          </div>
          <button className="icon-btn" onClick={onClose} title="close (Esc)">✕</button>
        </div>
        <div className="drawer-body">
          {spec.tool_cmd && (
            <div className="field">
              <span className="fl">Underlying tool command</span>
              <div className="cmdline" title="the raw external-tool command this wraps — run it directly if you prefer">
                <code className="cmd expanded">{spec.tool_cmd.replace(/<target>/g, targets.trim().split(/[\s,]+/)[0] || "<target>")}</code>
                <button className="btn sm" onClick={() => copyText(spec.tool_cmd!.replace(/<target>/g, targets.trim().split(/[\s,]+/)[0] || "<target>"))}>copy</button>
              </div>
            </div>
          )}
          {spec.targets !== "none" && (
            <label className="field"><span className="fl">Targets{spec.targets === "required" ? " *" : ""}</span>
              <textarea className="fin" rows={2} value={targets} onChange={(e) => setTargets(e.target.value)}
                        placeholder="10.0.0.0/24  or  10.0.0.5 10.0.0.6" /></label>
          )}
          {spec.profile && (
            <label className="field"><span className="fl">Profile</span>
              <select className="fin" value={profile} onChange={(e) => setProfile(e.target.value)}>
                {PROFILES.map((p) => <option key={p} value={p}>{p || "(default)"}</option>)}
              </select></label>
          )}
          {cmd === "enum" && (
            <label className="row" style={{ gap: 8, margin: "6px 0" }}
                   title="when discovery finishes, automatically run the deep per-service sweep (every applicable module, each self-skipping)">
              <input type="checkbox" checked={thenSweep} onChange={(e) => setThenSweep(e.target.checked)} />
              <span>then auto-enum discovered services (deep sweep)</span>
            </label>
          )}
          {(cmd === "enum" || cmd === "scan") && (
            <label className="row" style={{ gap: 8, margin: "6px 0" }}
                   title="skip hosts already enumerated in this engagement — pick up an interrupted run where it left off">
              <input type="checkbox" checked={resume} onChange={(e) => setResume(e.target.checked)} />
              <span>resume (skip hosts already finished)</span>
            </label>
          )}
          {spec.lhost && (
            <label className="field"><span className="fl">LHOST (callback IP)</span>
              <input className="fin" value={lhost} onChange={(e) => setLhost(e.target.value)} placeholder="your listener IP" /></label>
          )}
          {spec.creds && (
            <div className="field"><span className="fl">Credentials</span>
              <div className="row" style={{ gap: 6 }}>
                <input className="fin" placeholder="username" value={username} onChange={(e) => setU(e.target.value)} />
                <input className="fin" placeholder="password / hash" value={password} onChange={(e) => setP(e.target.value)} />
                <input className="fin" placeholder="domain" value={domain} onChange={(e) => setD(e.target.value)} />
              </div>
            </div>
          )}
          {spec.flags.length > 0 && (
            <div className="field"><span className="fl">Options</span>
              <div className="grid" style={{ gap: 6 }}>
                {spec.flags.map((f) => {
                  const kind = f.kind || "bool";
                  if (kind === "bool") return (
                    <label key={f.name} className="row" style={{ gap: 6 }}>
                      <input type="checkbox" checked={!!bools[f.name]} onChange={(e) => setBools((b) => ({ ...b, [f.name]: e.target.checked }))} />
                      <span>{f.label}</span></label>
                  );
                  return (
                    <label key={f.name} className="field" style={{ margin: 0 }}><span className="fl">{f.label}</span>
                      <div className="row" style={{ gap: 6 }}>
                        <input className="fin" placeholder={f.placeholder || ""} value={vals[f.name] || ""}
                               onChange={(e) => setVals((v) => ({ ...v, [f.name]: e.target.value }))} />
                        {kind === "wordlist" && (
                          <select className="fin" style={{ maxWidth: 160 }} value="" onChange={(e) => { if (e.target.value) setVals((v) => ({ ...v, [f.name]: e.target.value })); }}>
                            <option value="">bundled…</option>
                            {wlByKind(f.wordlist_kind).map((w) => <option key={w.name} value={w.name} title={`${w.blurb} (${w.line_count} lines)`}>{w.name}</option>)}
                          </select>
                        )}
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>
          )}
          {err && <div className="panel" style={{ borderColor: "var(--crit)", color: "var(--crit)", marginTop: 10 }}>{err}</div>}
          <div className="row" style={{ gap: 8, marginTop: 14 }}>
            <button className="btn primary" onClick={launch} disabled={busy || (spec.targets === "required" && !targets.trim())}>
              {busy ? "Launching…" : "▶ Launch scan"}
            </button>
            <button className="btn" onClick={onClose}>Cancel</button>
          </div>
        </div>
      </aside>
    </>
  );
}
