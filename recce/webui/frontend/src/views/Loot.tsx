import { useEffect, useState } from "react";
import { Credential, SprayHit, getCredentials, postSpray } from "../api";
import { Stat } from "../ui";

// "What did we extract?" The credential store — looted (web/db/share) + captured
// (kerberoast/gpp/secretsdump) — which the UI never surfaced before.

const KIND_LABEL: Record<string, string> = {
  password: "password", nthash: "NT hash", hash: "hash", blank: "blank",
};

export function Loot() {
  const [creds, setCreds] = useState<Credential[] | null>(null);
  const [reveal, setReveal] = useState<Set<number>>(new Set());
  const [err, setErr] = useState<string | null>(null);
  // spray control
  const [tgt, setTgt] = useState("");
  const [safe, setSafe] = useState(true);
  const [spraying, setSpraying] = useState(false);
  const [hits, setHits] = useState<SprayHit[] | null>(null);
  const [sprayMsg, setSprayMsg] = useState<string | null>(null);
  const load = () => getCredentials().then(setCreds).catch((e) => setErr(String(e)));
  useEffect(() => { load(); }, []);
  async function spray() {
    setSpraying(true); setSprayMsg(null); setHits(null);
    try {
      const r = await postSpray(tgt.trim(), safe);
      if (!r.ok) { setSprayMsg(r.error || "spray failed"); }
      else { setHits(r.hits); setSprayMsg(r.hits.length ? `${r.hits.length} valid login(s); ${r.new} new credential(s) stored.` : "no valid logins."); await load(); }
    } catch { setSprayMsg("spray failed"); }
    finally { setSpraying(false); }
  }
  if (err) return <div className="err">{err}</div>;
  if (!creds) return <div className="loading">Loading credentials…</div>;
  if (creds.length === 0)
    return <div className="empty">No credentials collected yet. They appear here once the credential-bearing modules run — web <code>.git</code>/<code>.env</code>, database trust / empty-password, SMB shares, Kerberoasting, GPP.</div>;
  const bySource: Record<string, number> = {};
  creds.forEach((c) => { bySource[c.source] = (bySource[c.source] || 0) + 1; });
  const toggle = (i: number) => setReveal((s) => { const n = new Set(s); n.has(i) ? n.delete(i) : n.add(i); return n; });
  return (
    <div className="lootview">
      <section className="stats">
        <Stat k="credentials" v={String(creds.length)} />
        <Stat k="sources" v={String(Object.keys(bySource).length)} />
        <Stat k="plaintext" v={String(creds.filter((c) => c.kind === "password").length)} />
        <Stat k="hashes" v={String(creds.filter((c) => c.kind === "nthash" || c.kind === "hash").length)} />
      </section>
      <section className="panel spraybar">
        <div className="panel-h"><h3>Spray these credentials</h3>
          <span className="muted">reuse the collected credentials across the login surface (SMB/WinRM/MSSQL/LDAP/SSH)</span></div>
        <div className="spray-row">
          <input className="scan-in" placeholder="target scope — blank = all, or 10.0.0.5 / 10.0.0.0/24"
                 value={tgt} onChange={(e) => setTgt(e.target.value)} disabled={spraying} />
          <label className="safetog" title="lockout-safe: paired user↔pass, one pass (netexec --no-bruteforce)">
            <input type="checkbox" checked={safe} onChange={(e) => setSafe(e.target.checked)} disabled={spraying} />
            lockout-safe
          </label>
          <button className="run" onClick={spray} disabled={spraying || creds.length === 0}>
            {spraying ? "Spraying…" : "💧 Spray"}
          </button>
        </div>
        {!safe && <div className="ranmsg warn-msg">Full user × password — real lockout risk on a domain lockout policy. Rules of engagement only.</div>}
        {sprayMsg && <div className="ranmsg">{sprayMsg}</div>}
        {hits && hits.length > 0 && (
          <table className="loottable"><thead><tr><th>Proto</th><th>Host</th><th>Login</th><th></th></tr></thead>
            <tbody>{hits.map((h, i) => (
              <tr key={i}><td className="mono">{h.proto}</td><td className="mono">{h.ip}</td>
                <td className="mono">{h.cred}</td>
                <td>{h.admin && <span className="tag warn">ADMIN · Pwn3d!</span>}</td></tr>
            ))}</tbody>
          </table>
        )}
      </section>

      <section className="panel">
        <div className="panel-h"><h3>Collected credentials</h3>
          <span className="muted">what recce collected / captured — or <code>recce creds --run</code> to spray</span></div>
        <div className="tablewrap">
          <table className="loottable">
            <thead><tr><th>Account</th><th>Secret</th><th>Kind</th><th>Source</th><th>From</th><th>Notes</th></tr></thead>
            <tbody>
              {creds.map((c, i) => (
                <tr key={i}>
                  <td className="mono">{c.label}</td>
                  <td className="mono secret">
                    <span className="secretval" onClick={() => toggle(i)} title="click to reveal / hide">
                      {reveal.has(i) ? (c.secret || "—") : "•".repeat(Math.min(12, (c.secret || "").length || 4))}</span>
                    {c.secret && <button className="copy" onClick={() => navigator.clipboard?.writeText(c.secret)} title="copy secret">copy</button>}
                  </td>
                  <td><span className="tag">{KIND_LABEL[c.kind] || c.kind}</span></td>
                  <td className="mono">{c.source}</td>
                  <td className="mono">{c.origin_ip}</td>
                  <td className="muted notes">{c.notes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
