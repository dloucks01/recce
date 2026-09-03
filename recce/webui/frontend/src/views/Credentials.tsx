import { useEffect, useState } from "react";
import { Credential, LootExtractResult, SprayHit, getCredentials, postLootExtract, postSpray, postCommand } from "../api";
import { Stat } from "../ui";
import { toast } from "../toast";
import { Nav } from "./shared";

const KIND_LABEL: Record<string, string> = {
  password: "password", nthash: "NT hash", hash: "hash", blank: "blank",
};

function protoToCommand(proto: string, admin: boolean): string {
  if (admin && (proto === "smb" || proto === "winrm")) return "deploy";
  if (proto === "ssh") return "deploy";
  return "credenum";
}

function protoToOneLiner(proto: string, user: string, ip: string): string {
  switch (proto) {
    case "smb": return `netexec smb ${ip} -u '${user}' -p 'PASSWORD'`;
    case "ssh": return `ssh ${user}@${ip}`;
    case "winrm": return `evil-winrm -i ${ip} -u '${user}' -p 'PASSWORD'`;
    case "mssql": return `netexec mssql ${ip} -u '${user}' -p 'PASSWORD'`;
    case "ldap": return `netexec ldap ${ip} -u '${user}' -p 'PASSWORD'`;
    default: return `netexec ${proto} ${ip} -u '${user}' -p 'PASSWORD'`;
  }
}

function credOneLiner(cred: Credential): string {
  const user = cred.label || cred.username;
  const ip = cred.origin_ip || "TARGET";
  const src = cred.source.toLowerCase();
  if (src.includes("ssh") || src.includes("linux")) return `ssh ${user}@${ip}`;
  if (src.includes("smb") || src.includes("ntlm") || src.includes("sam")) return `netexec smb ${ip} -u '${user}' -p 'SECRET'`;
  if (src.includes("mssql") || src.includes("sql")) return `netexec mssql ${ip} -u '${user}' -p 'SECRET'`;
  if (src.includes("postgres")) return `psql -h ${ip} -U ${user}`;
  if (src.includes("mysql") || src.includes("maria")) return `mysql -h ${ip} -u ${user} -p`;
  if (src.includes("mongo")) return `mongosh ${ip} -u ${user}`;
  if (src.includes("ftp")) return `ftp ${user}@${ip}`;
  if (src.includes("winrm")) return `evil-winrm -i ${ip} -u '${user}' -p 'SECRET'`;
  if (cred.kind === "nthash") return `netexec smb ${ip} -u '${user}' -H 'HASH'`;
  return `netexec smb ${ip} -u '${user}' -p 'SECRET'`;
}

function HitActions({ hit }: { hit: SprayHit }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function tryConnect() {
    setBusy(true); setMsg(null);
    const cmd = protoToCommand(hit.proto, hit.admin);
    const parts = hit.cred.split(":");
    const user = parts[0] || "";
    const pass = parts.slice(1).join(":") || "";
    try {
      await postCommand({
        command: cmd, targets: hit.ip,
        username: user, password: pass,
      });
      setMsg(`launched ${cmd}`);
    } catch (e) { setMsg(String(e instanceof Error ? e.message : e)); }
    finally { setBusy(false); }
  }

  function copyCmd() {
    const parts = hit.cred.split(":");
    const cmd = protoToOneLiner(hit.proto, parts[0] || "user", hit.ip);
    navigator.clipboard?.writeText(cmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  }

  return (
    <td className="hit-actions">
      {hit.admin && (
        <button className="cred-try-btn" onClick={tryConnect} disabled={busy}
                title={`run ${protoToCommand(hit.proto, hit.admin)} with these creds against ${hit.ip}`}>
          {busy ? "…" : "⚡ Deploy enum"}
        </button>
      )}
      <button className="cred-cmd-copy" onClick={copyCmd} title="copy one-liner">
        {copied ? "✓" : "📋"}
      </button>
      {msg && <span className="muted small"> {msg}</span>}
    </td>
  );
}

export function Credentials({ nav }: { nav?: Nav }) {
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

  function copyCred(c: Credential) {
    navigator.clipboard?.writeText(credOneLiner(c));
  }

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
          <table className="loottable"><thead><tr><th>Proto</th><th>Host</th><th>Login</th><th></th><th>Actions</th></tr></thead>
            <tbody>{hits.map((h, i) => (
              <tr key={i}><td className="mono">{h.proto}</td>
                <td className="mono">{nav
                  ? <span className="host-link" onClick={() => nav.openHost(h.ip)} title="host detail">{h.ip}</span>
                  : h.ip}</td>
                <td className="mono">{h.cred}</td>
                <td>{h.admin && <span className="tag warn">ADMIN · Pwn3d!</span>}</td>
                <HitActions hit={h} />
              </tr>
            ))}</tbody>
          </table>
        )}
      </section>

      <ExtractPanel onExtracted={load} />

      <section className="panel">
        <div className="panel-h"><h3>Collected credentials</h3>
          <span className="muted">what recce collected / captured — or <code>recce creds --run</code> to spray</span></div>
        <div className="tablewrap">
          <table className="loottable">
            <thead><tr><th>Account</th><th>Secret</th><th>Kind</th><th>Source</th><th>From</th><th>Notes</th><th className="creds-act-col">Actions</th></tr></thead>
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
                  <td className="mono">{nav && c.origin_ip
                    ? <span className="host-link" onClick={() => nav.openHost(c.origin_ip)} title="host detail">{c.origin_ip}</span>
                    : c.origin_ip}</td>
                  <td className="muted notes">{c.notes}</td>
                  <td className="creds-act-col">
                    <button className="cred-cmd-copy" onClick={() => copyCred(c)}
                            title={credOneLiner(c)}>📋 cmd</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

// Auto-loot: paste raw tool output — secretsdump rows, .env dumps, netexec
// output, whatever — and recce scrapes credentials from it into the store.
function ExtractPanel({ onExtracted }: { onExtracted: () => void }) {
  const [text, setText] = useState("");
  const [originIp, setOriginIp] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<LootExtractResult | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function go() {
    if (!text.trim() || busy) return;
    setBusy(true); setErr(null); setResult(null);
    try {
      const r = await postLootExtract(text, originIp.trim());
      setResult(r);
      if (r.added > 0) {
        toast.show(`+${r.added} credential(s) looted (${r.skipped_dupes} dupes skipped)`);
        onExtracted();
      } else if (r.found > 0) {
        toast.show(`${r.found} found — all already in the store`);
      } else {
        toast.show("no credentials recognised in that text");
      }
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    } finally { setBusy(false); }
  }

  return (
    <section className="panel autoloot">
      <div className="panel-h">
        <h3>Auto-loot from pasted text</h3>
        <span className="muted">
          scrapes secretsdump rows, .env-style KEY=VALUE, and user:pass lines — dupes skipped
        </span>
      </div>
      <div className="autoloot-row">
        <input className="scan-in" placeholder="origin host (optional)" value={originIp}
               onChange={e => setOriginIp(e.target.value)} style={{maxWidth: 200}} />
        <button className="run" onClick={go} disabled={busy || !text.trim()}>
          {busy ? "Scanning…" : "🔓 Extract"}
        </button>
      </div>
      <textarea className="imp-paste autoloot-text"
                placeholder="paste any tool output — secretsdump dump, a .env file, netexec results, config snippets…"
                value={text} onChange={e => setText(e.target.value)} disabled={busy} />
      {err && <div className="ranmsg warn-msg">{err}</div>}
      {result && result.found > 0 && (
        <div className="autoloot-result">
          <div className="autoloot-summary">
            found <b>{result.found}</b> · added <b>{result.added}</b> new
            {result.skipped_dupes > 0 && <> · skipped <b>{result.skipped_dupes}</b> dup{result.skipped_dupes > 1 ? "es" : ""}</>}
          </div>
          {result.credentials.length > 0 && (
            <ul className="autoloot-list">
              {result.credentials.map((c, i) => (
                <li key={i}>
                  <span className="mono">{c.username}</span>
                  <span className="mono muted">{c.secret_preview}</span>
                  <span className="tag">{c.kind}</span>
                  <span className="muted small">{c.source}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </section>
  );
}
