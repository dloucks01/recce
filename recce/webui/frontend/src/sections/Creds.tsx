// Creds — the captured/looted credential store, spray launcher, and paste-to-loot.
import { useEffect, useMemo, useState } from "react";
import { Credential, LootFile, getCredentials, getLoot, lootFileUrl, postSprayAsync, postLootExtract } from "../api";
import { SectionProps } from "../nav";
import { Panel, Empty, Chip } from "../kit";
import { copyText } from "../util";
import { toast } from "../toast";

export function Creds(_: SectionProps) {
  const [creds, setCreds] = useState<Credential[]>([]);
  const [loot, setLoot] = useState<LootFile[]>([]);
  const [q, setQ] = useState("");
  const [kind, setKind] = useState("all");
  const [reveal, setReveal] = useState<Set<string>>(new Set());
  const [paste, setPaste] = useState("");
  const [sprayT, setSprayT] = useState("");
  const [safe, setSafe] = useState(true);

  const load = () => {
    getCredentials().then(setCreds).catch(() => {});
    getLoot().then(setLoot).catch(() => {});
  };
  useEffect(() => { load(); }, []);

  // Live refresh: a spray running elsewhere folds validated logins into the store
  // server-side and publishes an "add"/"spray_hit" event. Reload on those so hits
  // actually "fold back here" without a manual refresh.
  useEffect(() => {
    let es: EventSource | null = null;
    try {
      es = new EventSource("/api/events");
      es.onmessage = (m) => {
        try { const t = JSON.parse(m.data)?.type; if (t === "add" || t === "spray_hit" || t === "session") load(); } catch { /* noop */ }
      };
    } catch { /* SSE unavailable — the manual ↻ still works */ }
    return () => es?.close();
  }, []);

  const kinds = useMemo(() => [...new Set(creds.map((c) => c.kind).filter(Boolean))].sort(), [creds]);
  const rows = useMemo(() => {
    const n = q.toLowerCase();
    return creds.filter((c) => (kind === "all" || c.kind === kind) &&
      (!n || `${c.username} ${c.domain} ${c.source} ${c.origin_ip}`.toLowerCase().includes(n)));
  }, [creds, q, kind]);

  // Key must be unique per row: the store can hold two entries for the same
  // domain\user+kind with different secrets (rotated password, same account from
  // two tools). Including secret+origin keeps the reveal-toggle from flipping both.
  const ck = (c: Credential) => `${c.domain}\\${c.username}:${c.kind}:${c.secret}:${c.origin_ip}`;
  const toggle = (k: string) => setReveal((s) => { const n = new Set(s); n.has(k) ? n.delete(k) : n.add(k); return n; });

  async function doPaste() {
    if (!paste.trim()) return;
    try { const r = await postLootExtract(paste); toast.show(`extracted ${r.added} new credential(s) (${r.skipped_dupes} dupes)`); setPaste(""); load(); }
    catch (e) { toast.show(String(e)); }
  }
  async function spray() {
    const t = sprayT.trim();
    if (!t) { toast.show("enter targets — an IP / CIDR / range, or 'all' to spray every discovered host"); return; }
    // Map the explicit "all" opt-in to the backend's --all sentinel; the backend
    // deliberately rejects an empty target list so nobody sprays the whole scope
    // by accident.
    const arg = /^(all|--all|\*)$/i.test(t) ? "--all" : t;
    try { await postSprayAsync(arg, safe); toast.show("spray started — validated logins fold in here as they land"); }
    catch (e) { toast.show(String(e)); }
  }

  return (
    <>
      <Panel title="Spray" sub="try the captured credentials across the scope (lockout-aware)">
        <div className="row wrap" style={{ gap: 8 }}>
          <input className="fin" style={{ maxWidth: 320 }} placeholder="targets — IP / CIDR / range (or 'all')" value={sprayT} onChange={(e) => setSprayT(e.target.value)} />
          <Chip label="safe (no lockout risk)" on={safe} onClick={() => setSafe(!safe)} />
          <button className="btn sm primary" onClick={spray}>💧 Spray</button>
        </div>
      </Panel>

      <Panel title={`Credential store (${creds.length})`}
             actions={<>
               <select className="btn sm" value={kind} onChange={(e) => setKind(e.target.value)}><option value="all">All kinds</option>{kinds.map((k) => <option key={k} value={k}>{k}</option>)}</select>
               <input className="namebox" style={{ width: 180 }} placeholder="filter: user, domain, source…" value={q} onChange={(e) => setQ(e.target.value)} />
             </>}>
        {rows.length === 0 ? <Empty>No credentials yet — loot from sessions, crack hashes, or paste below.</Empty> : (
          <table className="tbl">
            <thead><tr><th>User</th><th style={{ width: 70 }}>Kind</th><th>Secret</th><th style={{ width: 130 }}>Source</th><th style={{ width: 90 }}>From</th></tr></thead>
            <tbody>
              {rows.map((c) => {
                const k = ck(c);
                const shown = reveal.has(k);
                return (
                  <tr key={k}>
                    <td><span className="mono">{c.domain ? `${c.domain}\\` : ""}{c.username}</span></td>
                    <td><span className="chip">{c.kind}</span></td>
                    <td>
                      <span className="row" style={{ gap: 6 }}>
                        <span className="mono" style={{ maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{shown ? c.secret : "••••••••"}</span>
                        <button className="linkish" onClick={() => toggle(k)}>{shown ? "hide" : "show"}</button>
                        <button className="linkish" onClick={() => copyText(c.secret).then(() => toast.show("secret copied"))}>copy</button>
                        <button className="linkish" onClick={() => copyText(`${c.domain ? c.domain + "\\" : ""}${c.username}:${c.secret}`).then(() => toast.show("user:secret copied"))}>copy pair</button>
                      </span>
                    </td>
                    <td className="muted">{c.source}</td>
                    <td className="mono faint">{c.origin_ip || "—"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title={`Looted files (${loot.length})`}
             sub="files pulled off targets through sessions — shared across the team"
             actions={<button className="btn sm" title="refresh" onClick={load}>↻</button>}>
        {loot.length === 0 ? <Empty>No looted files yet — pull files from a session (Download) and they appear here.</Empty> : (
          <table className="tbl">
            <thead><tr><th>File</th><th style={{ width: 110 }}>Host</th><th style={{ width: 90 }}>Size</th><th style={{ width: 90 }} /></tr></thead>
            <tbody>
              {loot.map((f) => (
                <tr key={f.rel}>
                  <td className="mono">{f.name}</td>
                  <td className="mono faint">{f.host || "—"}</td>
                  <td className="muted">{f.size < 1024 ? `${f.size} B` : `${(f.size / 1024).toFixed(1)} KB`}</td>
                  <td><a className="linkish" href={lootFileUrl(f.rel)} download>download</a></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel title="Paste to loot" sub="drop secretsdump / gpp / mimikatz / key=value output — recce extracts credentials">
        <textarea className="fin" rows={4} placeholder="paste tool output here…" value={paste} onChange={(e) => setPaste(e.target.value)} />
        <div className="row" style={{ marginTop: 8 }}><button className="btn sm primary" disabled={!paste.trim()} onClick={doPaste}>Extract credentials</button></div>
      </Panel>
    </>
  );
}
