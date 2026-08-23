import { useEffect, useState } from "react";
import { HostDetail, VulnDetail, SessionInfo, Credential, getHost, getSessions, getCredentials } from "./api";
import { SevTag, NoteCell, useEscape, useResizableDrawer } from "./ui";
import { FindingDetail } from "./FindingDetail";
import { PortStatus } from "./collab";

// Slide-in panel with everything about one host: posture, services, full findings
// (each expandable to raw output + remediation + QoD), AD accounts, and a note.
export function HostDrawer(
  { ip, onClose, onTick, onNote, onOpenShell }:
  { ip: string | null; onClose: () => void; onOpenShell?: (id: string) => void;
    onTick: (k: string, r: boolean) => void; onNote: (k: string, t: string) => void }
) {
  const [d, setD] = useState<HostDetail | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [openV, setOpenV] = useState<string | null>(null);
  const [shells, setShells] = useState<SessionInfo[]>([]);
  const [creds, setCreds] = useState<Credential[]>([]);

  // this host's caught shells + looted creds — the engagement-native tie-in
  useEffect(() => {
    if (!ip) { setShells([]); setCreds([]); return; }
    const load = () => {
      getSessions(ip).then(setShells).catch(() => {});
      getCredentials().then((cs) => setCreds(cs.filter((c) => c.origin_ip === ip))).catch(() => {});
    };
    load();
    const t = window.setInterval(load, 3000);
    return () => window.clearInterval(t);
  }, [ip]);

  useEffect(() => {
    if (!ip) return;
    setD(null); setErr(null); setOpenV(null);
    getHost(ip).then(setD).catch((e) => setErr(String(e)));
  }, [ip]);

  useEscape(onClose, ip != null);
  const { width, startResize } = useResizableDrawer("recce.hostw", 620);

  if (!ip) return null;

  // local optimistic updates so ticks/notes reflect immediately in the drawer too
  function tick(v: VulnDetail) {
    const reviewed = !v.reviewed;
    setD((cur) => cur && { ...cur, vulns: cur.vulns.map((x) => x.key === v.key ? { ...x, reviewed } : x) });
    onTick(v.key, reviewed);
  }
  function note(key: string, text: string, isHost: boolean) {
    setD((cur) => cur && (isHost
      ? { ...cur, notes: text }
      : { ...cur, vulns: cur.vulns.map((x) => x.key === key ? { ...x, notes: text } : x) }));
    onNote(key, text);
  }

  const shown = d ? d.vulns.filter((v) => v.tier !== "lead") : [];
  const leads = d ? d.vulns.length - shown.length : 0;

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label={`host ${ip}`} style={{ width }}>
        <div className="drawer-resize" onMouseDown={startResize} title="drag to resize" />
        <button className="drawer-x" onClick={onClose} aria-label="close">✕</button>
        {err && <div className="err">Could not load host: {err}</div>}
        {!d && !err && <div className="loading">Loading {ip}…</div>}
        {d && (
          <>
            <header className="dh">
              <div className="dh-ip mono">{d.ip}</div>
              {d.hostname && <div className="dh-name">{d.hostname}</div>}
              <div className="dh-tags">
                {d.os && <span className="tagpill">{d.os}</span>}
                {d.roles.map((r) => <span key={r} className="tagpill role">{r}</span>)}
                {d.smb_signing && <span className="tagpill">SMB signing: {d.smb_signing}</span>}
                {d.defenses.map((x) => <span key={x} className="tagpill">{x}</span>)}
              </div>
              {d.access_detail && <div className="dh-access">🔓 {d.access_detail}</div>}
              <div className="steps big">
                <Step on={d.ports.length > 0} label="scan" />
                <Step on={d.enumerated} label="enum" />
                <Step on={d.vuln_scanned} label="vuln" />
                <Step on={d.access} label="access" ok />
              </div>
            </header>

            <Section title="What's been done">
              <HostActivity d={d} shells={shells} creds={creds} />
            </Section>

            {shells.length > 0 && (
              <Section title={`Shells (${shells.length})`}
                       extra="Sessions tab to drive">
                <div className="drawer-shells">
                  {shells.map((s) => (
                    <button key={s.id} className="drawer-shell"
                            onClick={() => onOpenShell?.(s.id)} title="open in Sessions">
                      <span className={"sess-dot " + (s.status === "live" ? "live" : "stale")} />
                      <span className="mono">{s.kind}</span>
                      <span className="badge">{s.status}</span>
                      {s.pty && <span className="badge pty">PTY</span>}
                      {s.driver && <span className="muted small">▸ {s.driver}</span>}
                      <span className="muted small" style={{ marginLeft: "auto" }}>open →</span>
                    </button>
                  ))}
                </div>
              </Section>
            )}

            <Section title="Note">
              <NoteCell value={d.notes} onSave={(t) => note(d.key, t, true)} />
            </Section>

            <Section title={`Findings (${shown.length})`}
                     extra={leads > 0 ? `${leads} leads hidden` : undefined}>
              {shown.length === 0 && <div className="muted small">no findings above the confidence threshold</div>}
              <div className="dv-list">
                {shown.map((v) => (
                  <div key={v.key} className={"dv" + (v.reviewed ? " done" : "")}>
                    <div className="dv-row" onClick={() => setOpenV(openV === v.key ? null : v.key)}>
                      <input type="checkbox" checked={v.reviewed}
                             onClick={(e) => e.stopPropagation()} onChange={() => tick(v)} />
                      <SevTag severity={v.severity} />
                      <div className="dv-title">
                        <div className="t">{v.title}</div>
                        <div className="m mono">
                          {[v.cve, v.source].filter(Boolean).join(" · ")}
                        </div>
                      </div>
                      <div className="dv-badges">
                        {v.kev && <span className="badge kev" title="CISA Known Exploited Vulnerability — confirmed exploited in the wild; fix first">🔥</span>}
                        <span className={"tier " + v.tier}>{v.tier}</span>
                        <span className="caret">{openV === v.key ? "▾" : "▸"}</span>
                      </div>
                    </div>
                    {openV === v.key && (
                      <FindingDetail v={v} onNote={(k, t) => note(k, t, false)} />
                    )}
                  </div>
                ))}
              </div>
            </Section>

            <Section title={`Services (${d.ports.length})`}>
              <table className="mini">
                <tbody>
                  {d.ports.map((p) => (
                    <tr key={`${p.proto}/${p.port}`}>
                      <td><PortStatus ip={d.ip} port={p.port} /></td>
                      <td className="mono">{p.port}/{p.proto}</td>
                      <td>{p.service}</td>
                      <td className="muted">{[p.product, p.version].filter(Boolean).join(" ") || p.banner}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Section>

            {d.accounts.length > 0 && (
              <Section title={`Accounts (${d.accounts.length})`}>
                <table className="mini">
                  <tbody>
                    {d.accounts.map((a, i) => (
                      <tr key={i}>
                        <td><span className="tagpill sm">{a.kind}</span></td>
                        <td className="mono">{a.domain ? `${a.domain}\\` : ""}{a.name}</td>
                        <td className="muted small">
                          {a.attrs.spn ? "SPN " : ""}
                          {a.attrs.admincount ? "adminCount " : ""}
                          {a.attrs.asrep_roastable ? "AS-REP " : ""}
                          {a.attrs.delegation ? `deleg:${a.attrs.delegation} ` : ""}
                          {a.attrs.memberof || a.detail || ""}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Section>
            )}
          </>
        )}
      </aside>
    </>
  );
}

// "What's been done" — the detailed per-host account, assembled from data recce already
// has: the full phase set (not just 4 steps), and which modules produced findings.
function HostActivity(
  { d, shells, creds }: { d: HostDetail; shells: SessionInfo[]; creds: Credential[] }
) {
  const sev = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>;
  d.vulns.forEach((v) => { if (v.tier !== "lead") sev[v.severity] = (sev[v.severity] || 0) + 1; });
  const findingN = Object.values(sev).reduce((a, b) => a + b, 0);

  // group findings by the module (source) that produced them — "what each tool did"
  const bySource: Record<string, number> = {};
  d.vulns.forEach((v) => { if (v.tier !== "lead") bySource[v.source] = (bySource[v.source] || 0) + 1; });

  const phases: { label: string; done: boolean; detail: string }[] = [
    { label: "Port scan", done: d.ports.length > 0, detail: `${d.ports.length} port(s) open` },
    { label: "Service enum", done: d.enumerated, detail: d.enumerated ? "services identified" : "not yet" },
    { label: "Vuln scan", done: d.vuln_scanned, detail: d.vuln_scanned ? `${findingN} finding(s)` : "not yet" },
    { label: "Database", done: d.db, detail: d.db ? "db enumerated" : "" },
    { label: "Priv-esc", done: d.privesc, detail: d.privesc ? "checks run" : "" },
    { label: "Cred enum", done: d.credenum, detail: d.credenum ? "credentialed enum" : "" },
    { label: "Access", done: d.access, detail: d.access ? (d.access_detail || `${shells.length} shell(s)`) : "no foothold" },
  ].filter((p) => p.done || ["Port scan", "Service enum", "Vuln scan", "Access"].includes(p.label));

  return (
    <div className="host-activity">
      <ul className="phase-list">
        {phases.map((p) => (
          <li key={p.label} className={"phase-row" + (p.done ? " done" : "")}>
            <span className="phase-ic">{p.done ? "✔" : "○"}</span>
            <span className="phase-label">{p.label}</span>
            <span className="phase-detail muted">{p.detail}</span>
          </li>
        ))}
      </ul>

      {Object.keys(bySource).length > 0 && (
        <div className="by-source">
          <div className="muted small">Findings by module</div>
          <div className="source-chips">
            {Object.entries(bySource).sort((a, b) => b[1] - a[1]).map(([src, n]) => (
              <span key={src} className="source-chip"><b>{src}</b> {n}</span>
            ))}
          </div>
        </div>
      )}

      {(shells.length > 0 || creds.length > 0) && (
        <div className="activity-tally">
          {shells.length > 0 && <span className="tally">🖥 {shells.length} shell(s)</span>}
          {creds.length > 0 && <span className="tally">🔑 {creds.length} cred(s) looted</span>}
          {sev.critical > 0 && <span className="tally crit">{sev.critical} critical</span>}
        </div>
      )}
    </div>
  );
}

function Section({ title, extra, children }: { title: string; extra?: string; children: React.ReactNode }) {
  return (
    <section className="drawer-sec">
      <div className="drawer-sec-h"><h4>{title}</h4>{extra && <span className="muted small">{extra}</span>}</div>
      {children}
    </section>
  );
}

function Step({ on, label, ok }: { on: boolean; label: string; ok?: boolean }) {
  return <span className={"step" + (on ? " on" : "") + (on && ok ? " ok" : "")}>{label}</span>;
}
