import { useEffect, useState } from "react";
import { HostDetail, VulnDetail, getHost } from "./api";
import { SevTag, NoteCell } from "./ui";
import { FindingDetail } from "./FindingDetail";

// Slide-in panel with everything about one host: posture, services, full findings
// (each expandable to raw output + remediation + QoD), AD accounts, and a note.
export function HostDrawer(
  { ip, onClose, onTick, onNote }:
  { ip: string | null; onClose: () => void;
    onTick: (k: string, r: boolean) => void; onNote: (k: string, t: string) => void }
) {
  const [d, setD] = useState<HostDetail | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [openV, setOpenV] = useState<string | null>(null);

  useEffect(() => {
    if (!ip) return;
    setD(null); setErr(null); setOpenV(null);
    getHost(ip).then(setD).catch((e) => setErr(String(e)));
  }, [ip]);

  useEffect(() => {
    if (!ip) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [ip, onClose]);

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
      <aside className="drawer" role="dialog" aria-label={`host ${ip}`}>
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
                        {v.kev && <span className="badge kev">🔥</span>}
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
