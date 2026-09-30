// Host detail drawer — slides in from the right when you open a host. Services,
// findings, AD accounts, and posture for one host, plus the same collaboration
// actions the finding drawer has: claim, mark reviewed, note, scan this host.
// Reads /api/host/{ip}; mutations reuse the generic tracking/collab endpoints.
import { useEffect, useState } from "react";
import { getHost, HostDetail, postNote, postTick, getArtifacts, Artifact } from "./api";
import { Sev, Empty } from "./kit";
import { useFocus } from "./useFocus";
import { useCollab } from "./collab/CollabContext";
import { toast } from "./toast";
import { PocModal } from "./components/PocModal";

export function HostDrawer({ ip, onClose, onOpenFinding, onScanHost }:
  { ip: string; onClose: () => void;
    onOpenFinding?: (host: string) => void; onScanHost?: (ip: string) => void }) {
  const [h, setH] = useState<HostDetail | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [noteBase, setNoteBase] = useState("");
  const [reviewed, setReviewed] = useState(false);
  const [pbOpen, setPbOpen] = useState(false);
  const { c, me, assign } = useCollab();
  const { viewers, editors } = useFocus(`host:${ip}`);   // other operators on this host
  const justViewing = viewers.filter((v) => !editors.includes(v));
  const owner = c.assignments[ip] || h?.assignee || "";
  const hostKey = `host:${ip}`;

  useEffect(() => {
    let cancel = false;
    setH(null); setErr(null); setNote(""); setNoteBase(""); setReviewed(false);
    getHost(ip).then((d) => {
      if (cancel) return;
      setH(d); setNote(d.notes || ""); setNoteBase(d.notes || ""); setReviewed(!!d.reviewed);
    }).catch((e) => { if (!cancel) setErr(String(e)); });
    return () => { cancel = true; };
  }, [ip]);

  useEffect(() => {
    const k = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);

  const saveNote = () =>
    postNote(hostKey, note, noteBase).then((r) => {
      if (r && "conflict" in r) { setNote(r.notes); setNoteBase(r.notes); toast.show("note changed by another operator — reloaded"); }
      else { setNoteBase(note); toast.show("note saved"); }
    }).catch((e) => toast.show(String(e)));
  const toggleReviewed = () => {
    const next = !reviewed; setReviewed(next);
    postTick(hostKey, next).then(() => toast.show(next ? "host marked reviewed" : "review cleared"))
      .catch((e) => { setReviewed(!next); toast.show(String(e)); });
  };

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label={`host ${ip}`}>
        <div className="drawer-head">
          <div>
            <div className="mono" style={{ fontWeight: 700, fontSize: 15 }}>{ip}</div>
            {h && <div className="muted" style={{ fontSize: 12 }}>{h.hostname || "—"}{h.os ? ` · ${h.os}` : ""}</div>}
          </div>
          <button className="icon-btn" onClick={onClose} title="close (Esc)">✕</button>
        </div>

        {h && (
          <div className="row wrap" style={{ gap: 6, padding: "0 14px 8px", alignItems: "center" }}>
            <button className={"btn sm" + (owner === me ? " primary" : "")}
                    title={owner ? (owner === me ? "you own this host — click to release" : `owned by ${owner} — click to take over`) : "claim this host"}
                    onClick={() => assign(ip, owner === me ? "" : me)}>
              {owner ? (owner === me ? "✓ mine" : `owned: ${owner}`) : "claim"}
            </button>
            <label className="row" style={{ gap: 4, fontSize: 12, cursor: "pointer" }} title="mark this host reviewed for the team">
              <input type="checkbox" checked={reviewed} onChange={toggleReviewed} /> reviewed
            </label>
            {onScanHost && <button className="btn sm" title="scan this host (opens the enum launcher prefilled)" onClick={() => onScanHost(ip)}>⌖ scan host</button>}
            <button className="btn sm" title="proof-of-concept scripts for this host" onClick={() => setPbOpen(true)}>⚙ PoC</button>
          </div>
        )}
        {pbOpen && <PocModal scope="host" target={ip} title={h?.hostname || ip} onClose={() => setPbOpen(false)} />}

        {(editors.length > 0 || justViewing.length > 0) && (
          <div style={{ padding: "0 14px 6px", fontSize: 12, color: "var(--warn, #b45309)" }}
               title="other operators on this host right now">
            {editors.length > 0 && <span style={{ fontWeight: 600 }}>✏️ {editors.join(", ")} editing</span>}
            {editors.length > 0 && justViewing.length > 0 && <span> · </span>}
            {justViewing.length > 0 && <span>👁 {justViewing.join(", ")} here</span>}
          </div>
        )}

        <div className="drawer-body">
          {err && <div className="empty">{/404/.test(err)
            ? "Host not found — it may have been deleted, or its identifier is invalid."
            : err}</div>}
          {!h && !err && <div className="loading">Loading host…</div>}
          {h && (
            <>
              {(h.roles?.length > 0 || h.access || h.smb_signing) && (
                <div className="row wrap" style={{ gap: 6, marginBottom: 10 }}>
                  {h.roles?.map((r) => <span key={r} className="chip">{r}</span>)}
                  {h.access && <span className="chip on">access: {h.access_detail || "yes"}</span>}
                  {h.smb_signing && <span className="chip">smb signing: {h.smb_signing}</span>}
                </div>
              )}

              <label className="field" style={{ marginBottom: 12 }}>
                <span className="fl">Host note</span>
                <textarea className="fin" rows={2} value={note}
                          onChange={(e) => setNote(e.target.value)}
                          placeholder="shared note for this host…" />
                {note !== noteBase && <button className="btn sm primary" style={{ marginTop: 4, alignSelf: "flex-start" }} onClick={saveNote}>Save note</button>}
              </label>

              <h4 className="drawer-h">Services ({h.ports.length})</h4>
              {h.ports.length === 0 ? <Empty>No open ports.</Empty> : (
                <table className="tbl" style={{ marginBottom: 14 }}>
                  <tbody>
                    {h.ports.map((p) => (
                      <tr key={`${p.proto}/${p.port}`}>
                        <td className="mono" style={{ width: 70 }}>{p.port}/{p.proto}</td>
                        <td style={{ width: 90 }}>{p.service}</td>
                        <td className="muted">{[p.product, p.version].filter(Boolean).join(" ") || (p as { banner?: string }).banner || ""}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}

              <h4 className="drawer-h">Findings ({h.vulns.length})</h4>
              {h.vulns.length === 0 ? <Empty>No findings.</Empty> : (
                <div style={{ marginBottom: 14 }}>
                  {h.vulns.map((v) => (
                    <div key={v.key}
                         className={"row" + (onOpenFinding ? " click" : "")}
                         onClick={onOpenFinding ? () => { onOpenFinding(ip); onClose(); } : undefined}
                         title={onOpenFinding ? "open in Findings" : undefined}
                         style={{ gap: 8, padding: "5px 0", borderBottom: "1px solid color-mix(in srgb,var(--line) 55%,transparent)", alignItems: "baseline" }}>
                      <Sev s={v.severity} />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontWeight: 600 }}>{v.title}</div>
                        {(v.cve || v.remediation) && <div className="muted" style={{ fontSize: 11 }}>{v.cve}{v.cve && v.remediation ? " · " : ""}{v.remediation?.slice(0, 120)}</div>}
                      </div>
                      {v.kev && <span className="chip" style={{ color: "var(--kev)", borderColor: "var(--kev)" }}>KEV</span>}
                    </div>
                  ))}
                </div>
              )}

              <HostArtifacts ip={ip} />

              {h.accounts?.length > 0 && (
                <>
                  <h4 className="drawer-h">Accounts ({h.accounts.length})</h4>
                  <div style={{ marginBottom: 14 }}>
                    {h.accounts.slice(0, 40).map((a, i) => (
                      <div key={i} className="row" style={{ gap: 8, padding: "3px 0", fontSize: 12 }}>
                        <span className="chip">{a.kind}</span>
                        <span className="mono">{a.domain ? `${a.domain}\\` : ""}{a.name}</span>
                        <span className="muted">{a.detail}</span>
                      </div>
                    ))}
                    {h.accounts.length > 40 && <div className="faint" style={{ fontSize: 11, padding: "2px 0" }}>+{h.accounts.length - 40} more not shown</div>}
                  </div>
                </>
              )}

              {onOpenFinding && (
                <button className="btn" onClick={() => { onOpenFinding(ip); onClose(); }}>See host findings in Findings →</button>
              )}
            </>
          )}
        </div>
      </aside>
    </>
  );
}

// Artifacts pulled off this host via a shell session (files downloaded,
// captured outputs, screenshots, cred blobs). Written by the /download
// endpoint (async-C2 P0); async beacon results plug into the same rows
// in P1. Read-only for now — click a row to see its full path/hash/note.
function HostArtifacts({ ip }: { ip: string }) {
  const [arts, setArts] = useState<Artifact[]>([]);
  const [loaded, setLoaded] = useState(false);
  useEffect(() => {
    let cancel = false;
    getArtifacts({ host: ip, limit: 100 })
      .then((r) => { if (!cancel) { setArts(r.artifacts || []); setLoaded(true); } })
      .catch(() => { if (!cancel) setLoaded(true); });
    return () => { cancel = true; };
  }, [ip]);
  // Suppress the header until we know the count — avoids "Artifacts (0)"
  // flashing during load.
  if (!loaded) return null;
  if (arts.length === 0) return null;

  // Group by kind so the interesting ones (creds/screenshot) surface above
  // the bulk downloaded files — signal-first per webui-ux-preferences.
  const byKind: Record<string, Artifact[]> = {};
  for (const a of arts) (byKind[a.kind] ||= []).push(a);
  const kindOrder = ["cred-blob", "screenshot", "output", "file"];
  const ordered = kindOrder.filter((k) => byKind[k])
                           .concat(Object.keys(byKind).filter((k) => !kindOrder.includes(k)));

  return (
    <>
      <h4 className="drawer-h">Artifacts ({arts.length})</h4>
      <div style={{ marginBottom: 14 }}>
        {ordered.map((kind) => (
          <div key={kind} style={{ marginBottom: 6 }}>
            <div className="faint" style={{ fontSize: 11, padding: "2px 0" }}>
              {kind} ({byKind[kind].length})
            </div>
            {byKind[kind].map((a) => (
              <div key={a.id} className="row"
                   title={`${a.path}\nsha256: ${a.sha256 || "—"}\n${a.note || ""}`}
                   style={{ gap: 8, padding: "3px 0", fontSize: 12, alignItems: "baseline" }}>
                <span className="mono" style={{ flex: 1, overflow: "hidden",
                                                textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {a.path.split("/").pop() || a.path}
                </span>
                <span className="faint" style={{ fontSize: 10 }}>{a.bytes || 0}B</span>
                <span className="faint" style={{ fontSize: 10 }}>{a.captured_by || "—"}</span>
                {a.sha256 && (
                  <span className="mono faint"
                        style={{ fontSize: 10, cursor: "pointer" }}
                        title="click to copy sha256"
                        onClick={() => { navigator.clipboard?.writeText(a.sha256).catch(() => {}); }}>
                    {a.sha256.slice(0, 8)}…
                  </span>
                )}
              </div>
            ))}
          </div>
        ))}
      </div>
    </>
  );
}
