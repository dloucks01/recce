// Finding detail drawer — click a finding row to open it. Full context (output,
// remediation, QoD, verdict) + all the triage actions with room to breathe:
// reviewed, status, assignee, hot, dismiss, notes. Consistent with HostDrawer.
import { useEffect, useState } from "react";
import {
  Finding, VulnDetail, ProveResult, ExploitHint, RefInfo, getHost, getExploitHint, getRef, postProve,
  FINDING_STATUSES, FINDING_STATUS_LABEL, FindingStatus,
  setFindingStatus, setFindingAssignee, setFindingPriority, postTick, postNote,
  getArtifacts, Artifact,
} from "./api";
import { Sev } from "./kit";
import { useFocus } from "./useFocus";
import { NavCtx } from "./nav";
import { copyText } from "./util";
import { toast } from "./toast";
import { PocModal } from "./components/PocModal";

const HOT = (p?: string) => ["hot", "high"].includes((p || "").toLowerCase());

// Why a finding is (or isn't) trustworthy, in a sentence a tester can act on.
// version-db never touched the service; the rest were observed one way or another.
function provenance(f: Finding): { fp: boolean; text: string } {
  if (f.source === "version-db" || f.tier === "lead")
    return { fp: true, text: "Version/banner match only — recce compared a product + version banner against its vuln database but did NOT probe the live service. This is the most common false-positive source: verify before reporting." };
  if ((f.confidence || "").toLowerCase() === "potential")
    return { fp: true, text: "Heuristic match — flagged from indirect evidence, not a direct observation. Confirm before treating it as real." };
  const by: Record<string, string> = {
    nse: "an nmap NSE script", probe: "a recce service probe", web: "a recce web probe",
    smb: "a live SMB check", couchdb: "a live CouchDB check", oracle: "a live Oracle check",
    mysql: "a live MySQL check", postgres: "a live PostgreSQL check", mssql: "a live MSSQL check",
    mongodb: "a live MongoDB check", memcached: "a live Memcached check",
    influxdb: "a live InfluxDB check", cassandra: "a live Cassandra check", db2: "a live DB2 check",
  };
  const src = by[f.source] || `a ${f.source || "recce"} check`;
  return { fp: false, text: `Observed directly by ${src}` + (f.verdict ? ` · prove verdict: ${f.verdict.toLowerCase()}.` : ".") };
}

export function FindingDrawer({ finding, me, owners, hostClaim, dismissed, cluster = [], nav, onClose, onDismiss, onOpenSibling, mutate }:
  {
    finding: Finding; me: string; owners: string[]; hostClaim: string;
    dismissed: boolean; cluster?: Finding[]; nav?: NavCtx;
    onClose: () => void; onDismiss: (on: boolean) => void;
    onOpenSibling?: (key: string) => void;
    mutate: (o: Partial<Finding>) => void;   // optimistic list patch
  }) {
  const x = finding;
  const prov = provenance(x);
  const siblings = cluster.filter((f) => f.key !== x.key);
  const [detail, setDetail] = useState<VulnDetail | null>(null);
  // "Lead somewhere": a live prove verdict and an exploit-module hint, both
  // fetched lazily when the drawer opens. Prove verifies the finding in place;
  // the hint powers a one-click hop to Sessions with the msf module in hand.
  const [prove, setProve] = useState<ProveResult | null>(null);
  const [proving, setProving] = useState(false);
  const [hint, setHint] = useState<ExploitHint["hint"]>(null);
  const [pbOpen, setPbOpen] = useState(false);
  // Click a CVE/CWE chip → its offline reference detail (name / KEV / EPSS).
  const [ref, setRefInfo] = useState<RefInfo | null>(null);
  const [note, setNote] = useState(x.notes || "");
  const [noteConflict, setNoteConflict] = useState(false);
  const [editingNote, setEditingNote] = useState(false);        // advisory edit soft-lock
  const { viewers, editors } = useFocus(`finding:${x.key}`, editingNote);
  const justViewing = viewers.filter((v) => !editors.includes(v));

  // Compare-and-swap save: pass the note we loaded as the base so a concurrent
  // edit by another operator is detected (409) instead of silently overwritten.
  const saveNote = async () => {
    mutate({ notes: note });
    const r = await postNote(x.key, note, x.notes || "").catch(() => null);
    if (r && "conflict" in r) {
      setNoteConflict(true);        // surface their version; user re-saves to override
      setNote(r.notes);
      mutate({ notes: r.notes });
    } else {
      setNoteConflict(false);
    }
  };

  useEffect(() => { setNote(x.notes || ""); setNoteConflict(false); setProve(null); setHint(null); setRefInfo(null); }, [x.key]);
  useEffect(() => {
    let cancel = false;
    setDetail(null);
    getHost(x.ip).then((h) => { if (!cancel) setDetail(h.vulns.find((v) => v.key === x.key) || null); }).catch(() => {});
    // Does this finding have a proof recipe / an msf module? Decides which
    // "next step" buttons render. Best-effort — silence means "no".
    getExploitHint(x.key).then((h) => { if (!cancel) setHint(h.hint); }).catch(() => {});
    return () => { cancel = true; };
  }, [x.key, x.ip]);

  const runProve = async () => {
    setProving(true);
    try {
      const r = await postProve(x.key);
      setProve(r);
      // Persist to the row so the badge + provenance line reflect it everywhere.
      mutate({ verdict: r.verdict, verdict_evidence: r.evidence, verdict_finish: r.finish });
      toast.show(`prove: ${(r.verdict || "").toLowerCase() || "done"}`);
    } catch { toast.show("prove failed"); }
    finally { setProving(false); }
  };
  const goHost = () => { onClose(); nav?.openHost(x.ip); };
  const getShell = async () => {
    if (hint?.module) await copyText(hint.module);
    toast.show(hint?.module ? "msf module copied — opening Sessions" : "opening Sessions");
    onClose(); nav?.go("sessions");
  };
  useEffect(() => {
    const k = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-label={x.title}>
        <div className="drawer-head">
          <div className="row" style={{ gap: 8, minWidth: 0 }}>
            <Sev s={x.severity} />
            <div style={{ minWidth: 0 }}>
              <div style={{ fontWeight: 700 }}>{x.title}</div>
              <div className="muted mono" style={{ fontSize: 12 }}>{x.ip}{x.port ? `:${x.port}` : ""}{x.cve ? ` · ${x.cve}` : ""}</div>
            </div>
          </div>
          <button className="icon-btn" onClick={onClose} title="close (Esc)">✕</button>
        </div>
        {(editors.length > 0 || justViewing.length > 0) && (
          <div style={{ padding: "4px 14px", fontSize: 12 }}
               title="other operators on this finding right now">
            {editors.length > 0 && (
              <span style={{ color: "var(--warn, #b45309)", fontWeight: 600 }}>✏️ {editors.join(", ")} editing</span>
            )}
            {editors.length > 0 && justViewing.length > 0 && <span> · </span>}
            {justViewing.length > 0 && <span style={{ color: "var(--warn, #b45309)" }}>👁 {justViewing.join(", ")} here</span>}
          </div>
        )}

        <div className="drawer-body">
          {/* Provenance — is this real, or a banner-guess false positive? First
              thing a triager needs to know. */}
          <div style={{
            marginBottom: 12, padding: "8px 10px", borderRadius: 6, fontSize: 12,
            border: "1px solid " + (prov.fp ? "var(--warn, #b45309)" : "var(--ok)"),
            background: prov.fp ? "color-mix(in srgb, var(--warn) 10%, transparent)" : "color-mix(in srgb, var(--ok) 10%, transparent)",
            color: prov.fp ? "var(--warn, #b45309)" : "var(--ok)",
          }}>
            <b>{prov.fp ? "⚠ Likely false positive" : "✓ Observed"}</b> — {prov.text}
          </div>

          {/* Next steps — a finding should lead somewhere. Verify it, jump to the
              host in context, or hand it to Sessions to get a shell. */}
          {nav && (
            <div className="row wrap" style={{ gap: 6, marginBottom: 12 }}>
              <button className="btn sm" onClick={goHost} title="open this host in the Hosts tab">→ Open host</button>
              {hint !== null && (
                <button className="btn sm" onClick={runProve} disabled={proving}
                        title="run the T2 verification recipe now">
                  {proving ? "proving…" : (prove || x.verdict) ? "↺ Re-prove" : "✓ Prove"}
                </button>
              )}
              {hint?.module && (
                <button className="btn sm primary" onClick={getShell}
                        title={`Metasploit: ${hint.module}`}>🎯 Get shell</button>
              )}
              {!prov.fp && (
                <button className="btn sm" onClick={() => { onClose(); nav.toExploit({ key: x.key, target: `${x.ip}${x.port ? ":" + x.port : ""}` }); }}
                        title="jump to this finding in the prioritized exploit plan">Exploit plan →</button>
              )}
              {!prov.fp && (
                <button className="btn sm" onClick={() => setPbOpen(true)}
                        title="proof-of-concept scripts for this finding's host">⚙ PoC</button>
              )}
            </div>
          )}
          {pbOpen && <PocModal scope="finding" target={x.key} title={x.title} onClose={() => setPbOpen(false)} />}

          {/* Actions */}
          <div className="panel" style={{ marginBottom: 12 }}>
            <div className="row wrap" style={{ gap: 10, alignItems: "center" }}>
              <label className="row" style={{ gap: 6 }}>
                <input type="checkbox" checked={x.reviewed}
                       onChange={() => { mutate({ reviewed: !x.reviewed, reviewed_by: !x.reviewed ? me : "" }); postTick(x.key, !x.reviewed).catch(() => {}); }} />
                <span>Reviewed{x.reviewed && x.reviewed_by ? ` · ${x.reviewed_by === me ? "you" : x.reviewed_by}` : ""}</span>
              </label>
              <button className="btn sm" title="team hot list"
                      style={{ filter: HOT(x.priority) ? "none" : "grayscale(1) opacity(.5)" }}
                      onClick={() => { const on = !HOT(x.priority); mutate({ priority: on ? "hot" : "" }); setFindingPriority(x.key, on ? "hot" : "").catch(() => {}); }}>
                🔥 {HOT(x.priority) ? "On hot list" : "Flag hot"}
              </button>
              <button className={"btn sm" + (dismissed ? " primary" : " danger")} onClick={() => onDismiss(!dismissed)}>
                {dismissed ? "Restore" : "✗ Dismiss (not a finding)"}
              </button>
            </div>
            <div className="row wrap" style={{ gap: 10, marginTop: 10 }}>
              <label className="row" style={{ gap: 6 }}><span className="muted">Status</span>
                <select className="btn sm" value={x.status || ""}
                        onChange={(e) => { const s = e.target.value as FindingStatus; mutate({ status: s }); setFindingStatus(x.key, s).catch(() => {}); }}>
                  {FINDING_STATUSES.map((s) => <option key={s} value={s}>{FINDING_STATUS_LABEL[s]}</option>)}
                </select>
              </label>
              <label className="row" style={{ gap: 6 }}><span className="muted">Owner</span>
                <select className="btn sm" value={x.assignee || ""}
                        onChange={(e) => { mutate({ assignee: e.target.value }); setFindingAssignee(x.key, e.target.value).catch(() => {}); }}>
                  <option value="">{hostClaim ? `↳ ${hostClaim} (host)` : "unassigned"}</option>
                  <option value={me}>{me} (you)</option>
                  {owners.map((n) => <option key={n} value={n}>{n}</option>)}
                </select>
              </label>
            </div>
          </div>

          {/* Meta chips */}
          <div className="row wrap" style={{ gap: 6, marginBottom: 12 }}>
            <span className="chip">tier: {x.tier}</span>
            {x.kev && <span className="chip" style={{ color: "var(--kev)", borderColor: "var(--kev)" }}
                            title="CISA Known Exploited Vulnerabilities — seen exploited in the wild">KEV — known exploited</span>}
            {x.epss > 0 && <span className="chip" title="EPSS — probability of exploitation in the next 30 days">EPSS {x.epss}%</span>}
            {x.verdict && <span className="chip on">{x.verdict.toLowerCase()}</span>}
            {x.sources && x.sources.length > 1 && <span className="chip">{x.sources.length} sources</span>}
          </div>

          {/* References — tie the finding back to its CVE(s) / CWE(s). Airgapped
              by design: identifiers, not links — nothing reaches the network.
              Click a chip for offline detail (CWE weakness name, CVE KEV + EPSS)
              pulled from recce's bundled catalogues. */}
          {(() => {
            const cves = [...new Set([x.cve, ...(x.cves || [])].filter(Boolean))];
            const cwes = [...new Set((detail?.cwes || []).filter(Boolean))];
            if (cves.length === 0 && cwes.length === 0) return null;
            const showRef = (id: string) => {
              if (ref?.id === id) { setRefInfo(null); return; }   // toggle off
              setRefInfo({ kind: id.startsWith("CWE") ? "cwe" : "cve", id });   // optimistic
              getRef(id).then(setRefInfo).catch(() => setRefInfo({ kind: "cve", id, name: "" }));
            };
            const chip = (id: string, kev = false) => (
              <button key={id} className={"chip mono click" + (ref?.id === id ? " on" : "")}
                      onClick={() => showRef(id)} title="click for offline detail">
                {id}{kev ? " ⚑" : ""}
              </button>
            );
            return (
              <>
                <h4 className="drawer-h">References</h4>
                <div className="row wrap" style={{ gap: 6, marginBottom: ref ? 6 : 14 }}>
                  {cves.map((c) => chip(c, x.kev))}
                  {cwes.map((c) => chip(c))}
                </div>
                {ref && (
                  <div style={{ marginBottom: 14, padding: "8px 10px", borderRadius: 6, border: "1px solid var(--line)", background: "var(--surface2)", fontSize: 12 }}>
                    <div className="row" style={{ gap: 6, alignItems: "baseline" }}>
                      <b className="mono">{ref.id}</b>
                      <button className="linkish right" style={{ fontSize: 11 }}
                              onClick={() => copyText(ref.id).then((ok) => toast.show(ok ? `copied ${ref.id}` : "copy failed"))}>copy</button>
                    </div>
                    {ref.kind === "cwe" ? (
                      <div style={{ marginTop: 4 }}>{ref.name ? ref.name : <span className="muted">No offline name for this weakness id.</span>}
                        <div className="faint" style={{ marginTop: 2 }}>CWE — Common Weakness Enumeration (MITRE weakness class).</div>
                      </div>
                    ) : (
                      <div style={{ marginTop: 4 }}>
                        <div className="row wrap">
                          {ref.severity && <span style={{ fontWeight: 600 }} title="recce's severity assessment for this finding">severity {ref.severity}</span>}
                          {ref.cvss != null && <span className="muted" title="NVD CVSS base score (may differ from recce's severity)">{ref.severity ? " · " : ""}NVD CVSS {ref.cvss}</span>}
                          {ref.kev
                            ? <span title="CISA Known Exploited Vulnerabilities catalog" style={{ color: "var(--kev)", fontWeight: 600 }}> · ⚑ In CISA KEV — Known Exploited Vulnerabilities (seen exploited in the wild)</span>
                            : <span className="muted"> · not in CISA KEV</span>}
                          {ref.epss != null && ref.epss > 0 && <span className="muted"> · EPSS {ref.epss}% (exploitation probability, next 30 days)</span>}
                        </div>
                        {ref.desc && <div style={{ marginTop: 6 }}>{ref.desc}</div>}
                        {ref.exploit && <div style={{ marginTop: 6 }}><b>Public exploit:</b> <span className="mono" style={{ fontSize: 11 }}>{ref.exploit}</span></div>}
                        {ref.remediation && <div style={{ marginTop: 6 }}><b>Fix:</b> {ref.remediation}</div>}
                        {(ref.cwe && ref.cwe.length > 0) && <div className="faint" style={{ marginTop: 6 }}>Weakness: {ref.cwe.join(", ")}</div>}
                        {ref.source && <div className="faint" style={{ marginTop: 6, fontSize: 11 }}>source: {ref.source} (offline snapshot)</div>}
                        {!ref.desc && !ref.exploit && !ref.remediation && ref.cvss == null && (
                          <div className="faint" style={{ marginTop: 6 }}>
                            No offline detail for this id. recce ships KEV/EPSS + a curated vuln DB; for full
                            per-CVE detail install the optional CVE data pack (tools/build_cve_db.py).
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </>
            );
          })()}

          {/* Notes */}
          <h4 className="drawer-h">Note</h4>
          <div style={{ marginBottom: noteConflict ? 4 : 14 }}>
            <textarea className="fin" rows={2} placeholder="add a shared note… (Ctrl/⌘+Enter to save)" value={note}
                      onFocus={() => setEditingNote(true)}
                      onBlur={() => setEditingNote(false)}
                      onChange={(e) => { setNote(e.target.value); if (noteConflict) setNoteConflict(false); }}
                      onKeyDown={(e) => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) saveNote(); }} />
            <button className="btn sm" style={{ marginTop: 4 }} disabled={note === (x.notes || "")} onClick={saveNote}>Save note</button>
          </div>
          {noteConflict && (
            <div style={{ color: "var(--warn, #b45309)", fontSize: 12, marginBottom: 12 }}>
              Another operator edited this note — showing their version. Edit and Save again to override.
            </div>
          )}

          {/* Affected hosts — this same issue on the rest of the fleet. Click to
              jump the drawer to that host's copy without leaving the tab. */}
          {siblings.length > 0 && (
            <>
              <h4 className="drawer-h">Also on {siblings.length} other host{siblings.length === 1 ? "" : "s"}</h4>
              <div className="row wrap" style={{ gap: 6, marginBottom: 14 }}>
                {siblings.map((s) => (
                  <button key={s.key} className={"chip mono" + (onOpenSibling ? " click" : "")}
                          title={s.reviewed ? `reviewed by ${s.reviewed_by || "someone"}` : "open this host"}
                          onClick={() => onOpenSibling?.(s.key)}>
                    {s.reviewed ? "✓ " : ""}{s.ip}{s.port ? `:${s.port}` : ""}
                  </button>
                ))}
              </div>
            </>
          )}

          <FindingArtifacts findingKey={x.key} />

          {/* Evidence — what recce actually observed. This is the proof a tester
              pastes into the report; verdict evidence (from Prove) sits above the
              raw scan output. */}
          <h4 className="drawer-h">Evidence</h4>
          {(() => {
            const verdictEv = (prove?.evidence && prove.evidence.length ? prove.evidence : x.verdict_evidence) || [];
            const finish = prove?.finish || x.verdict_finish || "";
            const verdict = prove?.verdict || x.verdict || "";
            return (
              <>
                {verdict && (
                  <div style={{ marginBottom: 10, padding: "8px 10px", borderRadius: 6, border: "1px solid var(--line)", background: "var(--surface2)" }}>
                    <div className="row" style={{ gap: 6, marginBottom: verdictEv.length ? 6 : 0 }}>
                      <b style={{ fontSize: 12 }}>Prove verdict</b>
                      <span className="stbadge">{verdict.toLowerCase()}</span>
                    </div>
                    {verdictEv.length > 0 && (
                      <ul style={{ margin: 0, paddingLeft: 16, fontSize: 12 }}>
                        {verdictEv.map((e, i) => <li key={i}>{e}</li>)}
                      </ul>
                    )}
                    {finish && (
                      <div className="row" style={{ gap: 6, marginTop: 8, alignItems: "center" }}>
                        <code className="mono" style={{ flex: 1, fontSize: 11, wordBreak: "break-all", background: "var(--ground)", padding: "3px 6px", borderRadius: 4 }}>{finish}</code>
                        <button className="btn sm" onClick={() => copyText(finish).then((ok) => toast.show(ok ? "copied" : "copy failed"))}>copy</button>
                      </div>
                    )}
                  </div>
                )}
                {detail == null ? <div className="loading">Loading…</div> : (
                  <>
                    {detail.output
                      ? <pre style={{ margin: 0, padding: 10, background: "var(--surface2)", border: "1px solid var(--line)", borderRadius: 6, fontSize: 11, maxHeight: 320, overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-word" }}>{detail.output.slice(0, 8000)}</pre>
                      : <div className="muted">No scan output recorded — {prov.fp ? "this is a banner/version inference, not a live capture. Prove or verify manually." : "the detector flagged this without capturing raw output."}</div>}
                    {detail.remediation && <div style={{ marginTop: 10 }}><b>Fix:</b> {detail.remediation}</div>}
                    {detail.qod > 0 && <div className="muted" style={{ marginTop: 6, fontSize: 12 }}>QoD {detail.qod} ({detail.qod_type})</div>}
                  </>
                )}
              </>
            );
          })()}
        </div>
      </aside>
    </>
  );
}

// Captured artifacts auto-linked to this finding (async-C2 P2). The
// download / beacon-result flow runs recce.act.artifact_link.link_artifact
// server-side and stamps artifact.finding_id when the command/path bridges
// to a keyword in this finding's title/script_id/output. Renders nothing
// when there's nothing to show — a fresh finding stays uncluttered.
function FindingArtifacts({ findingKey }: { findingKey: string }) {
  const [arts, setArts] = useState<Artifact[]>([]);
  const [loaded, setLoaded] = useState(false);
  useEffect(() => {
    let cancel = false;
    getArtifacts({ finding: findingKey, limit: 50 })
      .then((r) => { if (!cancel) { setArts(r.artifacts || []); setLoaded(true); } })
      .catch(() => { if (!cancel) setLoaded(true); });
    return () => { cancel = true; };
  }, [findingKey]);
  if (!loaded) return null;
  if (arts.length === 0) return null;
  return (
    <>
      <h4 className="drawer-h">
        Captured artifacts ({arts.length})
        <span className="faint" style={{ fontWeight: 400, fontSize: 11, marginLeft: 6 }}>
          — pulled off the target and auto-linked to this finding
        </span>
      </h4>
      <div style={{ marginBottom: 12 }}>
        {arts.map((a) => (
          <div key={a.id} className="row"
               title={`${a.path}\nsha256: ${a.sha256 || "—"}\n${a.note || ""}`}
               style={{ gap: 8, padding: "3px 0", fontSize: 12, alignItems: "baseline",
                        borderBottom: "1px solid color-mix(in srgb,var(--line) 40%,transparent)" }}>
            <span className="chip" style={{ fontSize: 10 }}>{a.kind}</span>
            <span className="mono" style={{ flex: 1, overflow: "hidden",
                                            textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
              {a.path.split("/").pop() || a.path}
            </span>
            <span className="faint" style={{ fontSize: 10 }}>{a.bytes || 0}B</span>
            <span className="faint" style={{ fontSize: 10 }}>{a.captured_by || "—"}</span>
            {a.sha256 && (
              <span className="mono faint" title="click to copy sha256"
                    style={{ fontSize: 10, cursor: "pointer" }}
                    onClick={() => { navigator.clipboard?.writeText(a.sha256).catch(() => {}); }}>
                {a.sha256.slice(0, 8)}…
              </span>
            )}
          </div>
        ))}
      </div>
    </>
  );
}
