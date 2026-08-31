// Phase D — AD attack chain walkthrough.
//
// A single narrative that walks a tester through the whole AD compromise
// with current engagement state visible at each step. Every step reads
// from the same shared-surface unions the KnownAssets tab uses, plus
// per-service finding kinds (null_session, ldap_anon_read, asrep_roast,
// msrpc_coercion, kerberos_spray_success, adcs-esc*). Where Phase C
// showed exploitation per-finding, this view shows the story per-chain.
import { useEffect, useState } from "react";
import {
  getAttackChainAd, AttackChainAdResponse, AttackChainStep,
  AttackChainStepStatus,
} from "../api";

const STATUS_META: Record<AttackChainStepStatus, {
  icon: string; color: string; label: string; bg: string;
}> = {
  proven:  { icon: "✓", color: "#16a34a", bg: "#dcfce7", label: "proven" },
  pending: { icon: "○", color: "#d97706", bg: "#fef3c7", label: "pending" },
  blocked: { icon: "⊗", color: "#dc2626", bg: "#fee2e2", label: "blocked" },
  skipped: { icon: "—", color: "#8892a0", bg: "#e5e7eb", label: "skipped" },
};

// Copy-to-clipboard with a graceful fallback for browsers where
// navigator.clipboard is unavailable (older Chrome without HTTPS, or a
// permissions-denied context). Same shape as ExploitSurface's copy.
async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch { /* fall through */ }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.top = "-1000px";
    document.body.appendChild(ta);
    ta.focus(); ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}

function CopyBtn({ text }: { text: string }) {
  const [state, setState] = useState<"idle" | "ok" | "err">("idle");
  async function onClick() {
    const ok = await copyText(text);
    setState(ok ? "ok" : "err");
    setTimeout(() => setState("idle"), 1500);
  }
  return (
    <button className="cred-cmd-copy" onClick={onClick}
            title="copy next-step advisory to clipboard">
      {state === "ok" ? "✓ copied"
        : state === "err" ? "! copy failed" : "📋 Copy"}
    </button>
  );
}

function StatusBadge({ status }: { status: AttackChainStepStatus }) {
  const m = STATUS_META[status];
  return (
    <span title={m.label}
          style={{
            display: "inline-flex", alignItems: "center", gap: 6,
            padding: "3px 10px", borderRadius: 999,
            fontFamily: "var(--mono)", fontSize: 11, fontWeight: 700,
            color: m.color, background: m.bg, whiteSpace: "nowrap",
            border: `1px solid ${m.color}33`,
          }}>
      <span style={{ fontSize: 13, lineHeight: 1 }}>{m.icon}</span>
      {m.label.toUpperCase()}
    </span>
  );
}

// Circular step-marker with icon + step number. Colored to match status.
function StepMarker({ status, n }: { status: AttackChainStepStatus; n: number }) {
  const m = STATUS_META[status];
  return (
    <div style={{
      width: 34, height: 34, borderRadius: "50%",
      background: m.color, color: "#fff",
      display: "flex", alignItems: "center", justifyContent: "center",
      fontFamily: "var(--mono)", fontSize: 13, fontWeight: 700,
      flexShrink: 0, zIndex: 1, boxShadow: `0 0 0 4px var(--surface)`,
    }} title={`step ${n} — ${m.label}`}>
      {status === "proven" ? m.icon : n}
    </div>
  );
}

function NextStepBlock({ text }: { text: string }) {
  if (!text) return null;
  return (
    <div style={{
      display: "flex", gap: 8, alignItems: "flex-start", marginTop: 6,
    }}>
      <pre style={{
        margin: 0, padding: "6px 10px", background: "var(--surface2)",
        border: "1px solid var(--line)", borderRadius: 6,
        fontFamily: "var(--mono)", fontSize: 12, color: "var(--text)",
        whiteSpace: "pre-wrap", wordBreak: "break-word", flex: 1,
      }}>{text}</pre>
      <CopyBtn text={text} />
    </div>
  );
}

interface StepCardProps {
  step: AttackChainStep;
  n: number;
  onOpenHost: (ip: string) => void;
  isLast: boolean;
}
function StepCard({ step, n, onOpenHost, isLast }: StepCardProps) {
  // Proven steps default-collapsed (the check is the whole story); pending
  // + blocked default-open so the tester sees the advisory without a click.
  const [open, setOpen] = useState(step.status !== "proven");
  const m = STATUS_META[step.status];
  return (
    <div style={{ display: "flex", gap: 12, position: "relative" }}>
      {/* Vertical timeline line — drawn behind the marker; hidden on the last step. */}
      {!isLast && (
        <div aria-hidden="true" style={{
          position: "absolute", left: 17, top: 34, bottom: -12, width: 2,
          background: "var(--line)", zIndex: 0,
        }} />
      )}
      <StepMarker status={step.status} n={n} />
      <div className="panel" style={{
        flex: 1, marginBottom: 12,
        borderLeft: `3px solid ${m.color}`,
      }}>
        <div className="panel-h" style={{
          cursor: "pointer", display: "flex", gap: 10,
          alignItems: "center", justifyContent: "space-between",
        }} onClick={() => setOpen(!open)}>
          <div style={{ display: "flex", gap: 10, alignItems: "center",
                        flexWrap: "wrap" }}>
            <h3 style={{ margin: 0 }}>{step.title}</h3>
            <StatusBadge status={step.status} />
            {step.evidence.length > 0 && (
              <span className="muted" style={{ fontSize: 12 }}>
                {step.evidence.length} evidence row{step.evidence.length === 1 ? "" : "s"}
              </span>
            )}
          </div>
          <span className="muted" style={{ fontSize: 12 }}>{open ? "▾" : "▸"}</span>
        </div>
        {open && (
          <div style={{ padding: "0 12px 12px 12px" }}>
            {step.depends_on.length > 0 && (
              <div className="muted" style={{ fontSize: 11, marginBottom: 6 }}>
                depends on: {step.depends_on.join(", ")}
              </div>
            )}
            {step.shared_surfaces_read.length > 0 && (
              <div className="muted" style={{ fontSize: 11, marginBottom: 6 }}>
                reads: {step.shared_surfaces_read.map((s) => (
                  <span key={s} className="mono" style={{
                    display: "inline-block", padding: "1px 6px", marginRight: 4,
                    background: "var(--surface2)", borderRadius: 4,
                    fontSize: 10,
                  }}>{s}</span>
                ))}
              </div>
            )}

            {step.evidence.length > 0 ? (
              <div style={{ marginTop: 6 }}>
                <div className="muted" style={{ fontSize: 11, marginBottom: 4 }}>
                  Evidence:
                </div>
                <div className="tablewrap">
                  <table className="loottable">
                    <thead><tr>
                      <th style={{ width: 160 }}>Finding</th>
                      <th style={{ width: 120 }}>Endpoint</th>
                      <th>Excerpt</th>
                    </tr></thead>
                    <tbody>
                      {step.evidence.slice(0, 12).map((e, i) => {
                        const endpoint = e.ip
                          ? (e.port ? `${e.ip}:${e.port}` : e.ip)
                          : "—";
                        return (
                          <tr key={`${e.finding_kind}-${i}`}>
                            <td className="mono" style={{ fontSize: 11 }}>
                              {e.finding_kind}
                            </td>
                            <td className="mono" style={{ fontSize: 11 }}>
                              {e.ip ? (
                                <a href="#" onClick={(ev) => {
                                  ev.preventDefault(); onOpenHost(e.ip);
                                }}>{endpoint}</a>
                              ) : endpoint}
                            </td>
                            <td style={{ fontSize: 12 }}>
                              {e.output_excerpt || <span className="muted">(no output)</span>}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                No evidence yet.
              </div>
            )}

            {step.next_step && (
              <div style={{ marginTop: 10 }}>
                <div className="muted" style={{ fontSize: 11, marginBottom: 4 }}>
                  Your next move:
                </div>
                <NextStepBlock text={step.next_step} />
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

interface Props {
  onOpenHost?: (ip: string) => void;
}
export function AttackChain({ onOpenHost }: Props = {}) {
  const [data, setData] = useState<AttackChainAdResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true); setErr(null);
    getAttackChainAd()
      .then((d) => { if (!cancelled) { setData(d); setLoading(false); } })
      .catch((e) => { if (!cancelled) { setErr(String(e)); setLoading(false); } });
    return () => { cancelled = true; };
  }, []);

  const openHost = onOpenHost || ((_ip: string) => { /* no-op fallback */ });

  if (loading) return <div className="loading">Loading AD attack chain…</div>;
  if (err) return <div className="err">{err}</div>;
  if (!data) return null;

  const { steps, summary } = data;
  const pctProven = summary.total > 0
    ? Math.round((summary.proven / summary.total) * 100) : 0;

  return (
    <div className="lootview">
      {/* Hero — "your next action" + overall progress. */}
      <section className="panel" style={{ borderLeft: "3px solid var(--accent)" }}>
        <div className="panel-h">
          <h3>
            AD chain — {summary.proven} of {summary.total} steps proven
          </h3>
          <span className="muted">
            {summary.pending} pending
            {summary.blocked > 0 && <> · {summary.blocked} blocked</>}
          </span>
        </div>
        <div style={{ padding: "0 12px 12px 12px" }}>
          {/* Progress bar. */}
          <div style={{
            height: 10, background: "var(--surface2)", borderRadius: 6,
            overflow: "hidden", marginBottom: 12,
            border: "1px solid var(--line)",
          }}>
            <div style={{
              width: `${pctProven}%`, height: "100%",
              background: STATUS_META.proven.color,
              transition: "width 250ms ease-out",
            }} />
          </div>

          {summary.next_action ? (
            <>
              <div className="muted" style={{ fontSize: 11, marginBottom: 4 }}>
                Your next action:
              </div>
              <NextStepBlock text={summary.next_action} />
              {summary.highest_reached && (
                <div className="muted" style={{ fontSize: 11, marginTop: 8 }}>
                  Furthest proven: <span className="mono">{summary.highest_reached}</span>
                </div>
              )}
            </>
          ) : (
            <div className="muted">
              Every step is proven — full AD compromise reachable end-to-end.
            </div>
          )}
        </div>
      </section>

      {/* Timeline of steps. */}
      <section className="panel" style={{ background: "transparent", padding: 0 }}>
        <div style={{ padding: "8px 0" }}>
          {steps.map((s, i) => (
            <StepCard key={s.id} step={s} n={i + 1}
                      onOpenHost={openHost} isLast={i === steps.length - 1} />
          ))}
        </div>
      </section>
    </div>
  );
}
