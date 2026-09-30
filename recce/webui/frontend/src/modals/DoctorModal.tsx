import { useCallback, useEffect, useState } from "react";
import { Modal } from "../ui";
import { DoctorIssue, DoctorState, getIssues, postDoctor } from "../api";
import { toast } from "../toast";

/**
 * Doctor modal — surfaces `/api/issues` (the engagement audit's persistent
 * findings list) and lets the tester re-run the audit via `/api/doctor`.
 * Written up to now was CLI-only (`recce doctor`); the endpoint always
 * existed, this just puts a button on it.
 */
export function DoctorModal({ onClose }: { onClose: () => void }) {
  const [state, setState] = useState<DoctorState | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>("");

  const refresh = useCallback(async () => {
    try {
      const s = await getIssues();
      setState(s);
      setErr("");
    } catch (e) {
      setErr((e as Error).message);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const rerun = async () => {
    setBusy(true);
    try {
      await postDoctor();
      toast.show("Doctor re-run kicked off");
      // Poll a couple times so the new issues list catches up.
      setTimeout(refresh, 800);
      setTimeout(refresh, 2500);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const issues = state?.issues || [];
  const counts = state?.counts || {};
  const grouped: Record<string, DoctorIssue[]> = {};
  for (const i of issues) {
    (grouped[i.severity] || (grouped[i.severity] = [])).push(i);
  }
  const sevOrder = ["critical", "high", "medium", "low", "info", "warn", "error", "incomplete"];
  const severities = Object.keys(grouped).sort(
    (a, b) => sevOrder.indexOf(a) - sevOrder.indexOf(b));

  return (
    <Modal title="Engagement Doctor"
           subtitle="Audits the engagement for missing scans, stale data, and skipped phases."
           onClose={onClose} size="lg"
           headerActions={
             <button className="btn primary" onClick={rerun} disabled={busy}>
               {busy ? "Running…" : "Re-run doctor"}
             </button>
           }>
      {err && <div className="error-banner">{err}</div>}
      {state === null && !err && <div className="empty">Loading issues…</div>}
      {state !== null && issues.length === 0 && (
        <div className="empty">
          <strong>All clear.</strong> The engagement passes every audit rule.
        </div>
      )}
      {issues.length > 0 && (
        <>
          <div className="doctor-counts">
            {sevOrder.filter(s => counts[s]).map(s =>
              <span key={s} className={`badge ${s}`}>{counts[s]} {s}</span>
            )}
          </div>
          {severities.map(sev => (
            <div key={sev} className="doctor-group">
              <h4>{sev.toUpperCase()} — {grouped[sev].length}</h4>
              <ul className="doctor-list">
                {grouped[sev].map((iss, idx) => (
                  <li key={idx} className={`doctor-item sev-${sev}`}>
                    <div className="doctor-kind">{iss.kind}</div>
                    <div className="doctor-msg">{iss.message}</div>
                    {iss.hint && <div className="doctor-hint">→ {iss.hint}</div>}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </>
      )}
    </Modal>
  );
}
