import { useEffect, useMemo, useState } from "react";
import {
  AdcsEsc1Available, AdcsEsc1AttemptResult, AdcsEsc1MatchingCred,
  getAdcsEsc1Available, postAdcsEsc1Attempt,
} from "../api";

/**
 * P1-7 frontend: modal that fires `POST /api/adcs/esc1/attempt` for the
 * AD attack-chain's `adcs_esc` step. The endpoint (see
 * `recce/webui/routes/adcs_esc1.py`) enforces three gating layers —
 * every one of them shows up in this modal:
 *
 *   1. **`confirm_sentinel`** — the exact string the operator must send
 *      back. Fetched via /available on mount so the button never
 *      hard-codes a stale value. When the operator clicks the intrusive
 *      "Run certipy" button, that string is what lands in the request
 *      body. If /available is unreachable we render an explicit error;
 *      no fallback fires.
 *   2. **matching_creds from the store** — the modal's principal picker
 *      is populated from /available's `matching_creds` list. The tester
 *      cannot type an ad-hoc password — recce looks the credential up
 *      by (username, domain) at request time.
 *   3. **certipy install** — when `tool_installed` is false the whole
 *      form is disabled and the modal renders the install command
 *      (`pip install certipy-ad`) inline.
 *
 * Deliberately kept as one small self-contained file: it's rendered
 * from a single StepCard branch in `views/AttackChain.tsx` and has no
 * cross-tab wiring.
 */
interface Props {
  templateHint?: string;                 // ADCS ESC finding often names the template
  caHint?: string;                       // finding may name the CA
  dcIpHint?: string;                     // AD chain knows the DC ip
  domainHint?: string;                   // AD chain knows the domain (e.g. corp.local)
  onClose: () => void;
  onSuccess?: (r: AdcsEsc1AttemptResult) => void;
  tester?: string;
}

export function Esc1RequestModal(
  { templateHint = "", caHint = "", dcIpHint = "", domainHint = "",
    onClose, onSuccess, tester }: Props
) {
  const [avail, setAvail] = useState<AdcsEsc1Available | null>(null);
  const [availErr, setAvailErr] = useState<string | null>(null);

  const [template, setTemplate] = useState(templateHint);
  const [ca, setCa] = useState(caHint);
  const [dcIp, setDcIp] = useState(dcIpHint);
  const [domain, setDomain] = useState(domainHint);
  const [credIdx, setCredIdx] = useState<number>(-1);
  const [upnTarget, setUpnTarget] = useState(
    domainHint ? `administrator@${domainHint}` : "administrator@");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<AdcsEsc1AttemptResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Fetch enabling state on mount — every render of the modal starts
  // with a fresh /available call so stale confirm_sentinels can never
  // be replayed from a prior mount.
  useEffect(() => {
    getAdcsEsc1Available()
      .then((a) => {
        setAvail(a);
        // Default-select a credential matching the AD-chain hints if one
        // exists (usually there IS one — the chain doesn't reach
        // `adcs_esc` without cred_acquired being proven).
        if (a.matching_creds.length && credIdx === -1) {
          const preferred = a.matching_creds.findIndex((c) =>
            domainHint && c.domain.toLowerCase() === domainHint.toLowerCase());
          setCredIdx(preferred >= 0 ? preferred : 0);
        }
      })
      .catch((e) => setAvailErr(String(e)));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Auto-fill UPN target when domain gets populated from the picker.
  useEffect(() => {
    if (domain && !upnTarget.includes("@")) {
      setUpnTarget(`administrator@${domain}`);
    }
  }, [domain, upnTarget]);

  const selected: AdcsEsc1MatchingCred | null = useMemo(() =>
    (avail && credIdx >= 0 ? avail.matching_creds[credIdx] : null), [avail, credIdx]);

  const canFire = useMemo(() => (
    !!avail && avail.tool_installed && !busy
    && !!template.trim() && !!ca.trim() && !!dcIp.trim() && !!domain.trim()
    && !!upnTarget.trim() && !!selected
  ), [avail, busy, template, ca, dcIp, domain, upnTarget, selected]);

  async function fire() {
    if (!avail || !selected) return;
    setBusy(true); setError(null); setResult(null);
    try {
      const r = await postAdcsEsc1Attempt({
        template: template.trim(), ca: ca.trim(), dc_ip: dcIp.trim(),
        domain: domain.trim(), username: selected.username,
        upn_target: upnTarget.trim(),
        confirm: avail.confirm_sentinel,
      }, tester);
      setResult(r);
      if (r.ok) onSuccess?.(r);
    } catch (e) {
      setError((e as Error).message || "request failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal esc1-modal" onClick={(ev) => ev.stopPropagation()}>
        <div className="modal-header">
          <h3>ADCS ESC1 — request cert as arbitrary UPN</h3>
          <button className="modal-close" onClick={onClose} title="close">✕</button>
        </div>
        <div className="modal-body">
          <div className="esc1-warn">
            ⚠ <b>T3 intrusive action.</b> Running this will create a real
            certificate on the target CA, generate audit event 4886, and
            yield a PFX that authenticates as the target UPN. Only fire
            with Rules of Engagement clearance.
          </div>

          {availErr && (
            <div className="esc1-err">Couldn't reach the ESC1 endpoint: {availErr}</div>
          )}
          {!avail && !availErr && <div className="muted">Loading…</div>}

          {avail && !avail.tool_installed && (
            <div className="esc1-tool-missing">
              <div><b>certipy not installed on the recce host.</b></div>
              <div className="muted small mono">{avail.tool_hint}</div>
            </div>
          )}

          {avail && avail.tool_installed && avail.matching_creds.length === 0 && (
            <div className="esc1-nocreds">
              No AD credential in the store to enroll on the template. Capture
              one first (spray, credenum, or the AD chain's `cred_acquired` step)
              — recce won't accept a password typed here.
            </div>
          )}

          {avail && avail.tool_installed && avail.matching_creds.length > 0 && (
            <div className="esc1-form">
              <label>
                <span>Enrolling principal (from store)</span>
                <select value={credIdx}
                        onChange={(e) => {
                          const i = Number(e.target.value);
                          setCredIdx(i);
                          const c = avail.matching_creds[i];
                          if (c?.domain && !domain) setDomain(c.domain);
                        }}
                        disabled={busy}>
                  {avail.matching_creds.map((c, i) => (
                    <option key={i} value={i}>
                      {c.username}{c.domain ? "@" + c.domain : ""}
                      {" — "}{c.source}
                      {c.has_hash ? " (nthash)" : ""}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                <span>Template</span>
                <input value={template} onChange={(e) => setTemplate(e.target.value)}
                       placeholder="e.g. VulnerableUserAuth" disabled={busy} />
              </label>
              <label>
                <span>CA name</span>
                <input value={ca} onChange={(e) => setCa(e.target.value)}
                       placeholder="e.g. CORP-CA" disabled={busy} />
              </label>
              <label>
                <span>DC IP / host</span>
                <input value={dcIp} onChange={(e) => setDcIp(e.target.value)}
                       placeholder="e.g. 10.0.0.10" disabled={busy} />
              </label>
              <label>
                <span>Domain</span>
                <input value={domain} onChange={(e) => setDomain(e.target.value)}
                       placeholder="e.g. corp.local" disabled={busy} />
              </label>
              <label>
                <span>UPN to embed in cert SAN</span>
                <input value={upnTarget} onChange={(e) => setUpnTarget(e.target.value)}
                       placeholder="administrator@corp.local" disabled={busy} />
              </label>
              <div className="esc1-actions">
                <button className="esc1-run" onClick={fire} disabled={!canFire}>
                  {busy ? "Running certipy…" : "🎯 Run certipy req (intrusive)"}
                </button>
                <button className="linkish" onClick={onClose}>Cancel</button>
              </div>
              <div className="muted small">
                Sends <code>confirm={avail.confirm_sentinel}</code> — the exact
                string the endpoint requires to fire. Password / hash comes
                from the store row for {selected?.username}, never from this form.
              </div>
            </div>
          )}

          {error && <div className="esc1-err">Request failed: {error}</div>}

          {result && (
            <div className={"esc1-result " + (result.ok ? "ok" : "err")}>
              <div className="esc1-result-h">
                {result.ok
                  ? `✓ Certificate issued in ${result.elapsed_s.toFixed(1)}s`
                  : `✗ certipy exited ${result.returncode ?? "?"} — ${result.error}`}
              </div>
              {result.ok && (
                <ul className="esc1-result-facts">
                  <li>UPN requested: <span className="mono">{result.upn_requested}</span></li>
                  <li>Template / CA: <span className="mono">{result.template}</span> on <span className="mono">{result.ca}</span></li>
                  <li>PFX ({result.pfx_size} B) saved to: <span className="mono">{result.pfx_saved_at}</span></li>
                  <li>Credential store entry:{" "}
                    {result.credential_added
                      ? <span className="ok-tag">added as kind=cert</span>
                      : <span className="muted">already present (dedup by user+domain)</span>}
                  </li>
                </ul>
              )}
              {result.stdout_tail && (
                <details className="esc1-stdout">
                  <summary className="muted small">certipy stdout tail</summary>
                  <pre className="mono">{result.stdout_tail}</pre>
                </details>
              )}
              {result.argv_redacted.length > 0 && (
                <details className="esc1-argv">
                  <summary className="muted small">argv (redacted)</summary>
                  <pre className="mono">{result.argv_redacted.join(" ")}</pre>
                </details>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
