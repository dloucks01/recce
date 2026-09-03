import { useEffect, useState } from "react";
import { getCredentials, Credential } from "../api";
import { Nav } from "../views/shared";

/**
 * P7-B1 replacement for the sidebar's full CredentialsPanel embed.
 *
 * The sidebar 🔑 tab used to inline the same full-featured credentials
 * view the top-level Credentials tab renders — search box, filter chips,
 * reveal toggles, delete buttons. Same fail-mode as the ⚡ Activity + 💬
 * Chat header buttons that eadada1 removed: two entrance points to the
 * same view is a UX foot-gun.
 *
 * This compact strip:
 *   * shows a KPI (N captured · latest source)
 *   * lists the newest 5 credentials as small chips
 *   * has one "Open Credentials tab →" link that jumps to the full view
 *     (via `nav.toCreds`, added in the same commit)
 *
 * All the mutation surfaces (add / spray / loot-extract / delete) stay
 * in the top-level Credentials tab; the sidebar is quick-glance only.
 */
export function CredsSummary({ nav }: { nav?: Nav }) {
  const [creds, setCreds] = useState<Credential[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const load = () =>
      getCredentials()
        .then((cs) => { if (alive) { setCreds(cs); setErr(null); } })
        .catch((e) => { if (alive) setErr(String(e)); });
    load();
    // Poll — the top-level tab writes into the store; the sidebar should
    // reflect changes without a page refresh. 5s is fine for the KPI.
    const t = window.setInterval(load, 5000);
    return () => { alive = false; window.clearInterval(t); };
  }, []);

  if (err) return <div className="creds-summary err">{err}</div>;
  if (creds === null) return <div className="creds-summary muted">Loading…</div>;

  if (creds.length === 0) {
    return (
      <div className="creds-summary empty">
        <div className="creds-summary-h">Credentials</div>
        <div className="muted small">
          No credentials captured yet. Run <span className="mono">recce credenum</span>{" "}
          or paste loot into the Credentials tab.
        </div>
        {nav?.toCreds && (
          <button className="linkish" onClick={() => nav.toCreds!()}>
            Open Credentials tab →
          </button>
        )}
      </div>
    );
  }

  const latest = creds[0];
  const sourceCounts: Record<string, number> = {};
  for (const c of creds) sourceCounts[c.source || "manual"] = (sourceCounts[c.source || "manual"] || 0) + 1;
  const topSources = Object.entries(sourceCounts).sort((a, b) => b[1] - a[1]).slice(0, 3);

  return (
    <div className="creds-summary">
      <div className="creds-summary-h">
        <span>Credentials</span>
        <span className="creds-summary-count">{creds.length}</span>
      </div>
      <div className="creds-summary-latest">
        <span className="muted small">latest:</span>{" "}
        <span className="mono">
          {latest.label || latest.username || "(anonymous)"}
          {latest.domain && `@${latest.domain}`}
        </span>
        <span className="muted small"> · from {latest.source || "manual"}</span>
      </div>
      <div className="creds-summary-sources">
        {topSources.map(([src, n]) => (
          <span key={src} className="creds-summary-chip"
                title={`${n} credential(s) from ${src}`}>
            {src} <span className="muted">×{n}</span>
          </span>
        ))}
      </div>
      {nav?.toCreds && (
        <button className="linkish creds-summary-open"
                onClick={() => nav.toCreds!()}>
          Open Credentials tab →
        </button>
      )}
    </div>
  );
}
