import { useEffect, useState } from "react";
import { getCredentials, postLootExtract, Credential, LootExtractResult } from "../api";
import { Nav } from "../views/shared";
import { toast } from "../toast";

/**
 * Sidebar 🔑 tab — a quick-glance-plus-quick-action strip.
 *
 * Original P7-B1 replacement of the full CredentialsPanel embed was
 * read-only and, honestly, felt like a link with extra chrome. The
 * user's read: "just gets clicked to open the main creds tab." So this
 * pass surfaces information the main tab already tracks (domain vs
 * local split, admin-flagged captures, freshness) plus one narrow
 * MUTATION affordance — paste-to-loot — so the sidebar becomes a real
 * workflow endpoint instead of a link with metadata.
 *
 * Deliberately keeps the mutation surface narrow:
 *   * paste-to-loot (calls /api/loot/extract) is fire-and-forget with
 *     visible feedback via toast + inline count. Nothing intrusive.
 *   * spray + credential deletion still live only on the top-level
 *     Credentials tab. Two paths to a destructive action is the exact
 *     foot-gun the P7-B1 dedupe pass fixed.
 */
export function CredsSummary({ nav }: { nav?: Nav }) {
  const [creds, setCreds] = useState<Credential[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [extractOpen, setExtractOpen] = useState(false);
  const [pasteText, setPasteText] = useState("");
  const [extractBusy, setExtractBusy] = useState(false);
  const [lastExtract, setLastExtract] = useState<LootExtractResult | null>(null);

  useEffect(() => {
    let alive = true;
    const load = () =>
      getCredentials()
        .then((cs) => { if (alive) { setCreds(cs); setErr(null); } })
        .catch((e) => { if (alive) setErr(String(e)); });
    load();
    const t = window.setInterval(load, 5000);
    return () => { alive = false; window.clearInterval(t); };
  }, []);

  async function doExtract() {
    if (!pasteText.trim() || extractBusy) return;
    setExtractBusy(true);
    try {
      const r = await postLootExtract(pasteText);
      setLastExtract(r);
      if (r.added > 0) {
        toast.show(`+${r.added} credential(s) looted from paste`);
        setPasteText("");                     // clear on success
      } else if (r.found > 0) {
        toast.show(`${r.found} found — all already in the store`);
      } else {
        toast.show("No credentials matched in the pasted text");
      }
      // refresh happens on next poll tick automatically.
    } catch (e) {
      toast.show(`Extract failed: ${(e as Error).message}`);
    } finally {
      setExtractBusy(false);
    }
  }

  if (err) return <div className="creds-summary err">{err}</div>;
  if (creds === null) return <div className="creds-summary muted">Loading…</div>;

  // Empty-state path — nothing to summarize; offer the paste-to-loot
  // action inline so this is the first thing an operator can do.
  if (creds.length === 0) {
    return (
      <div className="creds-summary empty">
        <div className="creds-summary-h">Credentials</div>
        <div className="muted small">
          No credentials captured yet. Paste tool output below or run{" "}
          <span className="mono">recce credenum</span>.
        </div>
        <ExtractBox open={extractOpen} setOpen={setExtractOpen}
                    text={pasteText} setText={setPasteText}
                    busy={extractBusy} onGo={doExtract}
                    lastResult={lastExtract} />
        {nav?.toCreds && (
          <button className="linkish" onClick={() => nav.toCreds!()}>
            Open Credentials tab →
          </button>
        )}
      </div>
    );
  }

  // Metrics the sidebar can compute in one pass — used by the KPI grid
  // and the domain/source chip rows below.
  const domains: Record<string, number> = {};
  const sourceCounts: Record<string, number> = {};
  let localN = 0;
  let adminN = 0;
  let plaintextN = 0;
  let hashN = 0;
  for (const c of creds) {
    sourceCounts[c.source || "manual"] = (sourceCounts[c.source || "manual"] || 0) + 1;
    if (c.domain) domains[c.domain] = (domains[c.domain] || 0) + 1;
    else localN += 1;
    // admin heuristic — spray-validated hits tagged "local admin" in notes,
    // or an explicitly labelled admin/root/administrator username. This
    // matches the tag on the spray-hits row so an operator sees the same
    // "N admin" count both places.
    const uname = (c.username || c.label || "").toLowerCase();
    const notes = (c.notes || "").toLowerCase();
    if (notes.includes("local admin") || notes.includes("(admin)")
        || uname === "administrator" || uname === "root"
        || uname === "sa" || uname.endsWith("\\administrator")) {
      adminN += 1;
    }
    if (c.kind === "password") plaintextN += 1;
    if (c.kind === "nthash" || c.kind === "hash") hashN += 1;
  }
  const latest = creds[0];
  const topDomains = Object.entries(domains).sort((a, b) => b[1] - a[1]).slice(0, 3);
  const topSources = Object.entries(sourceCounts).sort((a, b) => b[1] - a[1]).slice(0, 3);

  return (
    <div className="creds-summary">
      {/* KPI header — total + admin count (visible as its own chip so a
          juicy capture doesn't get lost in the total). */}
      <div className="creds-summary-h">
        <span>Credentials</span>
        <span className="creds-summary-count">{creds.length}</span>
        {adminN > 0 && (
          <span className="creds-summary-admin"
                title={`${adminN} admin/root/administrator/sa credential(s)`}>
            ⚠ {adminN} admin
          </span>
        )}
      </div>

      {/* Scope split — local vs each captured domain, so an operator
          can tell at a glance whether they've moved beyond local
          accounts. Chip layout matches the top sources row below. */}
      <div className="creds-summary-sources">
        <span className="creds-summary-chip"
              title="credentials with no AD domain (local / service accounts)">
          🏠 local <span className="muted">×{localN}</span>
        </span>
        {topDomains.map(([d, n]) => (
          <span key={d} className="creds-summary-chip scope-domain-chip"
                title={`${n} credential(s) in domain ${d}`}>
            🌐 <span className="mono">{d}</span> <span className="muted">×{n}</span>
          </span>
        ))}
      </div>

      {/* Kind breakdown — plaintext vs hash, so a tester sees at a
          glance whether cracking is still needed. */}
      <div className="creds-summary-kinds muted small">
        {plaintextN} plaintext · {hashN} hash{hashN === 1 ? "" : "es"}
      </div>

      {/* Freshest capture — the answer to "did that last spray hit?". */}
      <div className="creds-summary-latest">
        <span className="muted small">latest:</span>{" "}
        <span className="mono">
          {latest.label || latest.username || "(anonymous)"}
        </span>
        <span className="muted small"> · from {latest.source || "manual"}</span>
      </div>

      {/* Top sources — small, dense chip row. */}
      <div className="creds-summary-sources">
        {topSources.map(([src, n]) => (
          <span key={src} className="creds-summary-chip"
                title={`${n} credential(s) from ${src}`}>
            {src} <span className="muted">×{n}</span>
          </span>
        ))}
      </div>

      {/* Paste-to-loot — mutation surface. Collapsed by default so it
          doesn't crowd the summary; expands into a small textarea. */}
      <ExtractBox open={extractOpen} setOpen={setExtractOpen}
                  text={pasteText} setText={setPasteText}
                  busy={extractBusy} onGo={doExtract}
                  lastResult={lastExtract} />

      {nav?.toCreds && (
        <button className="linkish creds-summary-open"
                onClick={() => nav.toCreds!()}>
          Open Credentials tab →
        </button>
      )}
    </div>
  );
}

/** Compact paste-to-loot box. Collapsed link → 3-row textarea + Go. */
function ExtractBox(
  { open, setOpen, text, setText, busy, onGo, lastResult }:
  { open: boolean; setOpen: (b: boolean) => void;
    text: string; setText: (s: string) => void;
    busy: boolean; onGo: () => void;
    lastResult: LootExtractResult | null }
) {
  if (!open) {
    return (
      <button className="linkish creds-summary-paste-toggle"
              onClick={() => setOpen(true)}
              title="paste tool output — recce scrapes creds from it">
        📋 paste to loot…
      </button>
    );
  }
  return (
    <div className="creds-summary-extract">
      <textarea className="scan-in creds-summary-paste"
                placeholder="paste secretsdump / .env / nxc / any output — recce extracts creds"
                value={text} rows={3}
                onChange={(e) => setText(e.target.value)}
                disabled={busy} />
      <div className="creds-summary-extract-row">
        <button className="run" onClick={onGo}
                disabled={busy || !text.trim()}>
          {busy ? "Extracting…" : "Extract"}
        </button>
        <button className="linkish" onClick={() => { setOpen(false); }}>
          cancel
        </button>
        {lastResult && (
          <span className="muted small">
            last: +{lastResult.added} added
            {lastResult.skipped_dupes ? ` · ${lastResult.skipped_dupes} dupes` : ""}
            {lastResult.found === 0 && " · no creds matched"}
          </span>
        )}
      </div>
    </div>
  );
}
