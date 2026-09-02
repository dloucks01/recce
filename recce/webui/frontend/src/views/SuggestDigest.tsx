// Suggest tab — the WebUI twin of the `recce suggest` CLI digest.
//
// The CLI in recce/cli/_suggest.py prints three sections:
//   1. Engagement metrics (host count, credential count, loot dir).
//   2. Cross-service rule outputs (every fired _SUGGESTION_RULES entry,
//      confidence-sorted).
//   3. Proven-exploitable findings (Vulns with exploit_note or depth_tier,
//      ranked by tier → sev → KEV → EPSS).
//
// This view renders the exact same three sections, sourced from
// /api/suggest/digest, so a tester who lives in the GUI sees the same
// "given what recce already knows, what should I run right now?" digest
// as a tester who runs `recce suggest -o eng` on the terminal.
import { useEffect, useState } from "react";
import { SevTag } from "../ui";
import {
  getSuggestDigest,
  SuggestDigestResponse,
  SuggestDigestRule,
  SuggestDigestFinding,
} from "../api";

// T0..T4 chip palette, mirrored from ExploitSurface so both surfaces stay
// visually consistent. Recce backend depth.py is the source of truth for
// the tier labels; we render whatever tier_label the server sends back.
const TIER_COLOR: Record<string, string> = {
  t0: "#8892a0",
  t1: "#3b82f6",
  t2: "#f59e0b",
  t3: "#ef4444",
  t4: "#c026d3",
};

function TierChip({ tier, label }: { tier: string; label: string }) {
  if (!tier) return null;
  const color = TIER_COLOR[tier] || "#8892a0";
  return (
    <span title={`${tier.toUpperCase()} ${label}`}
          style={{
            display: "inline-block", padding: "1px 7px", borderRadius: 6,
            fontFamily: "var(--mono)", fontSize: 11, fontWeight: 700,
            color: "#fff", background: color, whiteSpace: "nowrap",
          }}>
      {tier.toUpperCase()}
    </span>
  );
}

function ConfChip({ confidence }: { confidence: string }) {
  const cls = confidence === "high" ? "sv2-conf-high"
    : confidence === "medium" ? "sv2-conf-medium"
    : "sv2-conf-low";
  return (
    <span className={cls} style={{
      fontFamily: "var(--mono)", fontSize: 10, fontWeight: 700,
      textTransform: "uppercase", letterSpacing: ".04em",
      padding: "1px 6px", border: "1px solid currentColor",
      borderRadius: 4,
    }} title={`rule confidence: ${confidence}`}>
      {confidence || "-"}
    </span>
  );
}

function MetricsCard({ d }: { d: SuggestDigestResponse }) {
  const m = d.metrics;
  return (
    <section className="panel">
      <div className="panel-h">
        <h3>Engagement metrics</h3>
        <span className="muted">
          the digest below reflects the state of this engagement right now
        </span>
      </div>
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
        gap: 10,
      }}>
        <div className="stat">
          <div className="k">Hosts</div>
          <div className="v">{m.host_count}</div>
        </div>
        <div className="stat">
          <div className="k">Credentials</div>
          <div className="v">{m.cred_count}</div>
        </div>
        <div className="stat">
          <div className="k">Loot dir</div>
          <div className="v">{m.loot_present ? "present" : "empty"}</div>
        </div>
        <div className="stat">
          <div className="k">Rules fired</div>
          <div className="v">{m.rules_total}</div>
        </div>
        <div className="stat">
          <div className="k">Exploit findings</div>
          <div className="v">{m.exploit_findings_total}</div>
        </div>
      </div>
      <div className="muted" style={{ marginTop: 8, fontSize: 12 }}>
        Engagement: <span className="mono">{m.eng_dir}</span>
      </div>
    </section>
  );
}

function RuleRow({ r }: { r: SuggestDigestRule }) {
  // Mirrors _print_top_actions in _suggest.py: show confidence + reason +
  // either the external cmd hint or a "prefill <field>=<value> on <cmd>"
  // human-readable form.
  const cmdOrField = r.external_cmd
    || (r.command
        ? `prefill \`${r.field}=${r.suggested_value}\` on \`${r.command}\``
        : "(info)");
  return (
    <div className="sv2-suggest-card" style={{ margin: 0 }}>
      <div className="sv2-suggest-card-h">
        <span className="sv2-suggest-card-title">
          {r.command || r.source || "advisory"}
        </span>
        <ConfChip confidence={r.confidence} />
      </div>
      <div className="sv2-suggest-reason">{r.reason}</div>
      <div className="sv2-suggest-value mono">{cmdOrField}</div>
      <div className="muted" style={{ fontSize: 10 }}>
        source: <span className="mono">{r.source || "-"}</span>
      </div>
    </div>
  );
}

function RulesCard({ rules, top }: { rules: SuggestDigestRule[]; top: number }) {
  return (
    <section className="panel">
      <div className="panel-h">
        <h3>Top {top} cross-service next moves</h3>
        <span className="muted">
          the _SUGGESTION_RULES set — facts learned across services
          become one-click prefills or shell-command hints
        </span>
      </div>
      {rules.length === 0 ? (
        <div className="empty">
          no cross-service intel yet — run <span className="mono">enum</span> against
          the target subnet, then refresh.
        </div>
      ) : (
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fill, minmax(320px, 1fr))",
          gap: 10,
        }}>
          {rules.map((r) => <RuleRow key={r.key} r={r} />)}
        </div>
      )}
    </section>
  );
}

function ExploitRow({ f, onOpenHost }:
    { f: SuggestDigestFinding; onOpenHost: (ip: string) => void }) {
  const endpoint = f.port ? `${f.ip}:${f.port}` : f.ip;
  const cve = (f.cves && f.cves[0]) || "";
  return (
    <tr>
      <td><SevTag severity={f.severity} /></td>
      <td><TierChip tier={f.tier} label={f.tier_label} /></td>
      <td className="mono">
        <a href="#" onClick={(e) => { e.preventDefault(); onOpenHost(f.ip); }}
           title="open host drawer">
          {endpoint}
        </a>
      </td>
      <td>
        <div style={{ fontWeight: 600, fontSize: 13 }}>{f.title}</div>
        <div className="muted" style={{ fontSize: 11 }}>
          {f.protocol}
          {cve && <> · <span className="mono">{cve}</span></>}
          {f.kev && <> · <span style={{
            fontSize: 10, padding: "0 5px", marginLeft: 4,
            background: "#dc2626", color: "#fff", borderRadius: 4,
          }}>KEV</span></>}
          {f.epss > 0 && <> · <span className="mono">EPSS {f.epss}</span></>}
        </div>
        {f.exploit_note && (
          <pre style={{
            margin: "6px 0 0", padding: "6px 10px",
            background: "var(--surface2)",
            border: "1px solid var(--line)", borderRadius: 6,
            fontFamily: "var(--mono)", fontSize: 12, color: "var(--text)",
            whiteSpace: "pre-wrap", wordBreak: "break-word",
          }}>{f.exploit_note}</pre>
        )}
      </td>
    </tr>
  );
}

function ExploitFindingsCard({ findings, top, onOpenHost }: {
  findings: SuggestDigestFinding[];
  top: number;
  onOpenHost: (ip: string) => void;
}) {
  return (
    <section className="panel">
      <div className="panel-h">
        <h3>Top {top} proven-exploitable findings (T2 / T3 / T4)</h3>
        <span className="muted">
          ranked by depth_tier ↓, severity ↓, KEV ↓, EPSS ↓
        </span>
      </div>
      {findings.length === 0 ? (
        <div className="empty">
          no findings carry <span className="mono">exploit_note</span> or
          <span className="mono"> depth_tier</span> yet — run <span className="mono">vulns</span> /
          a per-service deep probe first.
        </div>
      ) : (
        <div className="tablewrap">
          <table className="loottable">
            <thead><tr>
              <th style={{ width: 60 }}>Sev</th>
              <th style={{ width: 60 }}>Tier</th>
              <th style={{ width: 180 }}>Endpoint</th>
              <th>Finding &amp; next move</th>
            </tr></thead>
            <tbody>
              {findings.map((f, i) => (
                <ExploitRow key={`${f.ip}:${f.port}:${i}`} f={f}
                            onOpenHost={onOpenHost} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

interface Props {
  onOpenHost?: (ip: string) => void;
}

export function SuggestDigest({ onOpenHost }: Props = {}) {
  const [data, setData] = useState<SuggestDigestResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [top, setTop] = useState<number>(() => {
    const raw = parseInt(localStorage.getItem("recce.suggest.top") || "10", 10);
    return raw > 0 && raw <= 200 ? raw : 10;
  });

  useEffect(() => {
    let cancelled = false;
    setLoading(true); setErr(null);
    getSuggestDigest(top)
      .then((d) => { if (!cancelled) { setData(d); setLoading(false); } })
      .catch((e) => { if (!cancelled) { setErr(String(e)); setLoading(false); } });
    return () => { cancelled = true; };
  }, [top]);

  useEffect(() => {
    localStorage.setItem("recce.suggest.top", String(top));
  }, [top]);

  const openHost = onOpenHost || ((_ip: string) => { /* no-op fallback */ });

  return (
    <div className="lootview">
      <section className="panel" style={{ borderLeft: "3px solid var(--accent)" }}>
        <div className="panel-h">
          <h3>recce suggests…</h3>
          <span className="muted">
            same digest <span className="mono">recce suggest</span> prints on the CLI
          </span>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <label className="muted" style={{ fontSize: 12 }}>Top N per section:</label>
          <select value={top} onChange={(e) => setTop(parseInt(e.target.value, 10))}
                  className="sv2-select" style={{ maxWidth: 100 }}>
            {[5, 10, 20, 50, 100].map((n) =>
              <option key={n} value={n}>{n}</option>)}
          </select>
        </div>
      </section>

      {loading && <div className="loading">Loading digest…</div>}
      {err && <div className="err">{err}</div>}
      {!loading && !err && data && (
        <>
          <MetricsCard d={data} />
          <RulesCard rules={data.rules} top={data.top} />
          <ExploitFindingsCard findings={data.exploit_findings} top={data.top}
                               onOpenHost={openHost} />
        </>
      )}
    </div>
  );
}
