// Overview — the command centre / home. At-a-glance engagement state, ranked
// next moves, coverage, top-risk hosts, KEV shortlist. Everything links into its
// section; no heavy tables here.
import { useEffect, useState } from "react";
import { ActCard, getAct } from "../api";
import { Panel, StatRow, Meter, Sev, Empty } from "../kit";
import { SectionProps } from "../nav";

export function Overview({ data, nav }: SectionProps) {
  const { ov } = data;
  const [top, setTop] = useState<ActCard[] | null>(null);
  const [topErr, setTopErr] = useState(false);
  // Refetch the ranked plan whenever the engagement state actually moves (a scan
  // or module finished), not just at mount — otherwise "Next moves" freezes on
  // the plan from page load while the rest of the dashboard live-updates.
  useEffect(() => {
    getAct().then((p) => { setTop(p.top.slice(0, 5)); setTopErr(false); })
            .catch(() => { setTopErr(true); });
  }, [ov?.hosts_up, ov?.findings_total, ov?.accessed, ov?.reviewed]);

  if (!ov) return <div className="loading">Loading engagement…</div>;
  const sev = ov.by_severity || {};
  const leads = ov.leads_hidden || 0;

  return (
    <div className="grid" style={{ gap: 12 }}>
      <StatRow items={[
        { k: "Hosts up", v: <>{ov.hosts_up}<span className="faint" style={{ fontSize: 12 }}> / {ov.hosts_total}</span></> },
        { k: "Critical", v: sev.critical || 0, cls: "crit" },
        { k: "High", v: sev.high || 0 },
        { k: "KEV", v: ov.kev_total, cls: "kev" },
        { k: "Open ports", v: ov.services },
        { k: "Reviewed", v: ov.findings_total ? Math.round((100 * ov.reviewed) / ov.findings_total) + "%" : "0%", cls: "ok" },
      ]} />

      {leads > 0 && (
        <div className="muted" style={{ fontSize: 12, marginTop: -4 }}>
          Counts above are confirmed &amp; likely findings.{" "}
          <button className="linkish" onClick={() => nav.toFindings({})}>
            {leads} unconfirmed candidate{leads === 1 ? "" : "s"} hidden →
          </button>{" "}(review in Findings)
        </div>
      )}

      {/* Baked-intel status. The summary leads with the entry counts actually
          baked in, so a present-but-unstamped snapshot reads as healthy. Amber
          warning fires ONLY when the intel is genuinely absent (0 entries) —
          not merely unstamped, which is a provenance detail, not a gap. */}
      {ov.intel_asof && (() => {
        const present = ov.intel_asof.present ?? (ov.intel_asof.kev_count ?? 0) > 0;
        const stamped = ov.intel_asof.stamped ?? (ov.intel_asof.kev_as_of !== "unknown");
        return (
        <div className="muted" style={{
          fontSize: 12, marginTop: -4,
          color: !present ? "var(--warn, #b45309)" : undefined,
        }}
             title={
               `KEV: ${ov.intel_asof.kev_count ?? "?"} CVEs` +
               (ov.intel_asof.kev_catalog_version ? ` · v${ov.intel_asof.kev_catalog_version}` : "") +
               (ov.intel_asof.kev_released ? ` (released ${ov.intel_asof.kev_released})` : "") +
               ` · baked ${ov.intel_asof.kev_as_of || "unstamped"}\n` +
               `EPSS: ${ov.intel_asof.epss_count ?? "?"} scores` +
               (ov.intel_asof.epss_model ? ` · ${ov.intel_asof.epss_model}` : "") +
               (ov.intel_asof.epss_score_date ? ` (scored ${ov.intel_asof.epss_score_date})` : "") +
               ` · baked ${ov.intel_asof.epss_as_of || "unstamped"}`
             }>
          {!present && <span>⚠ </span>}
          Offline intel: {ov.intel_asof.summary}
          {present && !stamped && (
            <span> — <span className="mono">tools/refresh_intel.py</span> stamps the snapshot date</span>
          )}
        </div>
        );
      })()}

      <div className="grid" style={{ gridTemplateColumns: "minmax(0,1.5fr) minmax(0,1fr)", gap: 12 }}>
        <Panel title="★ Next moves" sub="highest-impact actions you can take now"
               actions={<button className="linkish" onClick={() => nav.go("exploit")}>all →</button>}>
          {top == null && !topErr ? <div className="loading">…</div>
            : topErr ? <Empty>Couldn't load the action plan — retrying on the next update.</Empty>
            : (top || []).length === 0 ? <Empty>Run a scan, then the deep modules — the plan builds itself.</Empty>
            : (top || []).map((c, i) => (
              <div key={i} className="row" style={{ padding: "6px 0", borderBottom: "1px solid color-mix(in srgb,var(--line) 55%,transparent)", gap: 8, alignItems: "baseline" }}>
                <span className="mono faint" style={{ width: 16 }}>{i + 1}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600 }}>{c.title}
                    {c.target && c.target !== "engagement" &&
                      <span className="mono faint" style={{ marginLeft: 6, fontSize: 11 }}>{c.target}</span>}</div>
                  <div className="muted" style={{ fontSize: 11 }}>→ {c.yields}</div>
                </div>
                <span className="chip">{c.archetype}</span>
              </div>
            ))}
        </Panel>

        <Panel title="Coverage" actions={<button className="linkish" onClick={() => nav.go("hosts")}>hosts →</button>}>
          {/* Scope is shown as a plain line, not a progress bar: the denominator is
              the address space (a /16 = 65,536 IPs), so a bar would read ~0% and
              mislead. "Hosts up" is the meaningful discovered count. */}
          <div className="row" style={{ justifyContent: "space-between", padding: "2px 0 8px", fontSize: 12 }}>
            <span className="muted">Scope</span>
            <span className="mono faint">{ov.hosts_up} up · {ov.scope_subnets} subnet{ov.scope_subnets === 1 ? "" : "s"} · {ov.scope_size.toLocaleString()} addrs</span>
          </div>
          <Meter label="Enumerated" now={ov.enumerated} total={ov.hosts_up} />
          <Meter label="Access gained" now={ov.accessed} total={ov.hosts_up} ok />
          <Meter label="Findings reviewed" now={ov.reviewed} total={ov.findings_total} />
        </Panel>
      </div>

      <div className="grid" style={{ gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr)", gap: 12 }}>
        <Panel title="Top-risk hosts" actions={<button className="linkish" onClick={() => nav.go("hosts")}>all →</button>}>
          {(ov.top_hosts || []).length === 0 ? <Empty>No hosts yet.</Empty> :
            ov.top_hosts.slice(0, 8).map((h) => (
              <div key={h.ip} className="row click" style={{ padding: "5px 0", borderBottom: "1px solid color-mix(in srgb,var(--line) 55%,transparent)" }}
                   onClick={() => nav.openHost(h.ip)}>
                <span className="mono" style={{ flex: 1 }}>{h.ip}{h.hostname ? ` · ${h.hostname}` : ""}</span>
                <span className="row" style={{ gap: 4 }}>
                  {(["critical", "high", "medium"] as const).map((s) => (h.findings?.[s] ? <span key={s} className={"sev " + s}>{h.findings[s]}</span> : null))}
                </span>
              </div>
            ))}
        </Panel>

        <Panel title="🔥 Known-exploited (KEV)" actions={<button className="linkish" onClick={() => nav.toFindings({})}>findings →</button>}>
          {(ov.kev_findings || []).length === 0 ? <Empty>No KEV findings.</Empty> :
            ov.kev_findings.slice(0, 8).map((f, i) => (
              <div key={i} className="row click" style={{ padding: "5px 0", borderBottom: "1px solid color-mix(in srgb,var(--line) 55%,transparent)", gap: 8 }}
                   onClick={() => nav.toFindings({ host: f.ip })}>
                <Sev s={f.severity} />
                <span style={{ flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.title}</span>
                {f.cve && <span className="mono faint" style={{ fontSize: 11 }}>{f.cve}</span>}
                {f.epss > 0 && <span className="mono kev" style={{ fontSize: 11 }} title="EPSS — probability of exploitation in the next 30 days">{f.epss}%</span>}
                <span className="mono faint" style={{ fontSize: 11 }}>{f.ip}</span>
              </div>
            ))}
        </Panel>
      </div>
    </div>
  );
}
