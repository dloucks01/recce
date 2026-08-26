import { useMemo, useState } from "react";
import { Finding, VulnDetail, SEVS, getHost, getExploitHint,
  FINDING_STATUSES, FINDING_STATUS_LABEL, FindingStatus, setFindingStatus } from "../api";
import { SevTag, NoteCell, useBounded } from "../ui";
import { FindingDetail } from "../FindingDetail";
import { useCollab } from "../collab";
import { toast } from "../toast";
import { FindingFilters, Nav } from "./shared";

// Severity chips carry pre-filter counts — the count reflects the whole
// engagement (minus leads), so a tester can see "there are 12 crits" even
// when they're currently filtered to a single host or KEV-only.
function SevChips({ value, onChange, counts }:
  { value: string; onChange: (v: string) => void; counts: Record<string, number> }
) {
  const total = SEVS.reduce((n, s) => n + (counts[s] || 0), 0);
  return (
    <div className="sev-chips">
      <button className={"sev-chip all" + (value === "all" ? " sel" : "")}
              onClick={() => onChange("all")}>
        <span className="sev-chip-label">All</span>
        <span className="sev-chip-count">{total}</span>
      </button>
      {SEVS.map((s) => {
        const c = counts[s] || 0;
        return (
          <button key={s} className={"sev-chip s-" + s + (value === s ? " sel" : "") + (c === 0 ? " empty" : "")}
                  onClick={() => onChange(value === s ? "all" : s)}
                  title={c === 0 ? `no ${s} findings` : `filter to ${c} ${s} findings`}>
            <span className="sev-chip-dot" aria-hidden />
            <span className="sev-chip-label">{s[0].toUpperCase() + s.slice(1)}</span>
            <span className="sev-chip-count">{c}</span>
          </button>
        );
      })}
    </div>
  );
}

export function Findings(
  { findings, f, setF, nav, onTick, onNote }:
  { findings: Finding[]; f: FindingFilters; setF: (o: Partial<FindingFilters>) => void;
    nav: Nav; onTick: (k: string, r: boolean) => void; onNote: (k: string, t: string) => void }
) {
  // Leads = QoD-below-threshold version/banner inferences (tier "lead"). They are the
  // bulk of the noise and the classic false-positive class, so they are hidden by
  // default; the "Leads" toggle brings them back when a tester wants to dig.
  const leadCount = useMemo(() => findings.filter((x) => x.tier === "lead").length, [findings]);
  // Sev counts on the visible universe (leads on/off follows the toggle, so
  // the chip totals match "what you'd see with just this sev filter applied").
  const sevCounts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const x of findings) {
      if (!f.leads && x.tier === "lead") continue;
      c[x.severity] = (c[x.severity] || 0) + 1;
    }
    return c;
  }, [findings, f.leads]);
  // Assignee filter: mine / unassigned / all. Finding assignment inherits from
  // its host (via c.assignments[ip]) — recce doesn't have per-finding
  // assignments yet, so a whole-host claim is what covers its findings too.
  const [assignee, setAssignee] = useState<"all" | "mine" | "unassigned">("all");
  // useCollab MUST resolve before the useMemo below — that memo's deps array
  // reads `cst.assignments`, and reading `cst` before its declaration is a
  // TDZ ReferenceError that crashes the whole Findings render.
  const { c: cst, me, dismiss } = useCollab();
  const rows = useMemo(() => {
    const n = f.q.toLowerCase();
    return findings.filter((x) => {
      const owner = cst.assignments[x.ip];
      if (assignee === "mine" && owner !== me) return false;
      if (assignee === "unassigned" && owner) return false;
      return (f.leads || x.tier !== "lead") &&
        (f.sev === "all" || x.severity === f.sev) &&
        (!f.host || x.ip === f.host) &&
        (!f.unreviewed || !x.reviewed) &&
        (!f.kev || x.kev) &&
        (!n || `${x.title} ${x.ip} ${x.cve} ${x.port} ${x.source}`.toLowerCase().includes(n));
    });
  }, [findings, f, assignee, cst.assignments, me]);
  const { shown, limit, total, sentinel } =
    useBounded(rows, 120, [f.sev, f.host, f.kev, f.unreviewed, f.leads, f.q]);

  // Inline expansion: full detail (output/remediation/QoD) isn't in the findings list
  // payload, so lazy-fetch it per host (one /api/host call, cached) on first expand.
  const [openKey, setOpenKey] = useState<string | null>(null);
  const [cache, setCache] = useState<Record<string, VulnDetail[]>>({});
  async function toggle(x: Finding) {
    if (openKey === x.key) { setOpenKey(null); return; }
    setOpenKey(x.key);
    if (!cache[x.ip]) {
      try {
        const h = await getHost(x.ip);
        setCache((c) => ({ ...c, [x.ip]: h.vulns }));
      } catch { /* leave it; the row just won't expand */ }
    }
  }
  const detailFor = (x: Finding) => cache[x.ip]?.find((v) => v.key === x.key);

  // Bulk selection — checkboxes appear alongside the reviewed tick.
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const toggleSel = (key: string) => setSelected(s => {
    const n = new Set(s);
    n.has(key) ? n.delete(key) : n.add(key);
    return n;
  });
  const visibleKeys = shown.map(x => x.key);
  const allVisibleSelected = visibleKeys.length > 0 && visibleKeys.every(k => selected.has(k));
  const someVisibleSelected = visibleKeys.some(k => selected.has(k));
  const toggleSelectAllVisible = () => setSelected(s => {
    if (allVisibleSelected) {
      const n = new Set(s);
      visibleKeys.forEach(k => n.delete(k));
      return n;
    }
    return new Set([...s, ...visibleKeys]);
  });
  const clearSel = () => setSelected(new Set());

  function bulkDismiss() {
    const keys = [...selected];
    const wereDismissed = keys.filter(k => !cst.dismissed[k]);
    wereDismissed.forEach(k => dismiss(k, true));
    // dismiss() already fires a per-item toast; suppress cascade by showing a summary
    if (wereDismissed.length > 0) {
      toast.show(`dismissed ${wereDismissed.length} finding(s)`, {
        label: "Undo",
        onClick: () => wereDismissed.forEach(k => dismiss(k, false)),
      });
    }
    clearSel();
  }
  function bulkTick(reviewed: boolean) {
    const keys = [...selected].filter(k => shown.find(x => x.key === k && x.reviewed !== reviewed));
    keys.forEach(k => onTick(k, reviewed));
    if (keys.length > 0) {
      toast.show(`${reviewed ? "marked" : "reopened"} ${keys.length} finding(s)`, {
        label: "Undo",
        onClick: () => keys.forEach(k => onTick(k, !reviewed)),
      });
    }
    clearSel();
  }

  return (
    <>
      {selected.size > 0 && (
        <div className="bulk-bar">
          <span className="bulk-count">{selected.size} selected</span>
          <button className="toggle" onClick={() => bulkTick(true)}>✓ Mark reviewed</button>
          <button className="toggle" onClick={() => bulkTick(false)}>↺ Reopen</button>
          <button className="toggle danger" onClick={bulkDismiss}>✗ Dismiss</button>
          <button className="linkish" onClick={clearSel}>clear selection</button>
        </div>
      )}
      <div className="findings-toolbar">
        <SevChips value={f.sev} onChange={(v) => setF({ sev: v })} counts={sevCounts} />
        <div className="findings-toolbar-tail">
          <div className="toggles">
            <button className={"toggle" + (f.unreviewed ? " on" : "")} onClick={() => setF({ unreviewed: !f.unreviewed })}>Unreviewed</button>
            <button className={"toggle" + (f.kev ? " on" : "")} onClick={() => setF({ kev: !f.kev })}>🔥 KEV</button>
            <button className={"toggle" + (assignee === "mine" ? " on" : "")}
                    onClick={() => setAssignee(assignee === "mine" ? "all" : "mine")}
                    title={`show only findings on hosts assigned to ${me}`}>👤 Mine</button>
            <button className={"toggle" + (assignee === "unassigned" ? " on" : "")}
                    onClick={() => setAssignee(assignee === "unassigned" ? "all" : "unassigned")}
                    title="show only findings on hosts nobody owns yet">✋ Unassigned</button>
            {leadCount > 0 && (
              <button className={"toggle" + (f.leads ? " on" : "")} onClick={() => setF({ leads: !f.leads })}
                      title="version/banner inferences below the confidence threshold">
                Leads <span className="ct">{leadCount}</span>
              </button>
            )}
          </div>
          <input className="search" placeholder="filter: cve, host, port…" value={f.q}
                 onChange={(e) => setF({ q: e.target.value })} spellCheck={false} />
        </div>
      </div>

      {(f.sev !== "all" || f.host || f.kev || f.unreviewed || f.leads || f.q) && (
        <div className="findings-active-filters" aria-label="active filters">
          <span className="faf-label">Filters:</span>
          {f.sev !== "all" && (
            <button className={"faf-chip s-" + f.sev}
                    onClick={() => setF({ sev: "all" })} title="clear severity filter">
              <span className="faf-key">sev</span>
              <span className="faf-val">{f.sev}</span>
              <span className="faf-x" aria-hidden>×</span>
            </button>
          )}
          {f.host && (
            <button className="faf-chip" onClick={() => setF({ host: "" })} title="clear host filter">
              <span className="faf-key">host</span>
              <span className="faf-val mono">{f.host}</span>
              <span className="faf-x" aria-hidden>×</span>
            </button>
          )}
          {f.kev && (
            <button className="faf-chip kev" onClick={() => setF({ kev: false })} title="clear KEV filter">
              🔥 <span className="faf-val">KEV only</span>
              <span className="faf-x" aria-hidden>×</span>
            </button>
          )}
          {f.unreviewed && (
            <button className="faf-chip" onClick={() => setF({ unreviewed: false })} title="clear unreviewed filter">
              <span className="faf-val">unreviewed only</span>
              <span className="faf-x" aria-hidden>×</span>
            </button>
          )}
          {f.leads && (
            <button className="faf-chip" onClick={() => setF({ leads: false })} title="hide leads">
              <span className="faf-val">leads visible</span>
              <span className="faf-x" aria-hidden>×</span>
            </button>
          )}
          {f.q && (
            <button className="faf-chip" onClick={() => setF({ q: "" })} title="clear search">
              <span className="faf-key">q</span>
              <span className="faf-val mono">{f.q}</span>
              <span className="faf-x" aria-hidden>×</span>
            </button>
          )}
          <button className="faf-clear linkish"
                  onClick={() => setF({ sev: "all", host: "", kev: false, unreviewed: false, leads: false, q: "" })}>
            clear all
          </button>
        </div>
      )}

      <div className="tablewrap">
        <table className="tbl findings">
          <thead><tr>
            <th className="sel-col" title="select for bulk actions">
              <input type="checkbox" checked={allVisibleSelected}
                     ref={el => { if (el) el.indeterminate = !allVisibleSelected && someVisibleSelected; }}
                     onChange={toggleSelectAllVisible} />
            </th>
            <th className="tick-col">✓</th><th>Sev</th><th>Finding</th><th>Host</th><th>Conf.</th><th>Note</th>
          </tr></thead>
          <tbody>
            {shown.map((x) => {
              const open = openKey === x.key;
              const detail = open ? detailFor(x) : undefined;
              const cls = ["row-sev-" + x.severity];
              if (x.reviewed) cls.push("done");
              if (open) cls.push("open");
              if (cst.dismissed[x.key]) cls.push("dismissed");
              if (selected.has(x.key)) cls.push("selected");
              return [
              <tr key={x.key} className={cls.join(" ")}>
                <td className="sel-col">
                  <input type="checkbox" checked={selected.has(x.key)}
                         onChange={() => toggleSel(x.key)} onClick={(e) => e.stopPropagation()} />
                </td>
                <td className="tick-col">
                  <input type="checkbox" checked={x.reviewed} onChange={() => onTick(x.key, !x.reviewed)} />
                </td>
                <td><SevTag severity={x.severity} /></td>
                <td className="expand" onClick={() => toggle(x)} title="show detail">
                  <div className="t"><span className="caret">{open ? "▾" : "▸"}</span> {x.title}</div>
                  <div className="m">{x.cve && <span>{x.cve} · </span>}{x.source}
                    {x.sources && x.sources.length > 1 && (
                      <span className="sources-badge" title={`corroborated by: ${x.sources.join(", ")}`}>
                        +{x.sources.length - 1} source{x.sources.length > 2 ? "s" : ""}
                      </span>
                    )}
                  </div>
                  <div className="badges">
                    {x.kev && <span className="badge kev" title="CISA Known Exploited Vulnerability — confirmed exploited in the wild; fix first">🔥 KEV</span>}
                    {x.epss > 0 && <span className="badge epss" title="EPSS — 30-day probability this CVE is exploited (FIRST.org)">EPSS {x.epss}%</span>}
                    {x.kev && nav.toExploitShell && (
                      <button className="kev-shell-btn" title="Get shell — opens Sessions with the msf module + target pre-filled"
                              onClick={async (e) => {
                                e.stopPropagation();
                                try {
                                  const h = await getExploitHint(x.key);
                                  nav.toExploitShell!({
                                    ip: h.ip, port: h.port, cve: h.cve, title: x.title,
                                    module: h.hint?.module || "", payload: h.hint?.payload || "",
                                    note: h.hint?.note || "",
                                  });
                                } catch { /* silent */ }
                              }}>🎯 shell</button>
                    )}
                  </div>
                </td>
                <td className="mono host-link" onClick={() => nav.openHost(x.ip)} title="host detail">
                  {x.ip}{x.port ? `:${x.port}` : ""}
                  {cst.assignments[x.ip] && (
                    <span className={"assignee-chip" + (cst.assignments[x.ip] === me ? " mine" : "")}
                          title={`host claimed by ${cst.assignments[x.ip]}`}>
                      {cst.assignments[x.ip] === me ? "you" : cst.assignments[x.ip]}
                    </span>
                  )}
                </td>
                <td><span className={"tier " + x.tier}>{x.tier === "lead" ? "lead · verify" : x.tier}</span></td>
                <td className="note-col">
                  <div className="note-col-row">
                    <select className={"finding-status status-" + (x.status || "new")}
                            value={x.status || ""}
                            title="lifecycle status — drives what appears in the retest / report filters"
                            onChange={(e) => {
                              const s = e.target.value as FindingStatus;
                              setFindingStatus(x.key, s).catch(() => {});
                              // optimistic local update — the SSE broker will resync anyway
                              (x as Finding).status = s;
                            }}>
                      {FINDING_STATUSES.map(s => (
                        <option key={s} value={s}>{FINDING_STATUS_LABEL[s]}</option>
                      ))}
                    </select>
                    <NoteCell value={x.notes} onSave={(t) => onNote(x.key, t)} />
                    <button className={"dismiss-btn" + (cst.dismissed[x.key] ? " on" : "")}
                            title={cst.dismissed[x.key] ? "restore this finding" : "mark not a finding (false positive)"}
                            onClick={() => dismiss(x.key, !cst.dismissed[x.key])}>
                      {cst.dismissed[x.key] ? "restore" : "dismiss"}
                    </button>
                  </div>
                </td>
              </tr>,
              open && (
                <tr key={x.key + ":d"} className="detail-row">
                  <td />
                  <td colSpan={6}>
                    {detail
                      ? <FindingDetail v={detail} onNote={onNote} onJumpToHost={nav.openHost} />
                      : <div className="muted small">loading detail…</div>}
                  </td>
                </tr>
              ),
              ];
            })}
            {rows.length === 0 && (
              <tr><td colSpan={7} className="empty">
                {!f.leads && leadCount > 0
                  ? `no confirmed findings match — ${leadCount} lead${leadCount > 1 ? "s" : ""} hidden (toggle “Leads” to show)`
                  : "no findings match this filter"}
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
      {sentinel}
      {total > 0 && (
        <div className="rowcount">
          showing {limit.toLocaleString()} of {total.toLocaleString()} findings
          {!f.leads && leadCount > 0 && <span className="muted"> · {leadCount} leads hidden</span>}
        </div>
      )}
    </>
  );
}
