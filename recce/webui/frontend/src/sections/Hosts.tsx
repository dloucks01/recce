// Hosts — the network picture. Dense table with rich filtering (subnet, OS,
// exposed service, risk, owner, access, reviewed) + click-to-sort headers + bulk
// claim/review, so a 100+ host engagement stays navigable. Click a row → drawer.
import { useMemo, useState } from "react";
import { Host, postBulkReview } from "../api";
import { useCollab } from "../collab";
import { SectionProps } from "../nav";
import { Empty, Chip } from "../kit";
import { toast } from "../toast";

const SEV = ["critical", "high", "medium", "low"] as const;
type Sort = "sev" | "ip" | "findings" | "host" | "subnet" | "ports";
// Group by the ACTUAL scope CIDR the backend resolved (/16, /28, /30, …). Only
// fall back to a derived /24 for a host with no resolved subnet (e.g. a manual
// add before scope was set).
const subnetOf = (h: Host) => h.subnet || (h.ip.split(".").slice(0, 3).join(".") + ".0/24");

export function Hosts({ data, nav }: SectionProps) {
  const { hosts } = data;
  const { c, me, assign } = useCollab();
  const [q, setQ] = useState("");
  const [owner, setOwner] = useState<"all" | "mine" | "unassigned">("all");
  const [subnet, setSubnet] = useState("all");
  const [os, setOs] = useState("all");
  const [svc, setSvc] = useState("all");
  const [risk, setRisk] = useState<"all" | "crit" | "high" | "any">("all");
  const [access, setAccess] = useState(false);
  const [unrev, setUnrev] = useState(false);
  const [sort, setSort] = useState<Sort>("sev");
  const [asc, setAsc] = useState(false);          // sort direction (default desc)
  const [sel, setSel] = useState<Set<string>>(new Set());

  const subnets = useMemo(() => [...new Set(hosts.map(subnetOf))].sort(), [hosts]);
  const oses = useMemo(() => [...new Set(hosts.map((h) => h.os).filter(Boolean))].sort(), [hosts]);
  const services = useMemo(() => [...new Set(hosts.flatMap((h) => (h.ports || []).map((p) => p.service).filter(Boolean)))].sort(), [hosts]);

  const ownerOf = (h: Host) => h.assignee || c.assignments[h.ip] || "";
  const rows = useMemo(() => {
    const n = q.toLowerCase();
    const f = hosts.filter((h) => {
      const o = ownerOf(h);
      if (owner === "mine" && o !== me) return false;
      if (owner === "unassigned" && o) return false;
      if (subnet !== "all" && subnetOf(h) !== subnet) return false;
      if (os !== "all" && h.os !== os) return false;
      if (svc !== "all" && !(h.ports || []).some((p) => p.service === svc)) return false;
      if (access && !h.access) return false;
      if (unrev && h.reviewed) return false;
      const fn = h.findings || {};
      if (risk === "crit" && !fn.critical) return false;
      if (risk === "high" && !(fn.critical || fn.high)) return false;
      if (risk === "any" && !SEV.some((s) => fn[s])) return false;
      return !n || `${h.ip} ${h.hostname || ""} ${h.os || ""} ${(h.roles || []).join(" ")}`.toLowerCase().includes(n);
    });
    const ipNum = (ip: string) => ip.split(".").reduce((a, o) => a * 256 + (+o || 0), 0);
    const cmp = (a: Host, b: Host) => {
      switch (sort) {
        case "ip": return ipNum(a.ip) - ipNum(b.ip);
        case "findings": return total(b) - total(a);
        case "host": return (a.hostname || a.ip).localeCompare(b.hostname || b.ip);
        case "subnet": return subnetOf(a).localeCompare(subnetOf(b)) || ipNum(a.ip) - ipNum(b.ip);
        case "ports": return (b.ports?.length || 0) - (a.ports?.length || 0);
        default: return sevScore(b) - sevScore(a) || ipNum(a.ip) - ipNum(b.ip);
      }
    };
    f.sort((a, b) => (asc ? -cmp(a, b) : cmp(a, b)));
    return f;
  }, [hosts, q, owner, subnet, os, svc, risk, access, unrev, sort, asc, c.assignments, me]);

  // Bound the rendered DOM without a virtualization dependency: past the cap,
  // render the top slice (the current sort decides which) and nudge to refine.
  // Keeps the table snappy on a 1000-host sweep while staying lightweight.
  const CAP = 400;
  const shown = rows.length > CAP ? rows.slice(0, CAP) : rows;

  // Selection is scoped to what's currently visible so a filter change + "select
  // all" never silently acts on hidden rows.
  const visibleIps = useMemo(() => new Set(shown.map((h) => h.ip)), [shown]);
  const selVisible = [...sel].filter((ip) => visibleIps.has(ip));
  const allSelected = shown.length > 0 && selVisible.length === shown.length;
  const toggleAll = () => setSel(allSelected ? new Set() : new Set(shown.map((h) => h.ip)));
  const toggleOne = (ip: string) => setSel((s) => { const n = new Set(s); n.has(ip) ? n.delete(ip) : n.add(ip); return n; });

  const bulkClaim = () => { selVisible.forEach((ip) => assign(ip, me)); toast.show(`claimed ${selVisible.length} host(s)`); setSel(new Set()); };
  const bulkReview = () => {
    const ips = new Set(selVisible);
    const n = selVisible.length;
    postBulkReview(selVisible.map((ip) => `host:${ip}`), true)
      .then(() => {
        // Optimistically flip the reviewed flag so the row (and the Unreviewed
        // filter) update immediately, then reconcile with a full data refresh —
        // h.reviewed comes from the engagement fetch, not collab state.
        data.setHosts((hs) => hs.map((h) => (ips.has(h.ip) ? { ...h, reviewed: true } : h)));
        toast.show(`marked ${n} host(s) reviewed`);
        setSel(new Set());
        data.refresh();
      })
      .catch((e) => toast.show(String(e)));
  };

  const setSortKey = (k: Sort) => { if (sort === k) setAsc(!asc); else { setSort(k); setAsc(false); } };
  const arrow = (k: Sort) => sort === k ? (asc ? " ▲" : " ▼") : "";
  const th = (k: Sort, label: string, extra: React.CSSProperties = {}, titleText = "click to sort") =>
    <th className="click" style={{ userSelect: "none", ...extra }} onClick={() => setSortKey(k)} title={titleText}>{label}{arrow(k)}</th>;

  return (
    <>
      <div className="filterbar">
        <select className="btn sm" value={subnet} onChange={(e) => setSubnet(e.target.value)} title="subnet">
          <option value="all">All subnets</option>{subnets.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="btn sm" value={os} onChange={(e) => setOs(e.target.value)} title="OS">
          <option value="all">Any OS</option>{oses.map((s) => <option key={s} value={s}>{s.replace(/^Microsoft /, "")}</option>)}
        </select>
        <select className="btn sm" value={svc} onChange={(e) => setSvc(e.target.value)} title="exposed service">
          <option value="all">Any service</option>{services.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="btn sm" value={risk} onChange={(e) => setRisk(e.target.value as typeof risk)} title="risk">
          <option value="all">Any risk</option><option value="crit">Has critical</option><option value="high">Has high+</option><option value="any">Has findings</option>
        </select>
        <Chip label="Access" on={access} onClick={() => setAccess(!access)} />
        <Chip label="Mine" on={owner === "mine"} onClick={() => setOwner(owner === "mine" ? "all" : "mine")} />
        <Chip label="Unclaimed" on={owner === "unassigned"} onClick={() => setOwner(owner === "unassigned" ? "all" : "unassigned")} />
        <Chip label="Unreviewed" on={unrev} onClick={() => setUnrev(!unrev)} />
        <span className="grow" />
        <input className="namebox" style={{ width: 180 }} placeholder="filter: ip, host, role…" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>

      {selVisible.length > 0 ? (
        <div className="row" style={{ gap: 8, alignItems: "center", margin: "0 2px 8px", fontSize: 12 }}>
          <b>{selVisible.length} selected</b>
          <button className="btn sm primary" onClick={bulkClaim}>Claim</button>
          <button className="btn sm" onClick={bulkReview}>Mark reviewed</button>
          <button className="btn sm" onClick={() => setSel(new Set())}>Clear</button>
        </div>
      ) : (
        <div className="muted" style={{ fontSize: 11, margin: "0 2px 8px" }}>
          showing {rows.length === shown.length ? rows.length : `top ${shown.length} of ${rows.length}`} of {hosts.length} hosts
          {rows.length > shown.length && <span className="faint"> · refine filters or sort to narrow</span>}
        </div>
      )}

      <div className="panel" style={{ padding: 0 }}>
        {rows.length === 0 ? <Empty>No hosts match these filters.</Empty> : (
          <table className="tbl">
            <thead><tr>
              <th style={{ width: 28 }}><input type="checkbox" checked={allSelected} onChange={toggleAll}
                  title={shown.length < rows.length ? `select the ${shown.length} shown (of ${rows.length} — refine to reach the rest)` : "select all"} /></th>
              {th("host", "Host")}{th("ports", "OS / Ports", { width: 150 }, "click to sort by open-port count")}
              {th("sev", "Severity", { width: 130 })}<th style={{ width: 140 }}>Progress</th><th style={{ width: 100 }}>Owner</th>
            </tr></thead>
            <tbody>
              {shown.map((h) => {
                const o = ownerOf(h);
                const checked = sel.has(h.ip);
                return (
                  <tr key={h.ip} className={"click" + (checked ? " sel-row" : "")} onClick={() => nav.openHost(h.ip)}>
                    <td onClick={(e) => { e.stopPropagation(); toggleOne(h.ip); }}>
                      <input type="checkbox" checked={checked} onChange={() => toggleOne(h.ip)} onClick={(e) => e.stopPropagation()} />
                    </td>
                    <td className="nowrap" style={{ maxWidth: 320 }} title={`${h.ip} ${h.hostname || ""} ${h.roles?.join(", ") || ""}`}>
                      <span className="mono" style={{ fontWeight: 600 }}>{h.ip}</span>
                      {h.hostname && <span className="muted"> · {h.hostname}</span>}
                      {h.roles?.length > 0 && <span className="muted" style={{ fontSize: 11 }}> · {h.roles.slice(0, 2).join(", ")}</span>}
                    </td>
                    <td className="muted nowrap" style={{ maxWidth: 160 }} title={h.os}>
                      {(h.os || "—").replace(/^Microsoft /, "")} <span className="faint mono">· {h.ports?.length || 0}p</span>
                    </td>
                    <td><span className="row" style={{ gap: 3 }}>
                      {SEV.map((s) => (h.findings?.[s] ? <span key={s} className={"sev " + s}>{h.findings[s]}</span> : null))}
                      {h.leads ? <span className="chip faint" title="unconfirmed candidates — verify in Findings">{h.leads}?</span> : null}
                    </span></td>
                    <td><span className="row" style={{ gap: 4, fontSize: 10 }}><Step on={h.enumerated} label="enum" /><Step on={h.vuln_scanned} label="vuln" /><Step on={h.access} label="acc" /></span></td>
                    <td>{o ? <span className={"chip" + (o === me ? " on" : "")}>{o === me ? "you" : o}</span> : <span className="faint">—</span>}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

function Step({ on, label }: { on: boolean; label: string }) {
  return <span title={label} style={{ padding: "0 5px", borderRadius: 3, background: on ? "color-mix(in srgb,var(--ok) 18%,transparent)" : "var(--surface2)", color: on ? "var(--ok)" : "var(--faint)", fontWeight: 700 }}>{label}</span>;
}
function total(h: Host): number { const f = h.findings || {}; return (f.critical || 0) + (f.high || 0) + (f.medium || 0) + (f.low || 0); }
function sevScore(h: Host): number { const f = h.findings || {}; return (f.critical || 0) * 1000 + (f.high || 0) * 100 + (f.medium || 0) * 10 + (f.low || 0); }
