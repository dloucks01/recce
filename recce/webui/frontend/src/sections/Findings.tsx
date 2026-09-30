// Findings — the triage floor. NOT a flat per-host list: findings are grouped by
// issue (CVE / title), so "EternalBlue on 6 hosts" is ONE row you triage once,
// not six. Groups are split into confidence lanes — real findings up top, the
// FP-prone version/banner "leads" in their own lane — so the signal isn't buried
// in noise. Click an issue → drawer with every affected host + why it may be a
// false positive. The prioritized "do this now" exploit workspace is the Exploit
// tab; this tab is about burning down the whole pile with a team.
import { useEffect, useMemo, useState } from "react";
import {
  Finding, setFindingAssignee, setFindingPriority, postBulkReview,
} from "../api";
import { useCollab } from "../collab";
import { SectionProps } from "../nav";
import { Empty, Chip, Avatar, Meter } from "../kit";
import { FindingDrawer } from "../FindingDrawer";

const SEVS = ["critical", "high", "medium", "low", "info"] as const;
const sevIdx = (s: string) => { const i = SEVS.indexOf(s as typeof SEVS[number]); return i < 0 ? 9 : i; };

// recce's own signal for "matched a banner/version, did NOT probe the live
// service" — the dominant false-positive source. Everything else was observed.
export const isLead = (f: Finding) => f.tier === "lead" || f.source === "version-db";

// An issue = every finding that shares a CVE (preferred) or, lacking one, an
// identical title. That's what collapses the per-host repeats into one row.
const gkeyOf = (f: Finding) => (f.cve || f.title || f.key).trim().toLowerCase();

type Group = {
  gkey: string; title: string; severity: string; kev: boolean; epss: number;
  cves: string[]; verdict: string; members: Finding[];
  lane: "act" | "verify"; owners: string[];
};

const VERDICT_RANK: Record<string, number> = { CONFIRMED: 3, LIKELY: 2, INCONCLUSIVE: 1 };

function group(findings: Finding[]): Group[] {
  const by = new Map<string, Finding[]>();
  for (const f of findings) {
    const k = gkeyOf(f);
    (by.get(k) || by.set(k, []).get(k)!).push(f);
  }
  const groups: Group[] = [];
  for (const [gkey, members] of by) {
    members.sort((a, b) => sevIdx(a.severity) - sevIdx(b.severity) || a.ip.localeCompare(b.ip));
    const cves = [...new Set(members.flatMap((m) => m.cves || []).filter(Boolean))];
    const verdict = members.map((m) => m.verdict || "")
      .sort((a, b) => (VERDICT_RANK[b] || 0) - (VERDICT_RANK[a] || 0))[0] || "";
    const owners = [...new Set(members.map((m) => m.assignee || "").filter(Boolean))];
    groups.push({
      gkey, title: members[0].title || members[0].cve || "finding",
      severity: members.map((m) => m.severity).sort((a, b) => sevIdx(a) - sevIdx(b))[0] || "info",
      kev: members.some((m) => m.kev),
      epss: Math.max(0, ...members.map((m) => m.epss || 0)),
      cves, verdict, members, owners,
      // A cluster is only "needs verification" when EVERY host is a lead. One
      // confirmed host anywhere promotes the whole issue to the actionable lane.
      lane: members.some((m) => !isLead(m)) ? "act" : "verify",
    });
  }
  return groups;
}

const groupSort = (a: Group, b: Group) =>
  (b.kev ? 1 : 0) - (a.kev ? 1 : 0) ||
  sevIdx(a.severity) - sevIdx(b.severity) ||
  b.members.length - a.members.length ||
  b.epss - a.epss;

export function Findings({ data, nav }: SectionProps) {
  const { findings, setFindings } = data;
  const { c, me, dismiss } = useCollab();

  const [sev, setSev] = useState("all");
  const [host, setHost] = useState(nav.seed?.host || "");
  const [owner, setOwner] = useState<string>("all");
  const [kev, setKev] = useState(false);
  const [unrev, setUnrev] = useState(false);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<Set<string>>(new Set());       // member keys
  const [openGkey, setOpenGkey] = useState<Set<string>>(new Set());
  const [showDismissed, setShowDismissed] = useState(false);
  const [openKey, setOpenKey] = useState<string | null>(null);

  useEffect(() => { if (nav.seed?.host) setHost(nav.seed.host); if (nav.seed?.sev) setSev(nav.seed.sev); }, [nav.seed]);

  const ownerOf = (x: Finding) => x.assignee || c.assignments[x.ip] || "";
  const owners = useMemo(() => {
    const s = new Set<string>();
    (c.roster || []).forEach((t) => t.name && s.add(t.name));
    c.online.forEach((n) => n && s.add(n));
    Object.values(c.assignments).forEach((n) => n && s.add(n));
    findings.forEach((x) => x.assignee && s.add(x.assignee));
    s.delete(""); s.delete("someone"); s.delete(me);
    return [...s].sort();
  }, [c.roster, c.online, c.assignments, findings, me]);

  // Filter at the finding level, then group. Dismissed findings are pulled out
  // into their own collapsed lane rather than mixed in or silently hidden.
  const n = q.toLowerCase();
  const passes = (x: Finding) => {
    const o = ownerOf(x);
    if (owner === "mine") { if (o !== me) return false; }
    else if (owner === "unassigned") { if (o) return false; }
    else if (owner !== "all") { if (o !== owner) return false; }
    return (sev === "all" || x.severity === sev) &&
      (!host || x.ip === host) &&
      (!unrev || !x.reviewed) &&
      (!kev || x.kev) &&
      (!n || `${x.title} ${x.ip} ${x.cve} ${x.port} ${x.source}`.toLowerCase().includes(n));
  };

  const { act, verify, dismissedGroups, counts } = useMemo(() => {
    const live: Finding[] = [], dead: Finding[] = [];
    for (const x of findings) {
      if (!passes(x)) continue;
      (c.dismissed[x.key] ? dead : live).push(x);
    }
    const gs = group(live).sort(groupSort);
    const act = gs.filter((g) => g.lane === "act");
    const verify = gs.filter((g) => g.lane === "verify");
    const dismissedGroups = group(dead).sort(groupSort);
    const counts = {
      issues: gs.length,
      findings: live.length,
      kev: act.filter((g) => g.kev).length,
      verify: verify.reduce((a, g) => a + g.members.length, 0),
      dismissed: dead.length,
    };
    return { act, verify, dismissedGroups, counts };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findings, sev, host, owner, kev, unrev, q, c.assignments, c.dismissed, me]);

  const sevCounts = useMemo(() => {
    const m: Record<string, number> = {};
    for (const x of findings) { if (isLead(x)) continue; m[x.severity] = (m[x.severity] || 0) + 1; }
    return m;
  }, [findings]);

  const patch = (key: string, o: Partial<Finding>) => setFindings((fs) => fs.map((f) => f.key === key ? { ...f, ...o } : f));
  const bulkReview = (keys: string[], r: boolean) => { postBulkReview(keys, r).catch(() => {}); keys.forEach((k) => patch(k, { reviewed: r, reviewed_by: r ? me : "" })); };
  const toggleSel = (keys: string[]) => setSel((s) => {
    const nn = new Set(s); const all = keys.every((k) => nn.has(k));
    keys.forEach((k) => all ? nn.delete(k) : nn.add(k)); return nn;
  });
  const clearSel = () => setSel(new Set());
  const openFinding = openKey ? findings.find((f) => f.key === openKey) || null : null;
  const cluster = openFinding ? findings.filter((f) => gkeyOf(f) === gkeyOf(openFinding)) : [];
  const toggleGroup = (g: string) => setOpenGkey((s) => { const nn = new Set(s); nn.has(g) ? nn.delete(g) : nn.add(g); return nn; });

  const nonLeadTotal = findings.filter((f) => !isLead(f)).length;

  return (
    <>
      {sel.size > 0 && (
        <div className="panel row wrap" style={{ gap: 8, marginBottom: 10, alignItems: "center" }}>
          <b>{sel.size} selected</b>
          <button className="btn sm" onClick={() => { bulkReview([...sel], true); clearSel(); }}>✓ Reviewed</button>
          <button className="btn sm" onClick={() => { bulkReview([...sel], false); clearSel(); }}>↺ Reopen</button>
          <select className="btn sm" value="__" onChange={(e) => { const v = e.target.value; if (v === "__") return; const who = v === "__un" ? "" : v; [...sel].forEach((k) => { patch(k, { assignee: who }); setFindingAssignee(k, who).catch(() => {}); }); clearSel(); e.currentTarget.value = "__"; }}>
            <option value="__">Assign to…</option><option value={me}>{me} (you)</option>
            {owners.map((o) => <option key={o} value={o}>{o}</option>)}<option value="__un">— unassign —</option>
          </select>
          <button className="btn sm" onClick={() => { [...sel].forEach((k) => { patch(k, { priority: "hot" }); setFindingPriority(k, "hot").catch(() => {}); }); clearSel(); }}>🔥 Flag hot</button>
          <button className="btn sm danger" onClick={() => { [...sel].forEach((k) => { if (!c.dismissed[k]) dismiss(k, true); }); clearSel(); }}>✗ Dismiss</button>
          <button className="linkish right" onClick={clearSel}>clear</button>
        </div>
      )}

      <div className="section-head" style={{ marginTop: -6 }}>
        <div className="row wrap" style={{ gap: 6 }}>
          <Chip label="All" on={sev === "all"} onClick={() => setSev("all")} count={nonLeadTotal} />
          {SEVS.slice(0, 4).map((s) => <Chip key={s} label={s[0].toUpperCase() + s.slice(1)} on={sev === s} onClick={() => setSev(sev === s ? "all" : s)} count={sevCounts[s] || 0} />)}
        </div>
        <div className="actions">
          <Chip label="Unreviewed" on={unrev} onClick={() => setUnrev(!unrev)} />
          <Chip label="🔥 KEV" on={kev} onClick={() => setKev(!kev)} />
          <select className="btn sm" value={owner} onChange={(e) => setOwner(e.target.value)} title="filter by owner">
            <option value="all">All owners</option><option value="mine">Mine</option><option value="unassigned">Unassigned</option>
            {owners.length > 0 && <option disabled>──────</option>}
            {owners.map((o) => <option key={o} value={o}>{o}</option>)}
          </select>
          <input className="namebox" style={{ width: 190 }} placeholder="filter: title, cve, host…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
      </div>

      {host && <div className="row" style={{ marginBottom: 8, gap: 8 }}><span className="chip on">host: {host}</span><button className="linkish" onClick={() => setHost("")}>clear</button></div>}

      {/* At-a-glance triage summary */}
      <div className="row wrap" style={{ gap: 14, margin: "0 2px 12px", fontSize: 12 }}>
        <span><b>{counts.issues}</b> issue{counts.issues === 1 ? "" : "s"} <span className="muted">· {counts.findings} findings</span></span>
        {counts.kev > 0 && <span style={{ color: "var(--kev)" }}><b>{counts.kev}</b> KEV</span>}
        {counts.verify > 0 && <span className="muted">{counts.verify} to verify</span>}
        {counts.dismissed > 0 && <span className="faint">{counts.dismissed} dismissed</span>}
      </div>

      {act.length === 0 && verify.length === 0 && dismissedGroups.length === 0 ? (
        <div className="panel"><Empty>No findings match.</Empty></div>
      ) : (
        <>
          <Lane title="Confirmed & observed" hint="findings recce saw directly — triage these first"
                groups={act} accent="var(--kev)" {...{ me, c, sel, ownerOf, openGkey, toggleGroup, toggleSel, bulkReview, dismiss, patch, setOpenKey }} />

          {verify.length > 0 && (
            <Lane title="Needs verification" hint="version / banner match only — the usual false-positive source"
                  groups={verify} accent="var(--faint)" muted {...{ me, c, sel, ownerOf, openGkey, toggleGroup, toggleSel, bulkReview, dismiss, patch, setOpenKey }} />
          )}

          {dismissedGroups.length > 0 && (
            <div style={{ marginTop: 14 }}>
              <button className="linkish" onClick={() => setShowDismissed((s) => !s)}>
                {showDismissed ? "▾" : "▸"} Dismissed ({counts.dismissed})
              </button>
              {showDismissed && (
                <div style={{ opacity: .6, marginTop: 6 }}>
                  <Lane title="" hint="" groups={dismissedGroups} accent="var(--faint)" muted
                        {...{ me, c, sel, ownerOf, openGkey, toggleGroup, toggleSel, bulkReview, dismiss, patch, setOpenKey }} />
                </div>
              )}
            </div>
          )}
        </>
      )}

      {openFinding && (
        <FindingDrawer finding={openFinding} me={me} owners={owners} cluster={cluster} nav={nav}
          hostClaim={c.assignments[openFinding.ip] || ""} dismissed={!!c.dismissed[openFinding.key]}
          onClose={() => setOpenKey(null)} onDismiss={(on) => dismiss(openFinding.key, on)}
          onOpenSibling={(k) => setOpenKey(k)}
          mutate={(o) => patch(openFinding.key, o)} />
      )}
    </>
  );
}

// One confidence lane: a header + its issue rows. Kept as a component so the
// actionable / needs-verification / dismissed lanes share exactly one layout.
function Lane({ title, hint, groups, accent, muted, me, c, sel, ownerOf, openGkey, toggleGroup, toggleSel, bulkReview, dismiss, patch, setOpenKey }: any) {
  if (groups.length === 0) return null;
  return (
    <div style={{ marginBottom: 16 }}>
      {title && (
        <div className="row" style={{ gap: 8, alignItems: "baseline", margin: "0 2px 6px" }}>
          <h4 style={{ margin: 0, fontSize: 13, color: muted ? "var(--muted)" : "var(--text)" }}>{title}</h4>
          <span className="faint" style={{ fontSize: 11 }}>{hint}</span>
        </div>
      )}
      <div className="panel" style={{ padding: 0 }}>
        {groups.map((g: Group) => (
          <GroupRow key={g.gkey} g={g} accent={accent}
            {...{ me, c, sel, ownerOf, openGkey, toggleGroup, toggleSel, bulkReview, dismiss, patch, setOpenKey }} />
        ))}
      </div>
    </div>
  );
}

function GroupRow({ g, c, sel, ownerOf, openGkey, toggleGroup, toggleSel, bulkReview, dismiss, setOpenKey }: any) {
  const keys = g.members.map((m: Finding) => m.key);
  const reviewedN = g.members.filter((m: Finding) => m.reviewed).length;
  const selN = keys.filter((k: string) => sel.has(k)).length;
  const owners: string[] = g.owners;
  const expanded = openGkey.has(g.gkey);
  const multi = g.members.length > 1;
  const rep: Finding = g.members[0];
  // Left border reflects SEVERITY (matches the sev badge), not the lane — a
  // uniform bar would read as meaningless, and magenta would collide with KEV.
  const sevColor = `var(--${g.severity === "info" ? "faint" : g.severity})`;

  return (
    <div style={{ borderLeft: `3px solid ${sevColor}` }}>
      <div className="frow" onClick={() => multi ? toggleGroup(g.gkey) : setOpenKey(rep.key)}>
        <div onClick={(e) => { e.stopPropagation(); toggleSel(keys); }} style={{ display: "flex", alignItems: "center" }}>
          <input type="checkbox" checked={selN === keys.length} ref={(el) => { if (el) el.indeterminate = selN > 0 && selN < keys.length; }} onChange={() => toggleSel(keys)} onClick={(e) => e.stopPropagation()} />
        </div>
        <span className="mono faint" style={{ width: 14, textAlign: "center" }}>{multi ? (expanded ? "▾" : "▸") : ""}</span>
        <span className={"sev " + (g.severity || "info")}>{(g.severity || "info").slice(0, 4)}</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div className="row" style={{ gap: 6, alignItems: "center" }}>
            <span style={{ fontWeight: 600 }} className="ellip">{g.title}</span>
            {g.kev && <span className="stbadge kev" title="CISA Known Exploited Vulnerabilities — seen exploited in the wild">KEV</span>}
            {g.verdict && <span className="stbadge">{g.verdict.toLowerCase()}</span>}
            {g.epss > 0 && <span className="faint mono" style={{ fontSize: 11 }} title="EPSS — probability of exploitation in the next 30 days">EPSS {g.epss}%</span>}
          </div>
          <div className="muted" style={{ fontSize: 11 }}>
            {g.cves.length > 0 ? <span className="mono">{g.cves.slice(0, 3).join(", ")}{g.cves.length > 3 ? "…" : ""} · </span> : null}
            {rep.source}
          </div>
        </div>
        <span className="chip" title={`${g.members.length} affected host${g.members.length === 1 ? "" : "s"}`} style={{ whiteSpace: "nowrap" }}>
          {g.members.length} host{g.members.length === 1 ? "" : "s"}
        </span>
        <div style={{ width: 108 }} onClick={(e) => e.stopPropagation()} title={`${reviewedN} of ${g.members.length} reviewed`}>
          <Meter label="" now={reviewedN} total={g.members.length} ok={reviewedN === g.members.length} />
        </div>
        <div className="row" style={{ gap: 2, width: 62, justifyContent: "flex-end" }}>
          {owners.slice(0, 3).map((o: string) => <Avatar key={o} name={o} sm online={c.online.includes(o)} />)}
        </div>
        <div className="frow-act row" onClick={(e) => e.stopPropagation()}>
          <button className="btn sm" title="mark whole issue reviewed" onClick={() => bulkReview(keys, reviewedN < keys.length)}>{reviewedN < keys.length ? "✓ all" : "↺"}</button>
          <button className="btn sm danger" title="dismiss whole issue as not-a-finding" onClick={() => keys.forEach((k: string) => { if (!c.dismissed[k]) dismiss(k, true); })}>✗</button>
        </div>
      </div>

      {expanded && multi && (
        <div style={{ background: "var(--surface2)" }}>
          {g.members.map((m: Finding) => {
            const o = ownerOf(m);
            return (
              <div key={m.key} className="frow sub click" onClick={() => setOpenKey(m.key)} style={c.dismissed[m.key] ? { opacity: .5 } : undefined}>
                <span style={{ width: 14 }} onClick={(e) => e.stopPropagation()}>
                  <input type="checkbox" checked={m.reviewed} onChange={() => bulkReview([m.key], !m.reviewed)} title={m.reviewed_by ? `reviewed by ${m.reviewed_by}` : "mark reviewed"} onClick={(e) => e.stopPropagation()} />
                </span>
                <span className="mono" style={{ flex: 1 }}>{m.ip}{m.port ? `:${m.port}` : ""}</span>
                {m.verdict && <span className="stbadge" style={{ marginRight: 6 }}>{m.verdict.toLowerCase()}</span>}
                {m.notes && <span title="has a note" style={{ marginRight: 6 }}>📝</span>}
                {o && <span title={`owner: ${o}`}><Avatar name={o} sm online={c.online.includes(o)} /></span>}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
