import { useCollab } from "./CollabContext";
import { hue, initials } from "./_shared";

export type OwnerStat = { total: number; done: number };

export function ownerStats(assignments: Record<string, string>, reviewedByIp: Record<string, boolean>) {
  const m: Record<string, OwnerStat> = {};
  for (const [ip, t] of Object.entries(assignments)) {
    const s = m[t] || (m[t] = { total: 0, done: 0 });
    s.total++; if (reviewedByIp[ip]) s.done++;
  }
  return m;
}

// A tiny "done/total" badge for a host's owner — surfaces per-tester progress inline.
export function OwnerProgress({ ip, stats }: { ip: string; stats: Record<string, OwnerStat> }) {
  const { c } = useCollab();
  const owner = c.assignments[ip];
  const s = owner && stats[owner];
  if (!s) return null;
  return <span className={"ownerprog mono" + (s.done === s.total ? " full" : "")}
               title={`${owner}: ${s.done}/${s.total} hosts done`}>{s.done}/{s.total}</span>;
}

// One-click personal focus: my claimed hosts that aren't reviewed yet.
export function MyQueue({ hosts, onOpen }:
  { hosts: { ip: string; reviewed: boolean }[]; onOpen: () => void }) {
  const { c, me } = useCollab();
  const mine = hosts.filter((h) => c.assignments[h.ip] === me);
  if (mine.length === 0) return null;
  const left = mine.filter((h) => !h.reviewed).length;
  return (
    <button className={"myqueue" + (left === 0 ? " clear" : "")} onClick={onOpen}
            title="my claimed hosts that still need review">
      ★ My queue {left === 0 ? "✓" : <span className="mq-n">{left}</span>}
    </button>
  );
}

// Dashboard panel: who owns how much of the scope, and how much is still unclaimed.
export function TeamCoverage(
  { hostsUp, reviewedByIp, onOpen }:
  { hostsUp: number; reviewedByIp: Record<string, boolean>; onOpen: (owner: string) => void }
) {
  const { c, me } = useCollab();
  const stat = ownerStats(c.assignments, reviewedByIp);
  const assigned = Object.keys(c.assignments).length;
  const unclaimed = Math.max(0, hostsUp - assigned);
  const testers = [...new Set([...c.online, ...Object.keys(stat)])]
    .sort((a, b) => (stat[b]?.total || 0) - (stat[a]?.total || 0) || a.localeCompare(b));
  if (testers.length <= 1 && assigned === 0) return null;
  const max = Math.max(1, unclaimed, ...Object.values(stat).map((s) => s.total));
  return (
    <section className="panel teampanel">
      <div className="panel-h"><h3>Team coverage</h3>
        <span className="panel-sub">hosts claimed · done — click a row to drill in</span>
        <button className="link" onClick={() => onOpen("all")}>hosts →</button></div>
      <ul className="teamlist">
        {testers.map((t) => {
          const s = stat[t] || { total: 0, done: 0 };
          return (
            <li key={t} onClick={() => onOpen(t)} title={`show ${t}'s hosts`}>
              <span className="avatar sm" style={{ background: `hsl(${hue(t)} 55% 45%)` }}>{initials(t)}</span>
              <span className="tm-name">{t === me ? `${t} (you)` : t}
                {c.online.includes(t) && <span className="tm-dot" title="online" />}</span>
              <div className="tm-track">
                <div className="tm-fill" style={{ width: `${(100 * s.total) / max}%` }}>
                  <div className="tm-done" style={{ width: s.total ? `${(100 * s.done) / s.total}%` : "0" }} />
                </div>
              </div>
              <span className="tm-n mono">{s.done}/{s.total}</span>
            </li>
          );
        })}
        <li className="tm-unclaimed" onClick={() => onOpen("unclaimed")} title="show unclaimed hosts">
          <span className="avatar sm more">?</span>
          <span className="tm-name">unclaimed</span>
          <div className="tm-track"><div className="tm-fill unc" style={{ width: `${(100 * unclaimed) / max}%` }} /></div>
          <span className="tm-n mono">{unclaimed}</span>
        </li>
      </ul>
    </section>
  );
}
