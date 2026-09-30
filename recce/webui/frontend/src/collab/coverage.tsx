import { useCollab } from "./CollabContext";

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

