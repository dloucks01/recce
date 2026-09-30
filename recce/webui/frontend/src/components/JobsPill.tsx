import { useJobs } from "../useJobs";

/**
 * Header pill: at-a-glance count of running scan jobs. Complements
 * AutocrackStatus + ProxyBadge (same slot, same self-refreshing pattern).
 * Clicking navigates to the Scan tab AND pops the terminal drawer for
 * the most-recently-started running job — the operator's expectation
 * from the "scan running" label. When multiple scans are up, the drawer
 * lands on the newest (most likely the one the operator just launched).
 *
 * Only renders when at least one job is running — a clean header when
 * the engagement is idle. Polls /api/jobs every 3s (matches the interval
 * ScanTab + CollabSidebar already poll at, keeping the payload cached).
 */
export function JobsPill({ onOpenConsole }: { onOpenConsole?: (jobId: string) => void }) {
  const running = useJobs().filter((j) => j.status === "running");

  if (running.length === 0) return null;

  const title = running
    .map((j) => {
      const bar = j.progress
        ? (j.progress.total != null
            ? ` · ${j.progress.done}/${j.progress.total}`
            : ` · ${j.progress.done} done`)
        : "";
      return `${j.tester || "system"} · ${j.cmd.slice(0, 80)}${bar}`;
    })
    .join("\n");

  // P7-C5: aggregate progress across the running jobs — the widest bar wins
  // so the header pill visibly moves even when multiple scans are up. When
  // no job has a total, we omit the bar and just show the count.
  const totalKnown = running.filter((j) => j.progress?.total != null);
  const aggPct = totalKnown.length
    ? Math.max(...totalKnown.map((j) => Math.min(100,
        (j.progress!.done / Math.max(1, j.progress!.total!)) * 100)))
    : null;

  const onClick = () => {
    if (!onOpenConsole || running.length === 0) return;
    // Pick the most-recently-STARTED running job — usually the one the
    // operator just launched and wants to watch. Falls back to running[0]
    // if start times are equal.
    const target = [...running].sort((a, b) => (b.started || 0) - (a.started || 0))[0];
    onOpenConsole(target.id);
  };

  return (
    <button className="jobs-pill"
            title={title}
            onClick={onClick}>
      <span className="jobs-pill-dot" />
      <span className="jobs-pill-count">{running.length}</span>
      <span className="jobs-pill-label">
        {running.length === 1 ? "scan running" : "scans running"}
      </span>
      {aggPct != null && (
        <span className="jobs-pill-bar">
          <span className="jobs-pill-bar-fill"
                style={{ width: `${Math.max(4, aggPct)}%` }} />
        </span>
      )}
    </button>
  );
}
