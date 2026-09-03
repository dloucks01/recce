import { useEffect, useState } from "react";

type Job = {
  id: string;
  status: "running" | "done" | "failed";
  cmd: string;
  tester: string;
  started: number;
};

/**
 * P7-C6 header pill: at-a-glance count of running scan jobs. Complements
 * AutocrackStatus + ProxyBadge (same slot, same self-refreshing pattern).
 * Clicking scrolls to / focuses the Scan console via the shared
 * `#scan-console-body` selector when it's open on-screen; otherwise it
 * just briefly pulses to remind the operator to open the Scan tab.
 *
 * Only renders when at least one job is running — a clean header when
 * the engagement is idle. Polls /api/jobs every 3s (matches the interval
 * ScanTab + CollabSidebar already poll at, keeping the payload cached).
 */
export function JobsPill() {
  const [running, setRunning] = useState<Job[]>([]);
  const [pulse, setPulse] = useState(false);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const r = await fetch("/api/jobs");
        if (!r.ok) return;
        const jobs: Job[] = await r.json();
        if (!alive) return;
        setRunning(jobs.filter((j) => j.status === "running"));
      } catch { /* silent */ }
    };
    tick();
    const t = window.setInterval(tick, 3000);
    return () => { alive = false; window.clearInterval(t); };
  }, []);

  if (running.length === 0) return null;

  const title = running
    .map((j) => `${j.tester || "system"} · ${j.cmd.slice(0, 80)}`)
    .join("\n");

  const onClick = () => {
    // Prefer scrolling the drawer into view (P7-B2 rendered it as a
    // fixed drawer). If it's minimized, the pill click puts a brief
    // pulse on this header widget so the operator knows to expand it.
    const drawer = document.querySelector<HTMLElement>(".scan-console-drawer");
    if (drawer) {
      drawer.scrollIntoView({ behavior: "smooth", block: "end" });
    } else {
      const pill = document.querySelector<HTMLElement>(".scan-console-pill");
      if (pill) {
        pill.scrollIntoView({ behavior: "smooth", block: "end" });
        pill.animate([{ transform: "scale(1)" }, { transform: "scale(1.15)" },
                      { transform: "scale(1)" }], { duration: 400 });
      } else {
        setPulse(true); window.setTimeout(() => setPulse(false), 500);
      }
    }
  };

  return (
    <button className={"jobs-pill" + (pulse ? " pulse" : "")}
            title={title}
            onClick={onClick}>
      <span className="jobs-pill-dot" />
      <span className="jobs-pill-count">{running.length}</span>
      <span className="jobs-pill-label">
        {running.length === 1 ? "scan running" : "scans running"}
      </span>
    </button>
  );
}
