import { useEffect, useState } from "react";
import { Job } from "./api";

// One shared /api/jobs poller for the whole app. The header pill, the collab
// sidebar, and the scan tab all used to run their own 2–3s pollers against the
// same endpoint; this collapses them into a single interval with a subscriber
// fan-out. The poll only runs while at least one component is mounted, and
// stops when the last unsubscribes.
let jobs: Job[] = [];
const subs = new Set<(j: Job[]) => void>();
let timer: number | null = null;

async function poll() {
  try {
    const r = await fetch("/api/jobs");
    if (!r.ok) return;
    jobs = (await r.json()) || [];
    subs.forEach((fn) => fn(jobs));
  } catch { /* transient — keep the last snapshot */ }
}

function ensureRunning() {
  if (timer != null) return;
  poll();
  timer = window.setInterval(poll, 3000);
}

export function useJobs(): Job[] {
  const [snapshot, setSnapshot] = useState<Job[]>(jobs);
  useEffect(() => {
    subs.add(setSnapshot);
    ensureRunning();
    setSnapshot(jobs);            // sync any consumer mounting mid-cycle
    return () => {
      subs.delete(setSnapshot);
      if (subs.size === 0 && timer != null) { window.clearInterval(timer); timer = null; }
    };
  }, []);
  return snapshot;
}
