import { useState, useEffect, useRef, useCallback } from "react";
import { useCollab } from "./collab";
import { ChatPanel } from "./ChatPanel";
import { AssignmentsPanel } from "./AssignmentsPanel";
import { CredsSummary } from "./components/CredsSummary";
import { Host, postJobCancel } from "./api";
import { toast } from "./toast";
import { Nav } from "./views";

function useSidebarResize(defaultW = 340) {
  const [width, setWidth] = useState(() => {
    const w = Number(localStorage.getItem("recce.sidebar-w"));
    return w >= 240 ? w : defaultW;
  });
  useEffect(() => { localStorage.setItem("recce.sidebar-w", String(Math.round(width))); }, [width]);
  const startResize = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    const onMove = (ev: MouseEvent) =>
      setWidth(Math.min(Math.max(240, window.innerWidth - ev.clientX), 600));
    const onUp = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      document.body.style.userSelect = "";
    };
    document.body.style.userSelect = "none";
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  }, []);
  return { width, startResize };
}

interface Job {
  id: string;
  status: "running" | "done" | "failed";
  cmd: string;
  tester: string;
  started: number;
  // P7-C5: throttled progress parsed from stdout. Null for short jobs
  // (spray/act/run callable jobs, quick scans that never emitted the
  // authoritative-target announcement). When present, `total` may
  // still be null — render as "N done" chip without a bar.
  progress?: { done: number; total: number | null; phase: string | null } | null;
}

// Backend emits activity as {ts, tester, kind, text} — kind is the discriminator,
// text is the pre-formatted human-readable line. Keep the icon table close to it.
const ACTIVITY_ICON: Record<string, string> = {
  assign: "👤", add: "➕", tick: "✓", note: "📝", scan: "🔍",
  import: "📥", label: "🏷", dismiss: "✗", chat: "💬", session: "⌨",
};

export function CollabSidebar({ hosts, nav }: { hosts: Host[]; nav?: Nav }) {
  const { c, me } = useCollab();
  const [jobs, setJobs] = useState<Job[]>([]);
  const [tab, setTab] = useState<"status" | "assign" | "activity" | "creds" | "chat">("status");
  const [autoScroll, setAutoScroll] = useState(true);
  const activityRef = useRef<HTMLDivElement>(null);
  const { width: sidebarWidth, startResize } = useSidebarResize();

  // Poll running jobs
  useEffect(() => {
    async function pollJobs() {
      try {
        const res = await fetch("/api/jobs");
        const data = await res.json();
        setJobs(data || []);
      } catch {}
    }
    pollJobs();
    const id = window.setInterval(pollJobs, 3000);
    return () => window.clearInterval(id);
  }, []);

  // Auto-scroll activity
  useEffect(() => {
    if (autoScroll && activityRef.current) {
      activityRef.current.scrollTop = activityRef.current.scrollHeight;
    }
  }, [c.activity, autoScroll]);

  const runningJobs = jobs.filter((j) => j.status === "running");
  const myHosts = hosts.filter((h) => c.assignments[h.ip] === me);
  const myPending = myHosts.filter((h) => !h.reviewed).length;
  const recentActivity = c.activity.slice(-20).reverse();

  return (
    <div className="collab-sidebar" style={{ width: sidebarWidth }}>
      <div className="sidebar-resize" onMouseDown={startResize} />
      {/* Header */}
      <div className="sidebar-header">
        <h3>Team</h3>
        <div className="sidebar-tabs">
          {/* Emoji-only tabs: `title` gives a hover tooltip but doesn't
              reach every screen reader — `aria-label` is the authoritative
              accessible name. Keep both so mouse-hover users still get
              the label, too. */}
          <button
            className={`tab-btn ${tab === "status" ? "active" : ""}`}
            onClick={() => setTab("status")}
            title="scanning status" aria-label="scanning status"
          >
            ▌
          </button>
          <button
            className={`tab-btn ${tab === "assign" ? "active" : ""}`}
            onClick={() => setTab("assign")}
            title="host assignments" aria-label="host assignments"
          >
            👤
          </button>
          <button
            className={`tab-btn ${tab === "activity" ? "active" : ""}`}
            onClick={() => setTab("activity")}
            title="activity log" aria-label="activity log"
          >
            ⚡
          </button>
          <button
            className={`tab-btn ${tab === "creds" ? "active" : ""}`}
            onClick={() => setTab("creds")}
            title="shared credentials" aria-label="shared credentials"
          >
            🔑
          </button>
          <button
            className={`tab-btn ${tab === "chat" ? "active" : ""}`}
            onClick={() => setTab("chat")}
            title="team chat" aria-label="team chat"
          >
            💬
          </button>
        </div>
      </div>

      {/* Status Tab */}
      {tab === "status" && (
        <div className="sidebar-content status-panel">
          {/* Running jobs */}
          {runningJobs.length > 0 && (
            <section className="sb-section">
              <div className="sb-section-h">
                <h4>Scanning now</h4>
                <span className="count">{runningJobs.length}</span>
              </div>
              {runningJobs.map((j) => (
                <div key={j.id} className={`job-card ${j.tester === me ? "mine" : ""}`}>
                  <div className="job-tester">
                    <span className="avatar xs" style={{ background: `hsl(${hue(j.tester)} 55% 45%)` }}>
                      {initials(j.tester)}
                    </span>
                    <span className="tester-name">{j.tester === me ? "You" : j.tester || "system"}</span>
                  </div>
                  <div className="job-cmd" title={j.cmd}>
                    {j.cmd.split(" ").slice(0, 3).join(" ")}
                  </div>
                  <div className="job-time">{timeAgo(j.started)}</div>
                  {j.progress && (
                    <div className="job-progress"
                         title={j.progress.total != null
                           ? `${j.progress.done} of ${j.progress.total} host(s) (${j.progress.phase || "…"})`
                           : `${j.progress.done} host(s) done · total unknown`}>
                      {j.progress.total != null ? (
                        <>
                          <div className="job-progress-bar">
                            <div className="job-progress-fill"
                                 style={{ width: `${Math.min(100,
                                   Math.max(2, (j.progress.done / Math.max(1, j.progress.total)) * 100))}%` }} />
                          </div>
                          <div className="job-progress-label">
                            {j.progress.done}/{j.progress.total}
                            {j.progress.phase && <span className="muted"> · {j.progress.phase}</span>}
                          </div>
                        </>
                      ) : (
                        <div className="job-progress-label">
                          {j.progress.done} done
                          {j.progress.phase && <span className="muted"> · {j.progress.phase}</span>}
                        </div>
                      )}
                    </div>
                  )}
                  <button className="job-cancel"
                          title="cancel this running job"
                          onClick={async () => {
                            if (!confirm(`Cancel job "${j.cmd.slice(0, 60)}"?`)) return;
                            try {
                              await postJobCancel(j.id);
                              toast.show("Cancel signalled — job winding down");
                            } catch (e) {
                              toast.show(`Cancel failed: ${(e as Error).message}`);
                            }
                          }}>
                    ✕
                  </button>
                </div>
              ))}
            </section>
          )}

          {/* My queue */}
          {myPending > 0 && (
            <section className="sb-section">
              <div className="sb-section-h">
                <h4>My queue</h4>
                <span className="count">{myPending}</span>
              </div>
              <button className="queue-btn" onClick={() => nav?.toHosts?.({ owner: me })}>
                {myPending} host{myPending !== 1 ? "s" : ""} need review
              </button>
            </section>
          )}

          {/* Team coverage */}
          {c.online.length > 0 && (
            <section className="sb-section">
              <div className="sb-section-h">
                <h4>Online</h4>
                <span className="count">{c.online.length}</span>
              </div>
              <div className="online-list">
                {c.online.map((t) => (
                  <div key={t} className={`online-item ${t === me ? "me" : ""}`}>
                    <span className="avatar xs" style={{ background: `hsl(${hue(t)} 55% 45%)` }}>
                      {initials(t)}
                    </span>
                    <span className="tester-name">{t === me ? "You" : t}</span>
                    <span className="online-dot" title="online" />
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Coverage snapshot */}
          {Object.keys(c.assignments).length > 0 && (
            <section className="sb-section">
              <div className="sb-section-h">
                <h4>Coverage</h4>
              </div>
              <div className="coverage-grid">
                <div className="cov-stat">
                  <span className="cov-label">Claimed</span>
                  <span className="cov-value">{Object.keys(c.assignments).length}</span>
                </div>
                <div className="cov-stat">
                  <span className="cov-label">Reviewed</span>
                  <span className="cov-value">
                    {Object.values(c.assignments).filter((ip) =>
                      hosts.find((h) => h.ip === ip && h.reviewed)
                    ).length}
                  </span>
                </div>
              </div>
            </section>
          )}
        </div>
      )}

      {/* Activity Tab */}
      {tab === "activity" && (
        <div className="sidebar-content activity-panel">
          <div className="activity-scroll" ref={activityRef}>
            {recentActivity.length === 0 ? (
              <div className="empty-state">No activity yet</div>
            ) : (
              recentActivity.map((a, i) => (
                <div key={i} className={`activity-item type-${a.kind}`}>
                  <span className="activity-icon">{ACTIVITY_ICON[a.kind] || "◦"}</span>
                  <div className="activity-text">
                    <span className="activity-who">{a.tester}</span>
                    <span className="activity-action">{a.text}</span>
                  </div>
                  <span className="activity-time">{timeAgo(a.ts)}</span>
                </div>
              )))
            }
          </div>
          <button className="autoscroll-toggle" onClick={() => setAutoScroll(!autoScroll)}>
            {autoScroll ? "📌 Following" : "📌 Pinned"}
          </button>
        </div>
      )}

      {/* Assignments Tab */}
      {tab === "assign" && (
        <div className="sidebar-content">
          <AssignmentsPanel hosts={hosts} />
        </div>
      )}

      {/* Credentials Tab — compact summary strip (P7-B1). The full
          Credentials view lives on the top-level Credentials tab; the
          sidebar is quick-glance only + a jump link. */}
      {tab === "creds" && (
        <div className="sidebar-content">
          <CredsSummary nav={nav} />
        </div>
      )}

      {/* Chat Tab */}
      {tab === "chat" && (
        <div className="sidebar-content">
          <ChatPanel tester={me} />
        </div>
      )}
    </div>
  );
}

// Helpers
function hue(name: string | null | undefined): number {
  if (!name) return 200;
  let h = 0;
  for (let i = 0; i < name.length; i++) {
    h = ((h << 5) - h + name.charCodeAt(i)) | 0;
  }
  return (h % 360 + 360) % 360;
}

function initials(name: string | null | undefined): string {
  if (!name) return "?";
  return name.split(" ").map((w) => w[0]).join("").toUpperCase().slice(0, 2);
}

function timeAgo(ts: number): string {
  const s = Math.round((Date.now() - ts * 1000) / 1000);
  if (s < 60) return "now";
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86400) return `${Math.round(s / 3600)}h`;
  return `${Math.round(s / 86400)}d`;
}
