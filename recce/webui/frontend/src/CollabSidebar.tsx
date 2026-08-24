import { useState, useEffect, useRef, useCallback } from "react";
import { useCollab } from "./collab";
import { ChatPanel } from "./ChatPanel";
import { AssignmentsPanel } from "./AssignmentsPanel";
import { CredentialsPanel } from "./CredentialsPanel";

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
}

interface Activity {
  type: string;
  by?: string;
  tester?: string;
  ip?: string;
  ts: number;
  what?: string;
}

export function CollabSidebar({ hosts, nav }: { hosts: any[]; nav?: any }) {
  const { c, me } = useCollab();
  const [jobs, setJobs] = useState<Job[]>([]);
  const [tab, setTab] = useState<"status" | "assign" | "activity" | "creds" | "chat">("status");
  const [autoScroll, setAutoScroll] = useState(true);
  const activityRef = useRef<HTMLDivElement>(null);
  const chatRef = useRef<HTMLDivElement>(null);
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

  // Testers online now
  const online = [...new Set([...c.online, ...runningJobs.map((j) => j.tester)])];

  return (
    <div className="collab-sidebar" style={{ width: sidebarWidth }}>
      <div className="sidebar-resize" onMouseDown={startResize} />
      {/* Header */}
      <div className="sidebar-header">
        <h3>Team</h3>
        <div className="sidebar-tabs">
          <button
            className={`tab-btn ${tab === "status" ? "active" : ""}`}
            onClick={() => setTab("status")}
            title="scanning status"
          >
            ▌
          </button>
          <button
            className={`tab-btn ${tab === "assign" ? "active" : ""}`}
            onClick={() => setTab("assign")}
            title="host assignments"
          >
            👤
          </button>
          <button
            className={`tab-btn ${tab === "activity" ? "active" : ""}`}
            onClick={() => setTab("activity")}
            title="activity log"
          >
            ⚡
          </button>
          <button
            className={`tab-btn ${tab === "creds" ? "active" : ""}`}
            onClick={() => setTab("creds")}
            title="shared credentials"
          >
            🔑
          </button>
          <button
            className={`tab-btn ${tab === "chat" ? "active" : ""}`}
            onClick={() => setTab("chat")}
            title="team chat"
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
              recentActivity.map((a, i) => {
                const icon = a.type === "assign" ? "👤" : a.type === "add" ? "➕" : a.type === "tick" ? "✓"
                  : a.type === "note" ? "📝" : a.type === "scan" ? "🔍" : a.type === "import" ? "📥"
                  : a.type === "label" ? "🏷" : a.type === "dismiss" ? "✗" : a.type === "chat" ? "💬" : "◦";
                const action = a.type === "assign" ? `claimed ${a.ip || "a host"}`
                  : a.type === "add" ? `added a ${a.what || "item"}`
                  : a.type === "tick" ? "reviewed a finding"
                  : a.type === "note" ? "left a note"
                  : a.type === "scan" ? "ran a scan"
                  : a.type === "import" ? "imported data"
                  : a.type === "label" ? `labeled ${a.ip || "a host"}`
                  : a.type === "dismiss" ? "dismissed a finding"
                  : a.type === "chat" ? "sent a message"
                  : (a as any).text || a.type || "activity";
                return (
                  <div key={i} className={`activity-item type-${a.type}`}>
                    <span className="activity-icon">{icon}</span>
                    <div className="activity-text">
                      <span className="activity-who">{a.by || a.tester}</span>
                      <span className="activity-action">{action}</span>
                    </div>
                    <span className="activity-time">{timeAgo(a.ts)}</span>
                  </div>
                );
              }))
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

      {/* Credentials Tab */}
      {tab === "creds" && (
        <div className="sidebar-content">
          <CredentialsPanel />
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
