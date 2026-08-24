import { useEffect, useMemo, useState } from "react";
import { SessionInfo, getDiff, getSessions } from "../api";
import { Nav } from "./shared";

// Every event that lands on the timeline is normalised to this shape so the
// renderer can be dumb: pick the icon, format the description, wire the click.
type TimelineEvent = {
  ts: number;
  kind: string;       // activity kind OR "session:caught" / "session:dropped"
  tester: string;
  text: string;
  ip?: string;        // if the event ties to a host — for click-to-open
  sessionId?: string; // if it ties to a session
};

const KIND_ICON: Record<string, string> = {
  session: "⌨",
  "session:caught": "⌨",
  "session:dropped": "⚠",
  assign: "👤",
  add: "➕",
  tick: "✓",
  note: "📝",
  scan: "🔍",
  import: "📥",
  label: "🏷",
  dismiss: "✗",
  chat: "💬",
  access: "🔓",
  cred: "🔑",
  finding: "🐞",
  review: "✓",
  port: "▩",
};

const IP_RE = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/;

export function Timeline({ nav }: { nav: Nav }) {
  const [events, setEvents] = useState<TimelineEvent[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [filter, setFilter] = useState<Set<string>>(new Set());
  const [testerFilter, setTesterFilter] = useState<string>("");

  useEffect(() => {
    (async () => {
      try {
        // since=1 pulls everything the diff endpoint has (activity + hosts)
        const [diff, sessions] = await Promise.all([getDiff(1), getSessions()]);
        const evs: TimelineEvent[] = [];
        for (const a of diff.activity) {
          evs.push({
            ts: a.ts, kind: a.kind || "event",
            tester: a.tester, text: a.text,
            ip: IP_RE.exec(a.text)?.[1],
          });
        }
        for (const s of sessions) {
          evs.push({
            ts: s.created, kind: "session:caught",
            tester: s.driver || "system",
            text: `shell caught from ${s.host_ip}${s.pty ? " (PTY)" : ""}${s.label ? ` — ${s.label}` : ""}`,
            ip: s.host_ip, sessionId: s.id,
          });
          if (s.status === "dead") {
            evs.push({
              ts: s.created + 1, kind: "session:dropped",
              tester: s.driver || "system",
              text: `session ${s.id.slice(0, 8)} dropped (${s.host_ip})`,
              ip: s.host_ip, sessionId: s.id,
            });
          }
        }
        evs.sort((a, b) => b.ts - a.ts);
        setEvents(evs);
      } catch (e) { setErr(String(e instanceof Error ? e.message : e)); }
    })();
  }, []);

  const kinds = useMemo(() => {
    if (!events) return [];
    const s = new Set<string>();
    events.forEach(e => s.add(e.kind));
    return [...s].sort();
  }, [events]);

  const testers = useMemo(() => {
    if (!events) return [];
    const s = new Set<string>();
    events.forEach(e => e.tester && s.add(e.tester));
    return [...s].sort();
  }, [events]);

  const shown = useMemo(() => {
    if (!events) return [];
    return events.filter(e =>
      (filter.size === 0 || filter.has(e.kind)) &&
      (!testerFilter || e.tester === testerFilter)
    );
  }, [events, filter, testerFilter]);

  // Group by day for readable scanning.
  const grouped = useMemo(() => {
    const g: Record<string, TimelineEvent[]> = {};
    for (const e of shown) {
      const d = new Date(e.ts * 1000);
      const day = d.toISOString().slice(0, 10);
      (g[day] ||= []).push(e);
    }
    return Object.entries(g).sort((a, b) => b[0].localeCompare(a[0]));
  }, [shown]);

  const toggleKind = (k: string) => setFilter(s => {
    const n = new Set(s);
    n.has(k) ? n.delete(k) : n.add(k);
    return n;
  });

  if (err) return <div className="err">{err}</div>;
  if (!events) return <div className="loading">Loading timeline…</div>;
  if (events.length === 0) return (
    <div className="empty">Nothing has happened yet — run a scan or attach a session and the timeline fills in.</div>
  );

  return (
    <div className="timeline-view">
      <section className="panel">
        <div className="panel-h">
          <h3>Engagement timeline</h3>
          <span className="muted">
            {events.length} event{events.length !== 1 ? "s" : ""}
            {shown.length !== events.length && ` · ${shown.length} shown`}
          </span>
        </div>
        <div className="tl-filters">
          <div className="tl-chips">
            {kinds.map(k => (
              <button key={k} className={"chip" + (filter.has(k) ? " sel" : "")}
                      onClick={() => toggleKind(k)} title={`filter: ${k}`}>
                {KIND_ICON[k] || "•"} {k}
              </button>
            ))}
            {filter.size > 0 && (
              <button className="linkish" onClick={() => setFilter(new Set())}>clear</button>
            )}
          </div>
          <select className="scan-in" value={testerFilter} onChange={e => setTesterFilter(e.target.value)}
                  style={{maxWidth: 160}}>
            <option value="">all testers</option>
            {testers.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
      </section>

      {grouped.map(([day, evs]) => (
        <section className="panel tl-day" key={day}>
          <div className="tl-day-h">
            <span className="tl-day-label">{formatDay(day)}</span>
            <span className="muted">{evs.length} event{evs.length !== 1 ? "s" : ""}</span>
          </div>
          <ul className="tl-list">
            {evs.map((e, i) => (
              <li key={i} className={"tl-event tl-k-" + e.kind.replace(/[^a-z]/gi, "-")}>
                <span className="tl-time mono">{formatTime(e.ts)}</span>
                <span className="tl-icon" title={e.kind}>{KIND_ICON[e.kind] || "•"}</span>
                <span className="tl-tester">{e.tester}</span>
                <span className="tl-text">{e.text}</span>
                <span className="tl-actions">
                  {e.sessionId && nav.toSessions && (
                    <button className="linkish" onClick={() => nav.toSessions!()}
                            title="open sessions">session →</button>
                  )}
                  {e.ip && (
                    <button className="linkish" onClick={() => nav.openHost(e.ip!)}
                            title={`open ${e.ip}`}>{e.ip} →</button>
                  )}
                </span>
              </li>
            ))}
          </ul>
        </section>
      ))}
    </div>
  );
}

function formatTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function formatDay(iso: string): string {
  const today = new Date().toISOString().slice(0, 10);
  const y = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
  if (iso === today) return "Today";
  if (iso === y) return "Yesterday";
  return new Date(iso + "T00:00:00").toLocaleDateString(undefined, { weekday: "long", month: "short", day: "numeric" });
}
