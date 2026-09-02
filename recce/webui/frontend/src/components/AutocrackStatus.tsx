/**
 * AutocrackStatus — a small always-visible pill for the header that surfaces
 * the auto-crack watcher's state so the tester can tell at a glance whether
 * it's on, when it last ticked, and what it has recovered.
 *
 * Backed by GET /api/autocrack/status (see recce/webui/routes/autocrack_status.py).
 * Polls every 30s: cheap, and the watcher itself only ticks every 60s so a
 * tighter poll wouldn't reveal anything new. Silent-fail on fetch errors —
 * a temporarily-down API shouldn't paint an alarming red state; we go grey
 * ("unknown"). If the tester loaded a page against a build with the route
 * missing, the pill stays grey and the app is otherwise unaffected.
 *
 * Kept as inline styles (not a new .css entry) so the widget is self-contained
 * and the diff for this feature stays confined to additions only.
 */
import { useEffect, useState } from "react";

type AutocrackStatusPayload = {
  running: boolean;
  last_tick_iso: string;
  queue_size: number;
  cracked_since_start: number;
  most_recent_crack: {
    username: string;
    hash_type: string;
    ts_iso: string;
  } | null;
};

// Colour of the dot maps directly to "should the tester worry":
//   green  — watcher up AND has ticked at least once
//   amber  — watcher up but has NOT yet ticked (fresh startup)
//   red    — watcher explicitly reported not running
//   grey   — status unknown (fetch failed / route missing)
type Dot = "green" | "amber" | "red" | "grey";

function dotOf(s: AutocrackStatusPayload | null): Dot {
  if (!s) return "grey";
  if (!s.running) return "red";
  return s.last_tick_iso ? "green" : "amber";
}

const DOT_COLOR: Record<Dot, string> = {
  green: "#22c55e",
  amber: "#f59e0b",
  red:   "#ef4444",
  grey:  "#94a3b8",
};

const DOT_LABEL: Record<Dot, string> = {
  green: "watcher running",
  amber: "watcher running — no tick yet",
  red:   "watcher stopped",
  grey:  "watcher status unknown",
};

// Human-friendly "3m ago" for the tooltip. Empty string → "never".
function agoOf(iso: string): string {
  if (!iso) return "never";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return iso;
  const secs = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
  return `${Math.round(secs / 86400)}d ago`;
}

function tooltipFor(s: AutocrackStatusPayload | null): string {
  if (!s) return "auto-crack watcher: status unknown";
  const lines: string[] = [];
  lines.push(`auto-crack watcher: ${s.running ? "running" : "stopped"}`);
  lines.push(`last tick: ${agoOf(s.last_tick_iso)}`);
  lines.push(`queue: ${s.queue_size}`);
  lines.push(`cracked since start: ${s.cracked_since_start}`);
  if (s.most_recent_crack) {
    const m = s.most_recent_crack;
    lines.push(`latest: ${m.username} (${m.hash_type}) — ${agoOf(m.ts_iso)}`);
  }
  return lines.join("\n");
}

const POLL_MS = 30_000;

export function AutocrackStatus() {
  const [state, setState] = useState<AutocrackStatusPayload | null>(null);

  useEffect(() => {
    let stopped = false;
    async function pull() {
      try {
        const r = await fetch("/api/autocrack/status");
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        const j: AutocrackStatusPayload = await r.json();
        if (!stopped) setState(j);
      } catch {
        // Silent-grey on error: the watcher itself may or may not be up;
        // we simply don't know, and a red badge would be dishonest.
        if (!stopped) setState(null);
      }
    }
    pull();
    const h = window.setInterval(pull, POLL_MS);
    return () => { stopped = true; window.clearInterval(h); };
  }, []);

  const dot = dotOf(state);
  const count = state?.cracked_since_start ?? 0;

  return (
    <div
      className="autocrack-pill"
      title={tooltipFor(state)}
      aria-label={`${DOT_LABEL[dot]}; ${count} cracked since start`}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        padding: "4px 10px",
        borderRadius: 20,
        border: "1px solid var(--line, #d0d7de)",
        background: "var(--surface2, transparent)",
        fontFamily: "var(--mono, ui-monospace, SFMono-Regular, monospace)",
        fontSize: 12,
        color: "var(--text, inherit)",
        lineHeight: 1,
        userSelect: "none",
      }}
    >
      <span
        aria-hidden="true"
        style={{
          width: 8,
          height: 8,
          borderRadius: "50%",
          background: DOT_COLOR[dot],
          boxShadow: dot === "green"
            ? `0 0 4px ${DOT_COLOR[dot]}`
            : "none",
          flex: "0 0 auto",
        }}
      />
      <span>crack {count}</span>
    </div>
  );
}

export default AutocrackStatus;
