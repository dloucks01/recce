// Tiny helpers used across the collab subsystem — kept here so no component
// reinvents a hue() or initials() locally.

// Word-split initials ("John Doe" -> "JD", "alice" -> "AL"), capped at 2.
export const initials = (n: string): string =>
  (n || "?").trim().split(/\s+/).map((w) => w[0]).join("").toUpperCase().slice(0, 2) || "?";

export const hue = (n: string): number => {
  let h = 0;
  for (let i = 0; i < (n || "").length; i++) h = ((h << 5) - h + n.charCodeAt(i)) | 0;
  return (h % 360 + 360) % 360;
};

export function when(ts: number) {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

// Short relative time ("now" / "5m" / "2h" / "3d") for dense rows (activity, jobs).
export function timeAgo(tsSecs: number): string {
  const s = Math.round(Date.now() / 1000 - tsSecs);
  if (s < 60) return "now";
  if (s < 3600) return `${Math.round(s / 60)}m`;
  if (s < 86400) return `${Math.round(s / 3600)}h`;
  return `${Math.round(s / 86400)}d`;
}

// last_seen (unix-secs string) -> "just now" / "5m ago" / "offline" for roster.
export function seenAgo(lastSeen: string): string {
  const t = Number(lastSeen);
  return t ? when(t) : "offline";
}

export function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export const IP_RE = /\b\d{1,3}(?:\.\d{1,3}){3}\b/;

export const KIND_ICON: Record<string, string> = {
  assign: "👤", add: "＋", access: "🔓", dismiss: "🚫", tick: "✓", note: "✎",
};
