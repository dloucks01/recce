// Tiny helpers used across the collab subsystem — kept here so no component
// reinvents a hue() or initials() locally.

export const initials = (n: string) => n.trim().slice(0, 2).toUpperCase() || "?";

export const hue = (n: string) => {
  let h = 0;
  for (const ch of n) h = (h * 31 + ch.charCodeAt(0)) % 360;
  return h;
};

export function when(ts: number) {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
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
