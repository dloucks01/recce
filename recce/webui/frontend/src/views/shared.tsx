// Shared types and helpers across the view modules.

export type FindingFilters = {
  sev: string; host: string; kev: boolean; unreviewed: boolean; leads: boolean; q: string;
};
export type Nav = {
  toFindings: (o?: Partial<FindingFilters>) => void;
  toHosts: (o?: { q?: string; owner?: string }) => void;
  toAct: () => void;
  openHost: (ip: string) => void;
};

export const ARCH_ICON: Record<string, string> = {
  loot: "🔓", crack: "🔑", spray: "💧", exploit: "💥", escalate: "⬆️",
  pivot: "↪️", "ad-path": "👑", "default-cred": "🔐",
};
// Display labels — keep the internal archetype keys, but present them professionally
// (e.g. "loot" reads as "collect" in the UI).
const ARCH_LABEL: Record<string, string> = { loot: "collect" };
export const archLabel = (a: string) => ARCH_LABEL[a] || a;

export const ARCHETYPES = ["loot", "spray", "exploit", "escalate", "crack", "default-cred", "ad-path", "pivot"];
