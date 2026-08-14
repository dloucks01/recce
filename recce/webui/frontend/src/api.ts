// Types + fetch helpers for the recce workbench API.

export type Finding = {
  key: string; reviewed: boolean; notes: string;
  severity: string; title: string; ip: string; port: number | null;
  cve: string; cves: string[]; kev: boolean; epss: number;
  tier: string; source: string; confidence: string;
};
export type Port = { port: number; proto: string; service: string; product: string };
export type Host = {
  ip: string; key: string; hostname: string; os: string; roles: string[]; up: boolean;
  ports: Port[]; findings: Record<string, number>;
  enumerated: boolean; vuln_scanned: boolean; access: boolean;
  db: boolean; privesc: boolean; credenum: boolean;
  reviewed: boolean; notes: string;
};
export type KevFinding = {
  key: string; ip: string; port: number | null; title: string;
  severity: string; cve: string; epss: number;
};
export type TopHost = {
  ip: string; hostname: string; os: string; roles: string[];
  findings: Record<string, number>; score: number;
};
export type Overview = {
  name: string; hosts_up: number; hosts_total: number;
  scope_subnets: number; scope_size: number; services: number;
  by_severity: Record<string, number>; findings_total: number;
  kev_total: number; kev_findings: KevFinding[]; top_hosts: TopHost[];
  reviewed: number; enumerated: number; accessed: number;
};

export const SEVS = ["critical", "high", "medium", "low"];
export const SEV_ALL = ["critical", "high", "medium", "low", "info"];

function tester(): string {
  return localStorage.getItem("recce.tester") || "someone";
}
const jsonHeaders = () => ({ "Content-Type": "application/json", "X-Tester": tester() });

export async function getJSON<T>(url: string): Promise<T> {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url}: ${r.status}`);
  return r.json();
}

export async function fetchAll(): Promise<[Overview, Finding[], Host[]]> {
  return Promise.all([
    getJSON<Overview>("/api/overview"),
    getJSON<Finding[]>("/api/findings"),
    getJSON<Host[]>("/api/hosts"),
  ]);
}

export async function postTick(key: string, reviewed: boolean) {
  await fetch("/api/tick", {
    method: "POST", headers: jsonHeaders(),
    body: JSON.stringify({ key, reviewed }),
  });
}

export async function postNote(key: string, note: string) {
  await fetch("/api/note", {
    method: "POST", headers: jsonHeaders(),
    body: JSON.stringify({ key, note }),
  });
}

export async function postScan(targets: string, profile: string): Promise<{ id: string }> {
  const r = await fetch("/api/scan", {
    method: "POST", headers: jsonHeaders(),
    body: JSON.stringify({ targets, phase: "scan", profile }),
  });
  if (!r.ok) throw new Error((await r.json()).detail ?? r.statusText);
  return r.json();
}

// weighted risk score for sorting hosts most-dangerous-first
export function hostScore(f: Record<string, number>): number {
  return (f.critical || 0) * 1000 + (f.high || 0) * 100 + (f.medium || 0) * 10 + (f.low || 0);
}
export function sevTotal(f: Record<string, number>): number {
  return SEVS.reduce((n, s) => n + (f[s] || 0), 0);
}
