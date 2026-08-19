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

export type Account = {
  kind: string; name: string; domain: string; rid: string; detail: string;
  attrs: Record<string, string>;
};
export type VulnDetail = Finding & {
  output: string; remediation: string; cwes: string[];
  qod: number; qod_type: string; state: string;
};
export type HostDetail = Host & {
  access_detail: string; smb_signing: string; defenses: string[];
  ports: (Port & { state?: string; version?: string; banner?: string })[];
  vulns: VulnDetail[]; accounts: Account[];
};
export async function getHost(ip: string) {
  return getJSON<HostDetail>(`/api/host/${encodeURIComponent(ip)}`);
}

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

export type ImportResult =
  | { mode: "job"; id: string; kind: string }
  | { mode: "done"; kind: string; added: number; summary: string };

// Fold external tool output (nmap, netexec, GetUserSPNs/GetNPUsers/secretsdump,
// on-target loot) into the live engagement. kind "auto" lets the server sniff it.
export async function postImport(content: string, filename: string, kind: string,
                                 encoding = ""): Promise<ImportResult> {
  const r = await fetch("/api/import", {
    method: "POST", headers: jsonHeaders(),
    body: JSON.stringify({ content, filename, kind, encoding }),
  });
  if (!r.ok) throw new Error((await r.json()).detail ?? r.statusText);
  return r.json();
}

// --- Act phase / Loot / ATT&CK ------------------------------------------------
export type ActCard = {
  archetype: string; title: string; target: string; command: string; yields: string;
  safety: string; tier: number; score: number; count: number;
  attack_id: string; attack_name: string; cwe: string; verify_first: boolean;
  why: string; needs: string[];
};
export type ActPlan = { top: ActCard[]; tiers: { tier: number; label: string; cards: ActCard[] }[] };
export type Credential = {
  username: string; secret: string; kind: string; domain: string;
  source: string; origin_ip: string; notes: string; label: string;
};
export type AttackTech = { id: string; name: string; url: string; hosts: string[] };
export type AttackCoverage = {
  technique_count: number; tactic_count: number;
  tactics: { tactic: string; tactic_id: string; techniques: AttackTech[] }[];
};
export const getAct = () => getJSON<ActPlan>("/api/act");
export const getCredentials = () => getJSON<Credential[]>("/api/credentials");
export const getAttack = () => getJSON<AttackCoverage>("/api/attack");
export type ActRunResult = { looted: number; creds: { label: string; source: string }[]; spray_files: string[] };
export async function postActRun(): Promise<ActRunResult> {
  const r = await fetch("/api/act/run", { method: "POST", headers: jsonHeaders() });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}
export type SprayHit = { proto: string; ip: string; user: string; secret: string; cred: string; admin: boolean };
export type SprayResult = { ok: boolean; error: string; hits: SprayHit[]; new: number };
export async function postSpray(targets: string, safe: boolean): Promise<SprayResult> {
  const r = await fetch("/api/spray", {
    method: "POST", headers: jsonHeaders(), body: JSON.stringify({ targets, safe }),
  });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

// weighted risk score for sorting hosts most-dangerous-first
export function hostScore(f: Record<string, number>): number {
  return (f.critical || 0) * 1000 + (f.high || 0) * 100 + (f.medium || 0) * 10 + (f.low || 0);
}
export function sevTotal(f: Record<string, number>): number {
  return SEVS.reduce((n, s) => n + (f[s] || 0), 0);
}
