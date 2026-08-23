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

export type CmdFlag = { name: string; flag: string; label: string; active?: boolean };
export type CmdSpec = {
  label: string; group: string;
  targets: "required" | "optional" | "none";
  profile: boolean; creds: boolean; lhost: boolean; flags: CmdFlag[];
};
export type CmdCatalog = Record<string, CmdSpec>;

export async function getCommands(): Promise<CmdCatalog> {
  const r = await fetch("/api/commands");
  if (!r.ok) throw new Error(r.statusText);
  return r.json();
}

export type RunReq = {
  command: string; targets?: string; profile?: string;
  username?: string; password?: string; domain?: string;
  lhost?: string; flags?: string[];
};

export async function postCommand(req: RunReq): Promise<{ id: string }> {
  const r = await fetch("/api/scan", {
    method: "POST", headers: jsonHeaders(), body: JSON.stringify(req),
  });
  if (!r.ok) throw new Error((await r.json()).detail ?? r.statusText);
  return r.json();
}

// back-compat convenience
export async function postScan(targets: string, profile: string): Promise<{ id: string }> {
  return postCommand({ command: "scan", targets, profile });
}

export type ImportResult =
  | { mode: "job"; id: string; kind: string }
  | { mode: "done"; kind: string; added: number; summary: string }
  | { mode: "preview"; kind: string; count: number; detail: string;
      sample: string[]; warning: string };

// Fold external tool output (nmap, netexec, GetUserSPNs/GetNPUsers/secretsdump,
// on-target loot) into the live engagement. kind "auto" lets the server sniff it.
export async function postImport(content: string, filename: string, kind: string,
                                 encoding = "", preview = false): Promise<ImportResult> {
  const r = await fetch("/api/import", {
    method: "POST", headers: jsonHeaders(),
    body: JSON.stringify({ content, filename, kind, encoding, preview }),
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
export type AttackTech = { id: string; name: string; hosts: string[] };
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

// --- multi-tester collaboration -----------------------------------------------
export type Activity = { ts: number; tester: string; kind: string; text: string };
export type Collab = {
  assignments: Record<string, string>;      // ip -> tester
  labels: Record<string, string[]>;         // ip -> labels
  port_status: Record<string, string>;      // "ip:port" -> todo|wip|done
  dismissed: Record<string, string>;        // finding key -> tester
  activity: Activity[];
  online: string[];
};
export const TRIAGE_LABELS = ["interesting", "needs-review", "out-of-scope"];

export async function getCollab(): Promise<Collab> { return getJSON<Collab>("/api/collab"); }

async function post(url: string, body?: unknown) {
  const r = await fetch(url, { method: "POST", headers: jsonHeaders(),
    body: body === undefined ? undefined : JSON.stringify(body) });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail ?? r.statusText);
  return r.json();
}
export const postAssign = (ip: string, tester: string) => post("/api/assign", { ip, tester });
export const postLabel = (ip: string, label: string, on: boolean) => post("/api/label", { ip, label, on });
export const postPortStatus = (ip: string, port: number, status: string) => post("/api/port_status", { ip, port, status });
export const postDismiss = (key: string, on: boolean) => post("/api/dismiss", { key, on });
export const pingPresence = () => post("/api/presence").catch(() => {});
export const addFinding = (b: { ip: string; port?: string; title: string; severity: string; cve?: string; output?: string }) => post("/api/add/finding", b);
export const addCredential = (b: { username: string; secret: string; kind: string; domain?: string; origin_ip?: string; notes?: string }) => post("/api/add/credential", b);
export const addHostScope = (targets: string) => post("/api/add/host", { targets });
export const addAccess = (ip: string, note: string) => post("/api/add/access", { ip, note });

// --- team chat ----------------------------------------------------------------
export type ChatFile = { stored: string; name: string; size: number };
export type ChatMsg = { id: string; ts: number; tester: string; text: string; image: string; file?: ChatFile | null };
export async function getChat(): Promise<ChatMsg[]> { return getJSON<ChatMsg[]>("/api/chat"); }
// image = base64 (no data: prefix) or "" for text-only; file = a general (non-image)
// attachment, {data: base64, name: original filename} or omitted.
export const postChat = (text: string, image: string, file?: { data: string; name: string } | null): Promise<ChatMsg> =>
  post("/api/chat", { text, image, file: file || null });

// --- playbook (shared engagement plan) ----------------------------------------
export type PbPhase = { key: string; label: string; state: string; detail: string; cmd: string };
export type PbBranch = { label: string; cmd: string; why: string };
export type Playbook = {
  phases: PbPhase[]; current: string | null;
  next: { label: string; cmd: string } | null;
  branches: PbBranch[]; path: string[];
};
export async function fetchPlaybook(): Promise<Playbook> { return getJSON<Playbook>("/api/playbook"); }

// --- shell sessions ---------------------------------------------------------
export interface SessionInfo {
  id: string; host_ip: string; host_port: number; kind: string;
  status: "live" | "stale" | "dead"; pty: boolean;
  driver: string | null; attached: string[]; created: number; bytes: number;
}
export interface ListenerInfo { id: string; host: string; port: number; kind: string; status: string; }

export async function getSessions(host?: string): Promise<SessionInfo[]> {
  return getJSON<SessionInfo[]>("/api/sessions" + (host ? `?host=${encodeURIComponent(host)}` : ""));
}
export async function getListeners(): Promise<ListenerInfo[]> { return getJSON<ListenerInfo[]>("/api/listeners"); }
export async function startListener(port: number): Promise<ListenerInfo> {
  const r = await fetch("/api/listeners", { method: "POST", headers: jsonHeaders(), body: JSON.stringify({ port }) });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}
export async function stopListener(id: string): Promise<void> {
  await fetch(`/api/listeners/${encodeURIComponent(id)}`, { method: "DELETE" });
}
