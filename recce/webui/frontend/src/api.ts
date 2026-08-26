// Types + fetch helpers for the recce workbench API.

// Finding lifecycle status. Empty string = implicit "new" (no row written).
export type FindingStatus = "" | "new" | "triaged" | "confirmed"
  | "in-report" | "excluded" | "retested-fixed" | "retested-open";
export const FINDING_STATUSES: FindingStatus[] = [
  "", "triaged", "confirmed", "in-report", "excluded",
  "retested-fixed", "retested-open",
];
export const FINDING_STATUS_LABEL: Record<FindingStatus, string> = {
  "": "new", new: "new", triaged: "triaged", confirmed: "confirmed",
  "in-report": "in report", excluded: "excluded",
  "retested-fixed": "retested — fixed", "retested-open": "retested — still open",
};
export type Finding = {
  key: string; reviewed: boolean; notes: string;
  severity: string; title: string; ip: string; port: number | null;
  cve: string; cves: string[]; kev: boolean; epss: number;
  tier: string; source: string; confidence: string;
  sources?: string[]; status?: FindingStatus;
  // `recce prove` verdict — empty until prove has run. Rendered as a
  // badge (✓ confirmed / ≈ likely / ? needs PoC / ✗ false pos).
  verdict?: string;
  verdict_evidence?: string[];
  verdict_finish?: string;
};

export async function setFindingStatus(key: string, status: FindingStatus): Promise<void> {
  const r = await fetch("/api/finding/status",
    { method: "POST", headers: jsonHeaders(), body: JSON.stringify({ key, status }) });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
}
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

export type ExploitHint = {
  key: string; ip: string; port: number; cve: string;
  hint: { module: string; payload: string; note: string } | null;
};
export async function getExploitHint(key: string): Promise<ExploitHint> {
  return getJSON<ExploitHint>(`/api/finding/exploit-hint?key=${encodeURIComponent(key)}`);
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

type Paginated<T> = { items: T[]; total: number; limit: number; offset: number };

export async function fetchAll(): Promise<[Overview, Finding[], Host[]]> {
  const [o, f, h] = await Promise.all([
    getJSON<Overview>("/api/overview"),
    getJSON<Paginated<Finding>>("/api/findings"),
    getJSON<Paginated<Host>>("/api/hosts"),
  ]);
  return [o, f.items, h.items];
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

export type CmdFlag = {
  name: string; flag: string; label: string;
  active?: boolean;
  // "bool" (checkbox) is the default. "text" / "int" / "list" render as
  // inputs and their values ride on `flag_values` in the scan POST.
  // "wordlist" adds a bundled-list dropdown next to the free-text input;
  // wordlist_kind ("paths"/"creds"/"users") filters which lists appear.
  kind?: "bool" | "text" | "int" | "list" | "wordlist";
  placeholder?: string;
  wordlist_kind?: "paths" | "creds" | "users";
};
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
  flag_values?: Record<string, string>;
};

export async function postCommand(req: RunReq): Promise<{ id: string }> {
  const r = await fetch("/api/scan", {
    method: "POST", headers: jsonHeaders(), body: JSON.stringify(req),
  });
  if (!r.ok) throw new Error((await r.json()).detail ?? r.statusText);
  return r.json();
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

// Raw-evidence attach — the escape hatch for files that can't be parsed
// (screenshots, PDFs, packet captures, vendor reports, proprietary formats).
// Saves the file into <eng>/evidence/<ip>/ and creates an info-level finding
// on the host titled "Manual evidence: <filename>" with a download link.
export async function uploadEvidence(ip: string, filename: string,
                                     base64Data: string, note?: string): Promise<{ path: string; bytes: number }> {
  const r = await fetch("/api/evidence/upload", {
    method: "POST", headers: jsonHeaders(),
    body: JSON.stringify({ ip, filename, data: base64Data, note: note || "" }),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}

// Phase 3 — declarative parser builder + LLM-assisted draft
export type ParserSpec = {
  name: string; description?: string;
  detect: { filename_glob?: string; content_re?: string; content_substr?: string };
  match?: { target_re?: string; port_default?: number };
  findings: Array<{ marker_re: string; severity: string; confidence?: string; source?: string }>;
};
export type ParserTestResult = {
  ok: boolean; error?: string; count: number;
  sample: Array<{ severity: string; title: string; ip: string; port: number | null }>;
};

export async function listUserParsers(): Promise<Array<{ name: string; description: string;
    detect: any; findings_count: number }>> {
  const r = await getJSON<{ parsers: any[] }>("/api/import/parsers");
  return r.parsers;
}
export async function testUserParser(spec: ParserSpec, sample: string): Promise<ParserTestResult> {
  const r = await fetch("/api/import/parsers/test",
    { method: "POST", headers: jsonHeaders(), body: JSON.stringify({ spec, sample }) });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}
export async function saveUserParser(spec: ParserSpec): Promise<{ path: string; name: string }> {
  const r = await fetch("/api/import/parsers/save",
    { method: "POST", headers: jsonHeaders(), body: JSON.stringify({ spec }) });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}
export async function deleteUserParser(name: string): Promise<void> {
  const r = await fetch(`/api/import/parsers/${encodeURIComponent(name)}`, { method: "DELETE" });
  if (!r.ok && r.status !== 404) throw new Error(`${r.status}`);
}
export async function draftParserWithLLM(sample: string, hint?: string): Promise<ParserSpec> {
  const r = await fetch("/api/import/parsers/draft",
    { method: "POST", headers: jsonHeaders(), body: JSON.stringify({ sample, hint: hint || "" }) });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  const d = await r.json();
  return d.spec;
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

export type AttackStep = { stage: string; ip: string; hostname: string; title: string;
  tool: string; cmd: string; why: string; key: string };
export type AttackStageGroup = { stage: string; steps: AttackStep[] };
export type AttackPath = { narrative: string[]; stages: AttackStageGroup[]; step_count: number };
export const getAttackPath = () => getJSON<AttackPath>("/api/attackpath");

export type PocAffected = { ip: string; port: number | null; title: string; severity: string; confidence: string };
export type PocEdb = { id: string; title: string };
export type PocDossier = {
  cve: string; title: string; severity: string; kev: boolean; epss: number; cwe: string[];
  affected: PocAffected[]; msf: string; edb: PocEdb[];
  dossier_md: string; harness_py: string;
};
export const getPoc = (cve: string) => getJSON<PocDossier>(`/api/poc/${encodeURIComponent(cve)}`);

export type DiffHost = { ip: string; hostname: string; updated: number;
  sev: Record<string, number>; port_count: number };
export type DiffActivity = { ts: number; tester: string; kind: string; text: string };
export type ScanDiff = {
  since: number; until: number;
  hosts_touched: DiffHost[];
  activity: DiffActivity[];
  summary: { hosts: number; findings_added: number; credentials_added: number;
    total_hosts: number; total_creds: number };
};
export const getDiff = (since?: number) =>
  getJSON<ScanDiff>(`/api/diff${since != null ? `?since=${since}` : ""}`);

export type LootExtracted = { username: string; kind: string; source: string; secret_preview: string };
export type LootExtractResult = {
  found: number; added: number; skipped_dupes: number;
  credentials: LootExtracted[];
};
export const postLootExtract = (text: string, origin_ip = "", note = "") =>
  post("/api/loot/extract", { text, origin_ip, note }) as Promise<LootExtractResult>;
export const getCredentials = () => getJSON<Paginated<Credential>>("/api/credentials").then(r => r.items);
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
  id: string; name?: string; host_ip: string; host_port: number; kind: string;
  status: "live" | "stale" | "dead"; pty: boolean; label: string;
  driver: string | null; attached: string[]; created: number; bytes: number;
}
export interface QuickAction { key: string; label: string; cmd: string; }
export async function getQuickActions(): Promise<QuickAction[]> {
  const r = await getJSON<{ actions: QuickAction[] }>("/api/sessions/quick-actions");
  return r.actions;
}
export async function runQuickAction(sessionId: string, key: string): Promise<{ output: string; cmd: string }> {
  const r = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/quick`,
    { method: "POST", headers: jsonHeaders(), body: JSON.stringify({ key }) });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}
export async function runShellCmd(sessionId: string, cmd: string): Promise<{ output: string }> {
  const r = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/quickrun`,
    { method: "POST", headers: jsonHeaders(), body: JSON.stringify({ cmd }) });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}
export async function getSessionHistory(sessionId: string): Promise<string[]> {
  const r = await getJSON<{ history: string[] }>(`/api/sessions/${encodeURIComponent(sessionId)}/history`);
  return r.history || [];
}
export async function putSessionHistory(sessionId: string, entries: string[]): Promise<void> {
  await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/history`,
    { method: "PUT", headers: jsonHeaders(), body: JSON.stringify({ entries }) });
}

// Engagement metadata (client, dates, testers, ROE, logo). Consumed by the
// docx report builder to render a branded cover page.
export type EngagementMeta = {
  engagement?: string; client?: string; tester?: string; testers?: string;
  scope_notes?: string; notes?: string; start_date?: string; end_date?: string;
  roe_notes?: string; client_logo?: string;
};
export async function getEngagementMeta(): Promise<EngagementMeta> {
  return getJSON<EngagementMeta>("/api/meta");
}
export async function setEngagementMeta(patch: EngagementMeta): Promise<void> {
  const r = await fetch("/api/meta",
    { method: "POST", headers: jsonHeaders(), body: JSON.stringify(patch) });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
}
// Teardown checklist: aggregate inventory of everything recce deployed that
// still needs cleanup at engagement end. Reads from the sessions store +
// live listener/session registries.
export type TeardownInventory = {
  generated_at: number; total: number;
  persistence: any[]; uploads: any[]; listeners: any[];
  sessions: any[]; tunnels: any[]; portfwds: any[];
};
export async function getTeardown(): Promise<TeardownInventory> {
  return getJSON<TeardownInventory>("/api/teardown");
}
export async function clearTeardownUpload(id: string): Promise<void> {
  await fetch(`/api/teardown/upload/${encodeURIComponent(id)}/clear`,
    { method: "POST", headers: jsonHeaders() });
}

export async function uploadClientLogo(base64Data: string): Promise<{ path: string }> {
  const r = await fetch("/api/meta/logo",
    { method: "POST", headers: jsonHeaders(), body: JSON.stringify({ data: base64Data }) });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}
export interface ListenerInfo { id: string; host: string; port: number; kind: string; status: string; }

export async function getSessions(host?: string): Promise<SessionInfo[]> {
  return getJSON<SessionInfo[]>("/api/sessions" + (host ? `?host=${encodeURIComponent(host)}` : ""));
}
export async function getListeners(): Promise<ListenerInfo[]> { return getJSON<ListenerInfo[]>("/api/listeners"); }
export async function startListener(port: number, tls = false): Promise<ListenerInfo> {
  const r = await fetch("/api/listeners", { method: "POST", headers: jsonHeaders(), body: JSON.stringify({ port, tls }) });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}
export async function stopListener(id: string): Promise<void> {
  await fetch(`/api/listeners/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export async function patchSession(sessionId: string, patch: { label?: string }): Promise<SessionInfo> {
  const r = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}`, {
    method: "PATCH", headers: jsonHeaders(), body: JSON.stringify(patch),
  });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}
export async function closeSession(sessionId: string): Promise<void> {
  const r = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}`, { method: "DELETE" });
  if (!r.ok && r.status !== 404) throw new Error(`${r.status}`);
}

export async function lootCred(sessionId: string, c: { username: string; secret: string; kind: string }): Promise<void> {
  const r = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/cred`, {
    method: "POST", headers: jsonHeaders(), body: JSON.stringify(c),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
}
export async function getTranscript(sessionId: string): Promise<string> {
  const r = await getJSON<{ data: string }>(`/api/sessions/${encodeURIComponent(sessionId)}/transcript`);
  return atob(r.data);
}

export async function upgradeSession(sessionId: string):
  Promise<{ upgraded?: boolean; reason?: string; session_id?: string; callback: string }> {
  const r = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/upgrade`, {
    method: "POST", headers: jsonHeaders(),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}

export async function spawnSession(sessionId: string):
  Promise<{ ok: boolean; session_id?: string; pty?: boolean; reason?: string }> {
  const r = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/spawn`, {
    method: "POST", headers: jsonHeaders(),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}

export async function getStager(tls: boolean): Promise<string> {
  const r = await getJSON<{ template: string }>("/api/stager?tls=" + (tls ? "true" : "false"));
  return r.template;
}

// --- session file transfer + on-target enum -----------------------------------
export async function runEnum(sessionId: string): Promise<{ id: string; bytes: number }> {
  const r = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/enum`, { method: "POST", headers: jsonHeaders() });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}
export async function downloadFromShell(sessionId: string, path: string): Promise<{ saved: string; size: number }> {
  const r = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/download`, {
    method: "POST", headers: jsonHeaders(), body: JSON.stringify({ path }),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}
export async function uploadToShell(sessionId: string, path: string, dataB64: string): Promise<{ bytes: number }> {
  const r = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/upload`, {
    method: "POST", headers: jsonHeaders(), body: JSON.stringify({ path, data: dataB64 }),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}

// --- reverse tunnel (SOCKS5 proxy through the shell) -------------------------
export type TunnelStatus = { active: boolean; socks_port?: number; tunnel_port?: number; agent_pid?: string; socks_addr?: string };
export async function startTunnel(sessionId: string, socksPort: number = 1080): Promise<{ ok: boolean; socks_port?: number; socks_addr?: string; agent_pid?: string; reason?: string }> {
  const r = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/tunnel`, {
    method: "POST", headers: jsonHeaders(),
    body: JSON.stringify({ action: "start", socks_port: socksPort }),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}
export async function stopTunnel(sessionId: string): Promise<{ ok: boolean }> {
  const r = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/tunnel`, {
    method: "POST", headers: jsonHeaders(), body: JSON.stringify({ action: "stop" }),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}
export async function tunnelStatus(sessionId: string): Promise<TunnelStatus> {
  const r = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/tunnel`, {
    method: "POST", headers: jsonHeaders(), body: JSON.stringify({ action: "status" }),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}

// --- port forwarding through the shell ----------------------------------------
export type PortFwd = { id: string; lport: number; rhost: string; rport: number; pid: string; method: string };
export async function startPortFwd(sessionId: string, listen_port: number, remote_host: string, remote_port: number): Promise<{ ok: boolean } & Partial<PortFwd> & { reason?: string }> {
  const r = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/portfwd`, {
    method: "POST", headers: jsonHeaders(),
    body: JSON.stringify({ action: "start", listen_port, remote_host, remote_port }),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}
export async function stopPortFwd(sessionId: string, id: string): Promise<{ ok: boolean }> {
  const r = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/portfwd`, {
    method: "POST", headers: jsonHeaders(), body: JSON.stringify({ action: "stop", id }),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}
export async function listPortFwds(sessionId: string): Promise<PortFwd[]> {
  const r = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/portfwd`, {
    method: "POST", headers: jsonHeaders(), body: JSON.stringify({ action: "list" }),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return (await r.json()).forwards;
}

// --- persistence (intrusive; tracked + removable) -----------------------------
export interface Persistence {
  id: string; host_ip: string; mechanism: string; artifact_path: string;
  installed_by: string; installed_at: number; removed_at: number | null;
}
export async function persistSession(sessionId: string): Promise<{ ok: boolean; id?: string; reason?: string }> {
  const r = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/persist`, {
    method: "POST", headers: jsonHeaders(), body: JSON.stringify({ mechanism: "cron" }),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}
export async function getPersistence(host?: string): Promise<Persistence[]> {
  return getJSON<Persistence[]>("/api/persistence" + (host ? `?host=${encodeURIComponent(host)}` : ""));
}
export async function removePersistence(id: string): Promise<{ ok: boolean; reason?: string }> {
  const r = await fetch(`/api/persistence/${encodeURIComponent(id)}/remove`, { method: "POST", headers: jsonHeaders() });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}
export async function removeAllPersistence(): Promise<{ removed: number; failed: { id: string; host_ip: string; path: string; reason: string }[] }> {
  const r = await fetch("/api/persistence/remove-all", { method: "POST", headers: jsonHeaders() });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}
