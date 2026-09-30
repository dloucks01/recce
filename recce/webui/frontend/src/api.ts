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
  // Test-management attribution: who reviewed it + when (unix secs, string),
  // who owns it, and any operator priority. Empty until a tester acts.
  reviewed_by?: string; reviewed_at?: string; assignee?: string; priority?: string;
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

// Per-finding ownership (distinct from the host-level collab claim). Empty
// assignee releases the finding.
export async function setFindingAssignee(key: string, assignee: string): Promise<void> {
  const r = await fetch("/api/finding/assign",
    { method: "POST", headers: jsonHeaders(), body: JSON.stringify({ key, assignee }) });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
}
export type Port = { port: number; proto: string; service: string; product: string };
export type Host = {
  ip: string; key: string; hostname: string; os: string; roles: string[]; up: boolean;
  subnet?: string;   // the actual scope CIDR containing the host (/16, /28, /30…)
  ports: Port[]; findings: Record<string, number>;
  leads?: number;    // unconfirmed candidate findings, excluded from `findings`
  enumerated: boolean; vuln_scanned: boolean; access: boolean;
  db: boolean; privesc: boolean; credenum: boolean;
  reviewed: boolean; notes: string;
  reviewed_by?: string; reviewed_at?: string; assignee?: string; priority?: string;
};
export type KevFinding = {
  key: string; ip: string; port: number | null; title: string;
  severity: string; cve: string; epss: number;
};
export type TopHost = {
  ip: string; hostname: string; os: string; roles: string[];
  findings: Record<string, number>; score: number;
};
// Freshness stamps for the baked KEV/EPSS snapshots — surfaced in the
// Overview so the operator knows which CISA catalog / EPSS model produced
// the KEV+EPSS chips they're looking at. Rewritten by
// tools/refresh_intel.py at build time.
export type IntelAsOf = {
  summary: string;                    // one-liner for a chip
  kev_as_of?: string;                 // YYYY-MM-DD refresh date, or "unknown"
  kev_catalog_version?: string;       // CISA catalogVersion, e.g. "2024.09.15"
  kev_released?: string;              // upstream date-released
  epss_as_of?: string;
  epss_model?: string;                // "v2024.02.29" for EPSS v4
  epss_score_date?: string;
  kev_count?: number;                 // KEV CVEs actually baked in
  epss_count?: number;                // EPSS scores actually baked in
  stamped?: boolean;                  // snapshot date written by refresh_intel
  present?: boolean;                  // any intel baked in at all
};
export type Overview = {
  name: string; hosts_up: number; hosts_total: number;
  scope_subnets: number; scope_size: number; services: number;
  by_severity: Record<string, number>; findings_total: number;
  leads_hidden?: number;   // unconfirmed candidates excluded from the counts above
  kev_total: number; kev_findings: KevFinding[]; top_hosts: TopHost[];
  reviewed: number; enumerated: number; accessed: number;
  intel_asof?: IntelAsOf;
};

export type Account = {
  kind: string; name: string; domain: string; rid: string; detail: string;
  attrs: Record<string, string>;
};
export type VulnDetail = Finding & {
  output: string; remediation: string; cwes: string[];
  qod: number; qod_type: string; state: string;
};
// Omit<Host, "ports"> — NOT `Host &`. The /api/host/{ip} detail endpoint sends a
// richer port shape than the host LIST does (state/version/banner separately,
// where the list pre-merges version into product). Intersecting would AND the
// two `ports` types rather than replace, so element access resolved to plain
// Port and `p.version` / `p.banner` failed to typecheck.
export type HostDetail = Omit<Host, "ports"> & {
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

// Offline reference detail for a CVE/CWE id (no external lookup — airgap-safe).
export type RefInfo = {
  kind: "cve" | "cwe"; id: string; name?: string; kev?: boolean; epss?: number;
  desc?: string; remediation?: string; severity?: string; cwe?: string[];
  cvss?: number | null; exploit?: string; source?: string;
};
export const getRef = (id: string) => getJSON<RefInfo>(`/api/ref/${encodeURIComponent(id)}`);

export const SEVS = ["critical", "high", "medium", "low"];
export const SEV_ALL = ["critical", "high", "medium", "low", "info"];

function tester(): string {
  return localStorage.getItem("recce.tester") || "someone";
}

// Light named identity: a stable per-tester token, generated once and persisted
// in this browser. Sent alongside the display name so the server can keep a
// durable roster and keep two same-named testers distinct. Not a secret / not
// auth — it just makes attribution stable. try/catch: private-mode localStorage
// can throw, in which case we fall back to an ephemeral in-memory token.
let _memToken = "";
function testerToken(): string {
  try {
    let t = localStorage.getItem("recce.tester_token");
    if (!t) {
      t = (crypto?.randomUUID?.() ||
           `t-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`);
      localStorage.setItem("recce.tester_token", t);
    }
    return t;
  } catch {
    if (!_memToken) _memToken = `t-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
    return _memToken;
  }
}
const jsonHeaders = () => ({
  "Content-Type": "application/json",
  "X-Tester": tester(),
  "X-Tester-Token": testerToken(),
});

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

// Save a note. When `base` (the text the editor loaded) is passed, the server
// does a compare-and-swap: if another operator changed the note since, it returns
// 409 and we hand back their current text so the caller can reconcile instead of
// silently clobbering it.
// Per-entity presence ("who's editing this") — ephemeral collision awareness.
// entity is e.g. "host:10.0.0.5" or "finding:<key>". Returns current watchers.
export function myTester(): string { return tester(); }
export async function postFocus(
  entity: string, on = true, editing = false,
): Promise<{ testers: string[]; editing: string[] }> {
  try {
    const r = await fetch("/api/presence/focus", {
      method: "POST", headers: jsonHeaders(), body: JSON.stringify({ entity, on, editing }),
    });
    if (!r.ok) return { testers: [], editing: [] };
    const d = await r.json();
    return { testers: (d.testers ?? []) as string[], editing: (d.editing ?? []) as string[] };
  } catch { return { testers: [], editing: [] }; }
}

// Operations log — shared, structured record of post-ex actions (who ran what
// on which host). Most-recent-first; optional host filter.
export type OplogEntry = {
  ts: string; operator: string; session_id: string; host_ip: string;
  kind: string; command: string; output: string; status: string; attack: string;
};
export async function getOplog(opts?: { limit?: number; host?: string }): Promise<OplogEntry[]> {
  const p = new URLSearchParams();
  if (opts?.limit) p.set("limit", String(opts.limit));
  if (opts?.host) p.set("host", opts.host);
  const r = await fetch("/api/oplog" + (p.toString() ? `?${p}` : ""));
  if (!r.ok) return [];
  const d = await r.json();
  return (d.items ?? []) as OplogEntry[];
}

export async function postNote(
  key: string, note: string, base?: string,
): Promise<{ ok: true } | { conflict: true; notes: string }> {
  const payload: Record<string, unknown> = { key, note };
  if (base !== undefined) payload.base = base;
  const r = await fetch("/api/note", {
    method: "POST", headers: jsonHeaders(), body: JSON.stringify(payload),
  });
  if (r.status === 409) {
    let notes = "";
    try {
      const d = await r.json();
      notes = (d?.detail?.notes ?? d?.notes ?? "") as string;
    } catch { /* ignore */ }
    return { conflict: true, notes };
  }
  return { ok: true };
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
  tool_cmd?: string;    // raw external-tool command + syntax this recce command wraps
};
export type CmdCatalog = Record<string, CmdSpec>;

// "recce suggests…" — surfaced by /api/scan/suggestions above the command grid.
// `command`/`field` empty means info-only (typically an external-tool handoff
// like hashcat/ntlmrelayx); otherwise the frontend prefills that command's
// form field with `suggested_value`. `key` is stable across page reloads so
// the dismissed set can be persisted in localStorage.
export type ScanSuggestion = {
  key: string;
  command: string;
  field: "" | "domain" | "username" | "targets";
  suggested_value: string;
  reason: string;
  confidence: "high" | "medium" | "low";
  source: string;
  external_cmd?: string;
  severity?: "critical" | "high" | "medium" | "low";
};

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
  then_sweep?: boolean;   // enum only: auto-run the deep per-service sweep after discovery
  resume?: boolean;       // enum/scan: skip hosts already enumerated (resume an interrupted run)
};

export async function postCommand(req: RunReq): Promise<{ id: string }> {
  const r = await fetch("/api/scan", {
    method: "POST", headers: jsonHeaders(), body: JSON.stringify(req),
  });
  if (!r.ok) throw new Error((await r.json()).detail ?? r.statusText);
  return r.json();
}

// Custom nmap — the tester's own scan. recce owns -oX/-oG output so results
// fold into the engagement and the scan is resumable.
export async function postNmapScan(args: string): Promise<{ id: string; gnmap: string }> {
  const r = await fetch("/api/scan/nmap", {
    method: "POST", headers: jsonHeaders(), body: JSON.stringify({ args }),
  });
  if (!r.ok) throw new Error((await r.json()).detail ?? r.statusText);
  return r.json();
}
export async function resumeNmapScan(gnmap: string): Promise<{ id: string; gnmap: string }> {
  const r = await fetch("/api/scan/nmap", {
    method: "POST", headers: jsonHeaders(), body: JSON.stringify({ resume: gnmap }),
  });
  if (!r.ok) throw new Error((await r.json()).detail ?? r.statusText);
  return r.json();
}
export type NmapLog = { gnmap: string; complete: boolean; mtime: number };
export const getNmapLogs = () =>
  getJSON<{ items: NmapLog[] }>("/api/scan/nmap/logs").then((r) => r.items || []);

// Which discovered hosts qualify for each command (count + sample), from the
// module's own targeting predicate. Drives the "N hosts qualify" hints.
export type ScanCtx = Record<string, { count: number; sample: string[]; hint?: string; detected?: number }>;
export const getScanContext = () =>
  getJSON<{ hosts: number; commands: ScanCtx }>("/api/scan/context").then((r) => r.commands);
export const getScanSuggestions = () =>
  getJSON<{ suggestions: ScanSuggestion[] }>("/api/scan/suggestions").then((r) => r.suggestions || []);
export type Wordlist = { name: string; kind: string; blurb: string; line_count: number };
export const getWordlists = () =>
  getJSON<{ wordlists: Wordlist[] }>("/api/wordlists").then((r) => r.wordlists || []);

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
  key: string; tool_cmd?: string; spray_hint?: string;
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

// --- P7-C1 async job handles (spray + act/run) -------------------------------
// Non-blocking variants. Launch returns immediately with a job id; poll
// /api/jobs/{id} until status flips out of "running" and the same result
// shape the sync variant returns inline appears on `row.result`.
export type JobHandle = { id: string; cmd: string; status: "running" | "done" | "failed" | "cancelled" };
// A row from GET /api/jobs (the list the header pill / sidebar / scan tab show).
export type Job = {
  id: string;
  status: "running" | "done" | "failed";
  cmd: string;
  tester: string;
  started: number;
  progress?: { done: number; total: number | null; phase: string | null } | null;
};
export type JobRow<R = unknown> = {
  id: string; cmd: string;
  status: "running" | "done" | "failed" | "cancelled";
  started: number; ended: number | null;
  returncode: number | null;
  lines: number;
  progress: { done: number; total: number | null; phase: string | null } | null;
  result: R | null;
};
export async function postActRunAsync(): Promise<JobHandle> {
  const r = await fetch("/api/act/run/async", { method: "POST", headers: jsonHeaders() });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}
export async function postSprayAsync(targets: string, safe: boolean): Promise<JobHandle> {
  const r = await fetch("/api/spray/async", {
    method: "POST", headers: jsonHeaders(),
    body: JSON.stringify({ targets: targets ? targets.split(/[\s,]+/).filter(Boolean) : [], safe }),
  });
  if (!r.ok) {
    let msg = `${r.status}`;
    try { const j = await r.json(); if (j?.detail) msg = j.detail; } catch { /* keep status */ }
    throw new Error(msg);
  }
  return r.json();
}
export async function getJob<R = unknown>(jid: string): Promise<JobRow<R>> {
  const r = await fetch(`/api/jobs/${encodeURIComponent(jid)}`);
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}
/** Poll /api/jobs/{jid} until status leaves "running". Rejects on cancel
 *  after `timeoutMs`; resolves with the final row (containing result). */
export async function waitForJob<R = unknown>(jid: string,
    { intervalMs = 500, timeoutMs = 15 * 60_000 }: { intervalMs?: number; timeoutMs?: number } = {}
  ): Promise<JobRow<R>> {
  const deadline = Date.now() + timeoutMs;
  // Small initial delay so a very fast job (act/run on an empty engagement)
  // finishes before the first poll — one round-trip instead of two.
  await new Promise((r) => setTimeout(r, Math.min(intervalMs, 50)));
  while (Date.now() < deadline) {
    const row = await getJob<R>(jid);
    if (row.status !== "running") return row;
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(`job ${jid} did not finish within ${Math.round(timeoutMs / 1000)}s`);
}

// weighted risk score for sorting hosts most-dangerous-first
export function hostScore(f: Record<string, number>): number {
  return (f.critical || 0) * 1000 + (f.high || 0) * 100 + (f.medium || 0) * 10 + (f.low || 0);
}

// --- multi-tester collaboration -----------------------------------------------
export type Activity = { ts: number; tester: string; kind: string; text: string };
// Durable roster entry (survives restart). last_seen is a unix-secs string.
export type Tester = { token: string; name: string; first_seen: string; last_seen: string };
export type Collab = {
  assignments: Record<string, string>;      // ip -> tester
  labels: Record<string, string[]>;         // ip -> labels
  port_status: Record<string, string>;      // "ip:port" -> todo|wip|done
  dismissed: Record<string, string>;        // finding key -> tester
  activity: Activity[];
  online: string[];
  roster?: Tester[];                         // everyone who ever joined
};
export const TRIAGE_LABELS = ["interesting", "needs-review", "out-of-scope"];

export async function getCollab(): Promise<Collab> { return getJSON<Collab>("/api/collab"); }

// Per-finding priority — the shared "hot list" the team rallies around. "" clears.
export async function setFindingPriority(key: string, priority: string): Promise<void> {
  const r = await fetch("/api/finding/priority",
    { method: "POST", headers: jsonHeaders(), body: JSON.stringify({ key, priority }) });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
}

async function post(url: string, body?: unknown) {
  const r = await fetch(url, { method: "POST", headers: jsonHeaders(),
    body: body === undefined ? undefined : JSON.stringify(body) });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail ?? r.statusText);
  return r.json();
}
// mid (mutation id) is echoed back in the SSE broadcast so the originating client
// can drop its own echo instead of re-fetching twice.
export const postAssign = (ip: string, tester: string, mid = "") => post("/api/assign", { ip, tester, mutation_id: mid });
export const postLabel = (ip: string, label: string, on: boolean, mid = "") => post("/api/label", { ip, label, on, mutation_id: mid });
export const postPortStatus = (ip: string, port: number, status: string, mid = "") => post("/api/port_status", { ip, port, status, mutation_id: mid });
export const postDismiss = (key: string, on: boolean, mid = "") => post("/api/dismiss", { key, on, mutation_id: mid });
export const pingPresence = () => post("/api/presence").catch(() => {});

// Loot browser — files pulled off targets during the engagement (session
// downloads + ADCS PFX). Serve one back via /api/loot/file?rel=<rel>.
export type LootFile = { name: string; rel: string; host: string; size: number; mtime: number };
export const getLoot = () => getJSON<{ items: LootFile[] }>("/api/loot").then((r) => r.items || []);
export const lootFileUrl = (rel: string) => `/api/loot/file?rel=${encodeURIComponent(rel)}`;
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
  socks_port?: number; portfwd_count?: number; portfwd_preview?: string[];
  oob_active?: boolean;
  // batch-2 ergonomics
  notes?: string;          // free-form operator context for the writeup
  pinned?: boolean;        // pinned sessions float to the top of the list
  listener_id?: string;    // id of the listener that caught this shell (empty for beacons / imports)
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
// `base` (the values the editor loaded) enables compare-and-swap on the free-text
// fields: a 409 means another operator changed one since, and we reconcile rather
// than clobber. Non-text fields stay last-write-wins.
export async function setEngagementMeta(
  patch: EngagementMeta, base?: EngagementMeta,
): Promise<{ ok: true } | { conflict: true; conflicts: Record<string, string> }> {
  const body: Record<string, unknown> = { ...patch };
  if (base) body.base = base;
  const r = await fetch("/api/meta",
    { method: "POST", headers: jsonHeaders(), body: JSON.stringify(body) });
  if (r.status === 409) {
    const d = await r.json().catch(() => ({}));
    return { conflict: true, conflicts: (d?.detail?.conflicts ?? {}) as Record<string, string> };
  }
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return { ok: true };
}
// Teardown checklist: aggregate inventory of everything recce deployed that
// still needs cleanup at engagement end. Reads from the sessions store +
// live listener/session registries.
export type TdPersistence = {
  id: string; host_ip: string; mechanism: string; artifact_path: string;
  remove_cmd: string; installed_by: string; installed_at: number; removed_at: number | null;
};
export type TdUpload = {
  id: string; host_ip: string; remote_path: string; bytes: number;
  uploaded_by: string; uploaded_at: number; cleared_at: number | null; note: string;
};
export type TdListener = { id: string; port: number; kind: string };
export type TdSession = { id: string; name: string; host_ip: string; kind: string; pty: boolean };
export type TdTunnel = { session_id: string; host_ip: string; socks_port: number };
export type TdPortfwd = { session_id: string; host_ip: string; lport: number; rhost: string; rport: number };
export type TeardownInventory = {
  generated_at: number; total: number;
  persistence: TdPersistence[]; uploads: TdUpload[]; listeners: TdListener[];
  sessions: TdSession[]; tunnels: TdTunnel[]; portfwds: TdPortfwd[];
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

export async function patchSession(
  sessionId: string,
  patch: { label?: string; notes?: string; pinned?: boolean },
): Promise<SessionInfo> {
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
  // Defensive: `data` should always be valid base64 from the server, but if a
  // partial write / stray byte slips in, don't let an uncaught DOMException
  // crash the terminal render.
  try { return atob(r.data || ""); } catch { return ""; }
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
// Queue-or-run a task through the beacon-aware /task endpoint. Interactive
// shells run synchronously and the response carries `output_b64` (the raw
// output). Beacons return `status:"queued"` + a task_id — the actual output
// arrives asynchronously when the beacon checks in and posts back through
// /beacon/result. The Run menu uses this so free-form commands work uniformly
// on both session kinds (before this, /quickrun 409'd on beacons because it
// required a live shell socket).
export interface RunTaskResult {
  id: string; host_ip: string; task_id: string;
  status?: "queued" | "done" | "error";
  output_b64?: string; captured_ms?: number;
  output?: string;                          // decoded convenience field, filled in below
  queued?: boolean;                         // true when the beacon path was taken
}
export async function runOrQueueTask(sessionId: string, command: string,
                                     timeoutSec: number = 30): Promise<RunTaskResult> {
  const r = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/task`, {
    method: "POST", headers: jsonHeaders(),
    body: JSON.stringify({ command, timeout: timeoutSec }),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  const j: RunTaskResult = await r.json();
  j.queued = j.status === "queued";
  // Decode output_b64 → output for interactive-shell responses so callers
  // don't each have to base64-decode themselves.
  if (!j.queued && j.output_b64) {
    try { j.output = atob(j.output_b64); } catch { j.output = ""; }
  } else if (!j.output_b64) {
    // Older interactive-mode responses may set `output` directly; leave alone.
    j.output = j.output || "";
  }
  return j;
}

// Beacon self-test: server-side round-trip proving queue → deliver → result
// → save works end-to-end without needing an external client. Returns per-stage
// timings + the saved artifact id on success, or {ok:false, reason} on failure.
export interface BeaconSelftestResult {
  ok: boolean; beacon_id?: string; task_id?: string; artifact_id?: string;
  stages?: { queue_ms?: number; deliver_ms?: number; result_ms?: number;
             tasks_delivered?: number; saved_path?: string; saved_bytes?: number };
  reason?: string;
}
export async function selftestBeacon(bid: string): Promise<BeaconSelftestResult> {
  const r = await fetch(`/api/beacons/${encodeURIComponent(bid)}/selftest`, {
    method: "POST", headers: jsonHeaders(),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}

// Promote a beacon to an interactive shell session by queuing the upgrade
// command. The stager connects back to an active listener on next check-in.
export async function promoteBeacon(bid: string, lhost?: string):
  Promise<{ ok: boolean; task_id: string; callback: string; token: string; message: string }> {
  const r = await fetch(`/api/beacons/${encodeURIComponent(bid)}/promote`, {
    method: "POST", headers: jsonHeaders(),
    body: JSON.stringify(lhost ? { lhost } : {}),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || `HTTP ${r.status}`);
  return r.json();
}

// Unified file-pull → session-loot. Works on both interactive shells (returns
// the saved file synchronously) and beacons (queues a `base64 <path>` task
// tagged loot-pull; /beacon/result auto-decodes + saves when the beacon posts
// its next result). Caller distinguishes by inspecting the response shape.
export interface LootPullSaved { ok: true; saved: string; size: number; artifact_id?: string; sha256?: string; finding_id?: string | null; }
export interface LootPullQueued { status: "queued"; task_id: string; path: string; host_ip: string; message: string; }
export async function pullLoot(sessionId: string, path: string): Promise<LootPullSaved | LootPullQueued> {
  const r = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/loot-pull`, {
    method: "POST", headers: jsonHeaders(), body: JSON.stringify({ path }),
  });
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

// --- Phase 7b — shared-surface readers (KnownAssets tab) ---------------------
// One helper per /api/known/* endpoint. Each returns the raw endpoint payload
// so the view can render totals, per-item detail, and any secondary shape
// (by_host / by_user / by_mode) without a second call.

export type KnownUser = { name: string };
export type KnownUsers = {
  items: KnownUser[]; total: number; sources: string[]; capped: boolean;
};
export const getKnownUsers = () => getJSON<KnownUsers>("/api/known/users");

export type KnownHash = {
  user: string; domain: string; kind: string; source: string;
  hashcat_mode: number; value_preview: string;
};
export type KnownHashes = {
  items: KnownHash[]; total: number;
  by_mode: Record<string, number>;
  categories: Record<string, number>;
  unique_users: number;
};
export const getKnownHashes = () => getJSON<KnownHashes>("/api/known/hashes");

export type KnownDomain = {
  dns: string; netbios: string; sources: string[];
  host_count: number; cred_count: number; is_primary: boolean;
};
export type KnownDomains = {
  items: KnownDomain[]; total: number;
  primary_dns: string; primary_netbios: string; operator_domain: string;
};
export const getKnownDomains = () => getJSON<KnownDomains>("/api/known/domains");

export type KnownHostnames = {
  items: { name: string }[]; total: number; capped: boolean;
  by_host: Record<string, string[]>;
};
export const getKnownHostnames = () => getJSON<KnownHostnames>("/api/known/hostnames");

export type KnownHostkey = {
  fingerprint: string; key_type: string;
  endpoints: string[]; endpoint_count: number; reused: boolean;
};
export type KnownHostkeys = {
  items: KnownHostkey[]; total: number;
  reused: { fingerprint: string; key_type: string; ips: string[]; endpoints: string[] }[];
};
export const getKnownHostkeys = () => getJSON<KnownHostkeys>("/api/known/hostkeys");

export type KnownMailAccount = {
  user: string; domain: string; sources: string[]; hosts: string[];
};
export type KnownMailAccounts = {
  items: KnownMailAccount[]; total: number; by_user: Record<string, string[]>;
};
export const getKnownMailAccounts = () =>
  getJSON<KnownMailAccounts>("/api/known/mail-accounts");

export type KnownOtAsset = {
  vendor?: string; model?: string; serial?: string; firmware?: string;
  protocol?: string; sources?: string[]; ip?: string;
  [k: string]: unknown;
};
export type KnownOtAssets = {
  items: KnownOtAsset[]; total: number;
  by_vendor: Record<string, number>;
  by_firmware: { vendor: string; model: string; firmware: string; count: number }[];
};
export const getKnownOtAssets = () => getJSON<KnownOtAssets>("/api/known/ot-assets");

export type KnownDevice = {
  vendor?: string; model?: string; firmware?: string; kind?: string;
  sources?: string[]; ip?: string;
  cves?: { cve: string; kev?: boolean; confidence?: string }[];
  [k: string]: unknown;
};
export type KnownDevices = {
  items: KnownDevice[]; total: number;
  by_vendor: Record<string, number>;
  cve_candidates: { device: unknown; cve: string; confidence: string }[];
};
export const getKnownDevices = () => getJSON<KnownDevices>("/api/known/devices");

export type RelayTargets = { items: { target: string }[]; total: number };
export const getRelayTargets = () => getJSON<RelayTargets>("/api/relay-targets");

export type HashlootCategory = {
  key: string; filename: string; mode: number; description: string;
};
export type HashlootCategories = { items: HashlootCategory[]; total: number };
export const getHashlootCategories = () =>
  getJSON<HashlootCategories>("/api/hashloot/categories");

// --- Phase C — ExploitSurface tab ("what should I do next") ------------------
// Each finding carries the "your next move" exploit_note (populated by
// service modules) plus a T0..T4 depth_tier. The endpoint filters +
// ranks server-side and groups by attack-chain heuristic. The same
// finding can belong to multiple groups.
export type ExploitFinding = {
  key: string;
  ip: string;
  port: number | null;
  protocol: string;
  service: string;
  title: string;
  severity: string;
  depth_tier: string;
  tier_label: string;
  exploit_note: string;
  kev: boolean;
  cwes: string[];
  cves: string[];
  epss: number;
  script_id: string;
  host_hint: string;
};
export type ExploitSurfaceResponse = {
  items: ExploitFinding[];
  total: number;
  groups: Record<string, string[]>;    // group name -> ordered finding keys
  truncated: boolean;
};
export const getExploitSurface = () =>
  getJSON<ExploitSurfaceResponse>("/api/exploit-surface");

// Exploit PoC scripts — recce's per-finding proof scripts for CONFIRMED findings
// (web PoCs, build recipes, pwntools skeletons). scope: engagement | host
// (target=ip) | finding (target=finding_key).
export type PocArtifact = {
  kind: string; host: string; filename: string; lang: string; source: string;
  proves: string; finding: string; build: string[]; deliver: string; proof: string;
};
export type PocResp = {
  artifacts: PocArtifact[];
  meta: { scope: string; target: string; hosts: number; count: number };
};
export const getPocScripts = (scope: string, target = "") =>
  getJSON<PocResp>(`/api/poc?scope=${encodeURIComponent(scope)}&target=${encodeURIComponent(target)}`);

// Prove (safe verify): which findings can be verified, and the verdict of running it.
export type ProveResult = { verdict: string; evidence?: string[]; finish?: string };
export const getProvable = () =>
  fetch("/api/prove/available").then((r) => (r.ok ? r.json() : { keys: [] }))
    .then((d: { keys: string[] }) => new Set(d.keys || []));
export const postProve = (key: string) =>
  post(`/api/prove/${encodeURIComponent(key)}`) as Promise<ProveResult>;

// --- Suggest tab — the WebUI twin of the `recce suggest` CLI digest ---------
// Three sections mirroring _suggest.py: engagement metrics, cross-service
// rule outputs, and proven-exploitable findings. Read-only; the tester
// uses this as a "given what recce knows, what should I run next?" digest.
export type SuggestDigestMetrics = {
  eng_dir: string;
  host_count: number;
  cred_count: number;
  loot_present: boolean;
  rules_total: number;
  exploit_findings_total: number;
};
export type SuggestDigestRule = {
  key: string;
  command: string;
  field: string;
  suggested_value: string;
  reason: string;
  confidence: "high" | "medium" | "low" | string;
  source: string;
  external_cmd?: string;
  severity?: string;
};
export type SuggestDigestFinding = {
  ip: string;
  port: number | null;
  protocol: string;
  title: string;
  severity: string;
  tier: string;
  tier_label: string;
  kev: boolean;
  epss: number;
  exploit_note: string;
  cves: string[];
};
export type SuggestDigestResponse = {
  metrics: SuggestDigestMetrics;
  rules: SuggestDigestRule[];
  exploit_findings: SuggestDigestFinding[];
  top: number;
};
export const getSuggestDigest = (top: number = 10) =>
  getJSON<SuggestDigestResponse>(`/api/suggest/digest?top=${top}`);

// --- Phase D + P1 — attack-chain walkthroughs --------------------------------
// Three sibling narratives — AD (11 steps), Cloud pivot (6 steps), Web n-day
// (6 steps) — that share one payload shape. Every step reports current
// engagement state (proven / pending / blocked) plus per-step evidence,
// contributing_hosts (deduped IPs across the evidence rows), and the "your
// next move" advisory to run when the step is not yet proven.
export type AttackChainStepStatus = "proven" | "pending" | "blocked" | "skipped";
export type AttackChainEvidence = {
  finding_kind: string;
  ip: string;
  port: number | null;
  output_excerpt: string;
};
export type AttackChainStep = {
  id: string;
  title: string;
  status: AttackChainStepStatus;
  evidence: AttackChainEvidence[];
  next_step: string;
  depends_on: string[];
  shared_surfaces_read: string[];
  // P1-4 — deduped IP list across this step's evidence rows. Empty when
  // every evidence row is union-derived (e.g. known_users).
  contributing_hosts: string[];
};
// P7-C2: `edges` is derived server-side from each step's depends_on so
// the ChainGraph SVG has a stable shape across every chain (AD/Cloud/
// Web) without re-walking dependencies on the client. `from` and `to`
// name step ids; edges whose target isn't in this chain are dropped
// server-side so a malformed dep can't wedge the renderer.
export type AttackChainEdge = { from: string; to: string };
export type AttackChainResponse = {
  steps: AttackChainStep[];
  edges: AttackChainEdge[];
  summary: {
    proven: number;
    pending: number;
    blocked: number;
    total: number;
    highest_reached: string;
    next_action: string;
    step_ids: string[];
  };
};
// Historical alias — the AD chain shipped alone in Phase D under this name.
export type AttackChainAdResponse = AttackChainResponse;
export const getAttackChainAd = () =>
  getJSON<AttackChainResponse>("/api/attack-chain/ad");
export const getAttackChainCloud = () =>
  getJSON<AttackChainResponse>("/api/attack-chain/cloud");
export const getAttackChainWeb = () =>
  getJSON<AttackChainResponse>("/api/attack-chain/web");

// P1-7: ADCS ESC1 auto-request (frontend affordance for the AD chain's
// adcs_esc step). See `recce/webui/routes/adcs_esc1.py` for the strict
// gating design — the confirm_sentinel is the exact string the operator
// must send back to fire, so we always fetch it fresh via /available.
export type AdcsEsc1MatchingCred = {
  username: string; domain: string; source: string; origin_ip: string;
  has_password: boolean; has_hash: boolean; notes: string;
};
export type AdcsEsc1Available = {
  tool_installed: boolean;
  tool_hint: string;
  matching_creds: AdcsEsc1MatchingCred[];
  confirm_sentinel: string;
};
export type AdcsEsc1AttemptRequest = {
  template: string; ca: string; dc_ip: string; domain: string;
  username: string; upn_target: string; confirm: string;
};
export type AdcsEsc1AttemptResult = {
  ok: boolean;
  upn_requested: string; template: string; ca: string; dc_ip: string;
  pfx_saved_at: string; pfx_size: number;
  credential_added: boolean;
  stdout_tail: string; error: string;
  returncode: number | null; elapsed_s: number;
  argv_redacted: string[];
};
export const getAdcsEsc1Available = () =>
  getJSON<AdcsEsc1Available>("/api/adcs/esc1/available");
export async function postAdcsEsc1Attempt(
  body: AdcsEsc1AttemptRequest, tester?: string,
): Promise<AdcsEsc1AttemptResult> {
  const r = await fetch("/api/adcs/esc1/attempt", {
    method: "POST",
    headers: { ...jsonHeaders(), ...(tester ? { "X-Tester": tester } : {}) },
    body: JSON.stringify(body),
  });
  if (!r.ok) {
    let msg = `HTTP ${r.status}`;
    try { const j = await r.json(); if (j?.detail) msg = j.detail; } catch { /* keep */ }
    throw new Error(msg);
  }
  return r.json();
}


// ---------------------------------------------------------------------------
// IA-restructure follow-up: wrappers for the endpoints that were CLI-only
// until Sept 2026. Each helper is a thin post/getJSON around an existing
// backend route — the routes themselves are unchanged.
// ---------------------------------------------------------------------------

// Vulndb / CVE-DB state + refresh.
export type VerifyState = { pending: number; already_ran: number; plan: string[]; completed: string[] };
export const getVerify = () => getJSON<VerifyState>("/api/verify");
export const postVerify = () => post("/api/verify", {});

// Engagement doctor (runs the audit) + the audit's persistent issues list.
export type DoctorIssue = { severity: string; kind: string; message: string; hint?: string };
export type DoctorState = { issues: DoctorIssue[]; counts: Record<string, number> };
export const getIssues = () => getJSON<DoctorState>("/api/issues");
export const postDoctor = () => post("/api/doctor", {});

// Scope editor: list / add / delete an in-scope subnet.
export type ScopeEntry = { subnet: string; size: number };
export const getScope = () => getJSON<ScopeEntry[]>("/api/scope");
export const postScope = (subnet: string, note = "") => post("/api/scope", { subnet, note });
export async function deleteScope(subnet: string) {
  const r = await fetch(`/api/scope/${encodeURIComponent(subnet)}`, { method: "DELETE" });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail ?? r.statusText);
  return r.json();
}

// Field-kit + engagement backup — both return a ZIP body; UI triggers a
// download via a temporary object URL. Fetch as blob rather than JSON.
async function _postBlob(url: string): Promise<Blob> {
  const r = await fetch(url, { method: "POST", headers: jsonHeaders() });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail ?? r.statusText);
  return r.blob();
}
export const postFieldkitExport = () => _postBlob("/api/fieldkit-export");
export const postBackup = () => _postBlob("/api/backup");

// Per-finding write-up (docx). Returns the DOCX bytes as a blob so the UI
// can hand it straight to a download anchor.
export async function postWriteupDocx(key: string): Promise<Blob> {
  const r = await fetch("/api/writeup", {
    method: "POST", headers: jsonHeaders(),
    body: JSON.stringify({ key }),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail ?? r.statusText);
  return r.blob();
}

// Deletes — findings by (ip, key), credentials by their {username, secret,
// kind, domain} tuple (the store dedupe key — no separate id).
export const deleteFinding = (ip: string, key: string) =>
  post("/api/delete/finding", { ip, key });
export const deleteCredential = (b: { username: string; secret: string; kind: string; domain?: string }) =>
  post("/api/delete/credential", b);

// Bulk-review — mark many findings reviewed in one call.
export const postBulkReview = (keys: string[], reviewed = true) =>
  post("/api/bulk-review", { keys, reviewed });

// Proxy indicator (state only; setting the proxy is a serve-time flag).
export type ProxyState = { url: string; enabled: boolean; kind: string };
export const getProxy = () => getJSON<ProxyState>("/api/proxy");

// Job cancel (a scan in flight can be aborted from the jobs list).
export const postJobCancel = (jid: string) =>
  post(`/api/jobs/${encodeURIComponent(jid)}/cancel`, {});

// Loot rescan — re-scan uploaded loot evidence.
export const postLootScanEvidence = () => post("/api/loot/scan-evidence", {});

// SQLi tester — single-URL probe (a full sqlmap run stays CLI-only).
export type SqliResult = { vulnerable: boolean; techniques: string[]; evidence?: string; error?: string };
export const postSqliTest = (url: string, param?: string) =>
  post("/api/sqli/test", { url, param }) as Promise<SqliResult>;

// Task-record layer (async-C2 P0). Every command dispatched through a
// session lands as a row here: queued the moment it's issued, updated in
// place with the result. Same shape whether interactive (round-trips in ms)
// or async beacon (P1, minutes between edges).
export type TaskRow = {
  ts: string; operator: string; session_id: string; host_ip: string;
  kind: string; command: string; output: string; status: string;
  attack: string; task_id: string; result_at: string; bytes: number;
};
export const getSessionTasks = (sid: string, opts: { since?: number; status?: string; limit?: number } = {}) => {
  const p = new URLSearchParams();
  if (opts.since) p.set("since", String(opts.since));
  if (opts.status) p.set("status", opts.status);
  if (opts.limit) p.set("limit", String(opts.limit));
  const qs = p.toString();
  return getJSON<{ id: string; host_ip: string; tasks: TaskRow[] }>(
    `/api/sessions/${encodeURIComponent(sid)}/tasks${qs ? "?" + qs : ""}`);
};

export type Artifact = {
  id: string; ts: string; task_id: string; session_id: string;
  host_ip: string; kind: string; path: string; sha256: string;
  bytes: number; captured_by: string; finding_id: string; note: string;
};
export const getArtifacts = (opts: { host?: string; session?: string; task?: string; finding?: string; limit?: number } = {}) => {
  const p = new URLSearchParams();
  if (opts.host) p.set("host", opts.host);
  if (opts.session) p.set("session", opts.session);
  if (opts.task) p.set("task", opts.task);
  if (opts.finding) p.set("finding", opts.finding);
  if (opts.limit) p.set("limit", String(opts.limit));
  const qs = p.toString();
  return getJSON<{ artifacts: Artifact[] }>(`/api/artifacts${qs ? "?" + qs : ""}`);
};

// Async beacons (P1). A beacon is a session with a queue-backed transport
// instead of a live socket; the operator dispatches tasks the same way,
// but they sit in 'queued' until the beacon client polls /beacon/checkin.
export type Beacon = {
  id: string; host_ip: string; transport: string; registered: number; last_checkin: number;
  sleep_s: number; jitter_pct: number; notes: string;
  // psk is ONLY present on the register response — never on GETs.
};
export type BeaconRegisterResponse = Beacon & {
  psk: string;                     // shown ONCE; operator must copy it now
};
export const listBeacons = () =>
  getJSON<{ beacons: Beacon[] }>("/api/beacons");
export const getBeacon = (bid: string) =>
  getJSON<Beacon>(`/api/beacons/${encodeURIComponent(bid)}`);
export const registerBeacon = (
  body: { host_ip: string; sleep_s?: number; jitter_pct?: number;
          transport?: "http" | "https"; notes?: string },
): Promise<BeaconRegisterResponse> =>
  post("/api/beacons", body) as Promise<BeaconRegisterResponse>;
export const patchBeacon = (bid: string,
                            body: { sleep_s?: number; jitter_pct?: number; notes?: string }) =>
  fetch(`/api/beacons/${encodeURIComponent(bid)}`, {
    method: "PATCH", headers: jsonHeaders(), body: JSON.stringify(body),
  }).then(async (r) => {
    if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail ?? r.statusText);
    return r.json() as Promise<Beacon>;
  });
export const deleteBeacon = (bid: string) =>
  fetch(`/api/beacons/${encodeURIComponent(bid)}`, { method: "DELETE" })
    .then(async (r) => {
      if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail ?? r.statusText);
      return r.json() as Promise<{ ok: true }>;
    });
