// Shared navigation + data types for the rebuilt workbench sections.
import { Overview, Finding, Host, Playbook } from "./api";

export type SectionId =
  | "overview" | "scan" | "hosts" | "findings"
  | "exploit" | "sessions" | "oplog" | "creds" | "report";

// What App threads into every section: the live engagement data + a small nav api.
export type EngData = {
  ov: Overview | null;
  findings: Finding[];
  hosts: Host[];
  pb: Playbook | null;
  refresh: () => Promise<void> | void;
  setFindings: (fn: (f: Finding[]) => Finding[]) => void;
  setHosts: (fn: (h: Host[]) => Host[]) => void;
};

export type NavCtx = {
  section: SectionId;
  go: (s: SectionId) => void;
  openHost: (ip: string) => void;               // opens the host detail drawer
  // Jump to Findings pre-filtered (e.g. by host or severity).
  toFindings: (o?: { host?: string; sev?: string }) => void;
  // Pending Findings filter, set by toFindings; the Findings section consumes it.
  seed?: { host?: string; sev?: string };
  // Jump to Scan with a host prefilled into the enum launch drawer.
  toScan: (ip: string) => void;
  scanSeed?: { host?: string };
  // Jump to the Exploit tab's "do this now" plan, scrolled to a specific
  // finding's action when a key is given (else just the plan).
  toExploit: (o?: { key?: string; target?: string }) => void;
  exploitSeed?: { key?: string; target?: string };
  // Jump to Scan AND pop the terminal drawer for `jobId` — used by the
  // header 'scan running' pill so a click actually shows the operator
  // what the running scan is doing, instead of just scrolling the drawer
  // (which does nothing when the drawer isn't open yet).
  toScanConsole: (jobId: string) => void;
  scanConsoleSeed?: { jobId?: string; nonce?: number };
  tester: string;
};

export type SectionProps = { data: EngData; nav: NavCtx };
