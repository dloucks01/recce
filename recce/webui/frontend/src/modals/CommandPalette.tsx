import { useEffect, useMemo, useRef, useState } from "react";
import { Finding, Host, SessionInfo, Credential } from "../api";
import { useEscape } from "../ui";

// A Cmd/Ctrl-K command palette that indexes everything the tester can
// jump to — hosts, findings, sessions, credentials, plus static app
// actions. Fuzzy match on the visible text; Enter fires the action.
//
// Design: purely additive over the existing App state (Nav, refresh
// callbacks). No new backend. Sessions and creds are pulled fresh each
// time the palette opens so a shell caught 10s ago is instantly there.

type Item = {
  kind: "host" | "finding" | "session" | "cred" | "action";
  label: string;         // main text
  sub?: string;          // secondary (host, port, CVE, etc.)
  keywords: string;      // pre-lowercased "search corpus" for this row
  score?: number;        // set during matching
  onSelect: () => void;
};

// Case-insensitive substring match with a small bonus for a prefix hit.
// Fast enough for a few thousand rows without an index.
function match(query: string, item: Item): number {
  if (!query) return 1;
  const q = query.toLowerCase();
  const hit = item.keywords.indexOf(q);
  if (hit < 0) {
    // Try loose char-in-order fuzzy — every query char appears in the
    // keywords in order. Half-score so exact matches always outrank.
    let i = 0;
    for (const c of q) {
      i = item.keywords.indexOf(c, i);
      if (i < 0) return 0;
      i++;
    }
    return 0.5;
  }
  return hit === 0 ? 2 : 1;
}

interface CommandPaletteProps {
  onClose: () => void;
  hosts: Host[];
  findings: Finding[];
  sessions: SessionInfo[];
  credentials: Credential[];
  onOpenHost: (ip: string) => void;
  onOpenFinding: (ip: string, key: string) => void;
  onOpenSession: (id: string) => void;
  onGoto: (tab: string) => void;
  onToggleTheme: () => void;
  onToggleImport: () => void;
}

export function CommandPalette(p: CommandPaletteProps) {
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  useEscape(p.onClose);

  useEffect(() => { inputRef.current?.focus(); }, []);

  const items = useMemo<Item[]>(() => {
    const out: Item[] = [];
    // Static actions first so they anchor the top of the list.
    const actions: [string, string, () => void][] = [
      // Palette entries mirror the current 11-tab IA plus muscle-memory
      // shortcuts for the legacy sub-tab names (Hosts / Services / Assets /
      // Exploit / Suggest / AD Chain / Cloud Chain / Web Chain / Playbook)
      // — App.tsx onGoto routes each legacy id to the right parent + sub.
      ["Go to Dashboard", "dashboard home overview", () => p.onGoto("dashboard")],
      ["Go to Scan", "scan run enum vulns", () => p.onGoto("scan")],
      ["Go to Data", "data hosts services assets", () => p.onGoto("data")],
      ["Go to Hosts", "hosts targets", () => p.onGoto("hosts")],
      ["Go to Services", "services ports open protocols", () => p.onGoto("services")],
      ["Go to Assets", "assets known-devices known-users domains", () => p.onGoto("assets")],
      ["Go to Findings", "findings vulns cves", () => p.onGoto("findings")],
      ["Go to Attack", "attack surface suggest chain ad cloud web", () => p.onGoto("attack")],
      ["Go to Attack › Surface", "exploit surface findings next move", () => p.onGoto("exploit")],
      ["Go to Attack › Suggest", "suggest digest ranked next-moves paste-ready", () => p.onGoto("suggest")],
      ["Go to Attack › AD", "ad chain attack walkthrough kerberos dc", () => p.onGoto("ad-chain")],
      ["Go to Attack › Cloud", "cloud chain imds iam sts s3 secrets pivot", () => p.onGoto("cloud-chain")],
      ["Go to Attack › Web", "web chain n-day kev poc oob callback session", () => p.onGoto("web-chain")],
      ["Go to Plan", "plan act attack archetype loot spray escalate", () => p.onGoto("plan")],
      ["Go to Plan › Phases", "playbook phases where we are", () => p.onGoto("playbook")],
      ["Go to Topology", "topology network map svg", () => p.onGoto("topology")],
      ["Go to Sessions", "sessions shells", () => p.onGoto("sessions")],
      ["Go to Timeline", "timeline events history", () => p.onGoto("timeline")],
      ["Go to Creds", "credentials creds passwords", () => p.onGoto("credentials")],
      ["Go to Report", "report studio export", () => p.onGoto("report")],
      ["Toggle theme", "dark light theme mode", p.onToggleTheme],
      ["Import tool output", "import nmap nessus", p.onToggleImport],
    ];
    for (const [label, kw, fn] of actions) {
      out.push({ kind: "action", label, keywords: (label + " " + kw).toLowerCase(), onSelect: fn });
    }
    for (const h of p.hosts) {
      // Roles + notes go into the keyword corpus so "search the DC by role"
      // or "find the host I put a note about" both work from the palette.
      out.push({
        kind: "host", label: h.ip, sub: h.hostname || h.os,
        keywords: `${h.ip} ${h.hostname || ""} ${h.os || ""} ${(h.roles || []).join(" ")} ${h.notes || ""}`.toLowerCase(),
        onSelect: () => p.onOpenHost(h.ip),
      });
    }
    for (const f of p.findings) {
      if (f.tier === "lead") continue; // hide low-conf leads by default
      out.push({
        kind: "finding", label: f.title, sub: `${f.ip}${f.port ? `:${f.port}` : ""}${f.cve ? ` · ${f.cve}` : ""}${f.notes ? ` · ✎ ${f.notes.slice(0, 40)}${f.notes.length > 40 ? "…" : ""}` : ""}`,
        keywords: `${f.title} ${f.ip} ${f.cve || ""} ${(f.cves || []).join(" ")} ${f.severity} ${f.source} ${f.notes || ""}`.toLowerCase(),
        onSelect: () => p.onOpenFinding(f.ip, f.key),
      });
    }
    for (const s of p.sessions) {
      // Include the human-friendly name so "attach to STORMY_BEAR" from the
      // palette works without knowing the hex id.
      out.push({
        kind: "session", label: `${s.name || "shell"} ${s.host_ip}`,
        sub: `${s.status}${s.pty ? " · PTY" : ""}${s.label ? " · " + s.label : ""}`,
        keywords: `session shell ${s.name || ""} ${s.host_ip} ${s.label || ""} ${s.status} ${s.id}`.toLowerCase(),
        onSelect: () => p.onOpenSession(s.id),
      });
    }
    for (const c of p.credentials) {
      out.push({
        kind: "cred", label: `${c.username || "(blank)"} · ${c.kind}`,
        sub: `${c.origin_ip || ""}${c.domain ? " · " + c.domain : ""}${c.source ? " · " + c.source : ""}${c.notes ? ` · ✎ ${c.notes.slice(0, 40)}` : ""}`,
        keywords: `${c.username} ${c.domain || ""} ${c.origin_ip || ""} ${c.source || ""} ${c.kind} ${c.notes || ""}`.toLowerCase(),
        onSelect: () => { p.onGoto("credentials"); p.onClose(); },
      });
    }
    return out;
  }, [p.hosts, p.findings, p.sessions, p.credentials]);

  const results = useMemo(() => {
    const scored = items.map(it => ({ ...it, score: match(q, it) }))
      .filter(it => it.score > 0);
    scored.sort((a, b) => b.score! - a.score!);
    return scored.slice(0, 40);
  }, [items, q]);

  useEffect(() => { setSel(0); }, [q]);
  // Keep the selected row visible on arrow-key nav.
  useEffect(() => {
    const el = listRef.current?.querySelectorAll<HTMLElement>(".cp-row")[sel];
    el?.scrollIntoView({ block: "nearest" });
  }, [sel]);

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setSel(s => Math.min(s + 1, results.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setSel(s => Math.max(s - 1, 0)); }
    else if (e.key === "Enter") {
      e.preventDefault();
      const it = results[sel];
      if (it) { it.onSelect(); p.onClose(); }
    }
  };

  return (
    <>
      <div className="modal-backdrop" onClick={p.onClose} />
      <div className="cp" role="dialog" aria-label="Command palette">
        <input ref={inputRef} className="cp-input" placeholder="Jump to a host, finding, session, cred, or action…"
               value={q} onChange={e => setQ(e.target.value)} onKeyDown={onKey} />
        <div className="cp-list" ref={listRef}>
          {results.length === 0 && (
            <div className="cp-empty">No matches for “{q}”</div>
          )}
          {results.map((it, i) => (
            <div key={i} className={`cp-row cp-${it.kind} ${i === sel ? "sel" : ""}`}
                 onMouseMove={() => setSel(i)}
                 onClick={() => { it.onSelect(); p.onClose(); }}>
              <span className="cp-kind">{KIND_LABEL[it.kind]}</span>
              <span className="cp-label">{it.label}</span>
              {it.sub && <span className="cp-sub muted">{it.sub}</span>}
            </div>
          ))}
        </div>
        <div className="cp-hint muted">
          <kbd>↑↓</kbd> navigate · <kbd>Enter</kbd> select · <kbd>Esc</kbd> close
        </div>
      </div>
    </>
  );
}

const KIND_LABEL: Record<Item["kind"], string> = {
  host: "host", finding: "finding", session: "sess",
  cred: "cred", action: "go",
};
