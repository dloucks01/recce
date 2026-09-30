import { useCallback, useEffect, useRef, useState } from "react";
import { useEngagement } from "./useEngagement";
import { useCollab } from "./collab";
import { toast, Toast } from "./toast";
import { SECTIONS, SECTION_MAP } from "./sections/registry";
import { SectionId, NavCtx, EngData } from "./nav";
import { TeamRail } from "./TeamRail";
import { HostDrawer } from "./HostDrawer";
import { Icon } from "./icons";
import { CommandPalette } from "./CommandPalette";
import { EngagementBadge } from "./components/EngagementBadge";
import { JobsPill } from "./components/JobsPill";
import { AutocrackStatus } from "./components/AutocrackStatus";
import { ProxyBadge } from "./components/ProxyBadge";
import { ImportModal, DoctorModal, ScopeModal, EncDecModal, ShortcutHelp } from "./modals";

type ModalId = "import" | "doctor" | "scope" | "encdec" | "shortcuts";

const VALID = new Set<string>(SECTIONS.map((s) => s.id));
const isSection = (s: string): s is SectionId => VALID.has(s);

function readSection(): SectionId {
  const p = new URLSearchParams(window.location.search).get("section") || "";
  return isSection(p) ? p : "overview";
}

// Persistent per-tester identity (localStorage). Name + a stable token are sent
// on every request by api.ts; here we just hold the display name + a gate.
function useTester() {
  const [who, setWho] = useState(() => localStorage.getItem("recce.tester") || "");
  const tester = who || "someone";
  const save = (name: string) => { const n = name.trim(); if (!n) return; localStorage.setItem("recce.tester", n); setWho(n); };
  return { tester, who, setWho, save };
}

export default function App() {
  const [section, setSection] = useState<SectionId>(readSection);
  const [navCollapsed, setNavCollapsed] = useState(() => localStorage.getItem("recce.nav") === "1");
  const [theme, setTheme] = useState(() => localStorage.getItem("recce.theme") || "light");
  const [railOpen, setRailOpen] = useState(() => localStorage.getItem("recce.rail") !== "0");
  const [findingsSeed, setFindingsSeed] = useState<{ host?: string; sev?: string }>({});
  const [scanSeed, setScanSeed] = useState<{ host?: string }>({});
  const [exploitSeed, setExploitSeed] = useState<{ key?: string }>({});
  const [scanConsoleSeed, setScanConsoleSeed] = useState<{ jobId?: string; nonce?: number }>({});
  const [drawerIp, setDrawerIp] = useState<string | null>(null);
  const [nameInput, setNameInput] = useState("");
  const [activeToast, setActiveToast] = useState<Toast | null>(null);
  const [tools, setTools] = useState(false);
  const [modal, setModal] = useState<ModalId | null>(null);
  const [palette, setPalette] = useState(false);
  const toolsRef = useRef<HTMLDivElement>(null);

  const { tester, who, setWho, save } = useTester();
  const collab = useCollab();
  const note = useCallback((m: string) => toast.show(m), []);
  const eng = useEngagement(tester, note, collab);

  useEffect(() => toast.subscribe(setActiveToast), []);
  useEffect(() => { document.documentElement.dataset.theme = theme === "dark" ? "dark" : "light"; localStorage.setItem("recce.theme", theme); }, [theme]);
  useEffect(() => { document.documentElement.dataset.density = "compact"; }, []);
  useEffect(() => { localStorage.setItem("recce.nav", navCollapsed ? "1" : "0"); }, [navCollapsed]);
  useEffect(() => { localStorage.setItem("recce.rail", railOpen ? "1" : "0"); }, [railOpen]);
  // Keep the section in the URL so links are shareable.
  useEffect(() => {
    const url = section === "overview" ? window.location.pathname : `?section=${section}`;
    window.history.replaceState(null, "", url);
  }, [section]);

  // Global hotkey: Cmd/Ctrl-K toggles the command palette; Esc closes menus.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      const typing = !!t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" || t.tagName === "SELECT" || t.isContentEditable);
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setPalette((v) => !v); }
      else if (e.key === "Escape") { setTools(false); }
      else if (!typing && e.key === "/") { e.preventDefault(); setPalette(true); }
      else if (!typing && e.key === "?") { e.preventDefault(); setModal("shortcuts"); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  // Dismiss the Tools dropdown on an outside click.
  useEffect(() => {
    if (!tools) return;
    const close = (e: MouseEvent) => { if (toolsRef.current && !toolsRef.current.contains(e.target as Node)) setTools(false); };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [tools]);

  const go = useCallback((s: SectionId) => setSection(s), []);
  const nav: NavCtx = {
    section, go, tester, seed: findingsSeed, scanSeed, exploitSeed, scanConsoleSeed,
    openHost: (ip) => setDrawerIp(ip),
    toFindings: (o) => { setFindingsSeed(o || {}); setSection("findings"); },
    toScan: (ip) => { setScanSeed({ host: ip }); setSection("scan"); },
    // Re-set the seed each call (even with the same key) so repeat clicks
    // re-trigger the scroll; a nonce keeps the object identity fresh.
    toExploit: (o) => { setExploitSeed({ ...(o || {}) }); setSection("exploit"); },
    // Nonce so a same-jobId click always re-opens the drawer (React only
    // fires a state-derived effect on identity change — same string wouldn't).
    toScanConsole: (jobId) => {
      setScanConsoleSeed({ jobId, nonce: Date.now() });
      setSection("scan");
    },
  };

  const data: EngData = {
    ov: eng.ov, findings: eng.findings, hosts: eng.hosts, pb: eng.pb,
    refresh: eng.refresh, setFindings: eng.setFindings, setHosts: eng.setHosts,
  };

  const Active = SECTION_MAP[section].Component;
  const badges: Partial<Record<SectionId, number>> = {
    findings: eng.findings.filter((f) => f.tier !== "lead").length || undefined,
    hosts: eng.hosts.length || undefined,
  };

  return (
    <div className="app">
      {/* Left nav rail */}
      <nav className={"nav" + (navCollapsed ? " collapsed" : "")}>
        <div className="nav-brand">
          <h1>recce</h1>
        </div>
        {SECTIONS.map((s) => (
          <button key={s.id} className={"nav-item" + (s.id === section ? " active" : "")}
                  onClick={() => go(s.id)} title={s.label}>
            <span className="ico"><Icon name={s.id} /></span>
            <span className="lbl">{s.label}</span>
            {badges[s.id] != null && <span className="badge">{badges[s.id]}</span>}
          </button>
        ))}
        <div className="nav-spacer" />
        <div className="nav-foot">
          <button className="nav-item" onClick={() => setNavCollapsed((v) => !v)} title="collapse">
            <span className="ico">{navCollapsed ? "»" : "«"}</span><span className="lbl">Collapse</span>
          </button>
        </div>
      </nav>

      {/* Center: topbar + section */}
      <div className="work">
        <header className="topbar">
          <EngagementBadge />
          <span className="grow" />
          <JobsPill onOpenConsole={nav.toScanConsole} />
          <AutocrackStatus />
          <ProxyBadge />
          <button className="search-btn" onClick={() => setPalette(true)} title="search + jump"><span>⌕ search</span><kbd>⌘K</kbd></button>
          <div className="tools-wrap" ref={toolsRef} style={{ position: "relative" }}>
            <button className={"icon-btn" + (tools ? " on" : "")} onClick={() => setTools((v) => !v)} title="tools">⚙</button>
            {tools && (
              <div className="tools-menu" role="menu">
                <button onClick={() => { setModal("import"); setTools(false); }}>Import data…</button>
                <button onClick={() => { setModal("scope"); setTools(false); }}>Scope…</button>
                <button onClick={() => { setModal("encdec"); setTools(false); }}>Encode / Decode…</button>
                <button onClick={() => { setModal("doctor"); setTools(false); }}>Doctor</button>
                <button onClick={() => { setModal("shortcuts"); setTools(false); }}>Keyboard shortcuts</button>
              </div>
            )}
          </div>
          <button className={"icon-btn" + (railOpen ? " on" : "")} onClick={() => setRailOpen((v) => !v)} title="toggle team panel"><Icon name="team" size={16} /></button>
          <button className="icon-btn" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} title="toggle theme">{theme === "dark" ? "☀" : "☾"}</button>
          {who ? (
            <button className="icon-btn" style={{ width: "auto", padding: "0 8px" }} onClick={() => setWho("")} title="change your name">{tester}</button>
          ) : (
            <form className="namebox" onSubmit={(e) => { e.preventDefault(); save(nameInput); }}>
              <input placeholder="your name…" value={nameInput} onChange={(e) => setNameInput(e.target.value)} />
              <button className="btn sm" type="submit" disabled={!nameInput.trim()}>Set</button>
            </form>
          )}
        </header>

        <main className="section">
          <div className="section-head">
            <h2>{SECTION_MAP[section].label}</h2>
          </div>
          {eng.err && <div className="panel" style={{ borderColor: "var(--crit)", color: "var(--crit)", marginBottom: 12 }}>{eng.err}</div>}
          <Active data={data} nav={nav} />
        </main>
      </div>

      {/* Right team rail (collapsible) */}
      {railOpen && <TeamRail />}

      {drawerIp && (
        <HostDrawer ip={drawerIp} onClose={() => setDrawerIp(null)}
          onOpenFinding={(ip) => { setFindingsSeed({ host: ip }); setDrawerIp(null); setSection("findings"); }}
          onScanHost={(ip) => { setScanSeed({ host: ip }); setDrawerIp(null); setSection("scan"); }} />
      )}

      {palette && (
        <CommandPalette hosts={eng.hosts} findings={eng.findings}
          onClose={() => setPalette(false)} go={nav.go} openHost={nav.openHost} toFindings={nav.toFindings} />
      )}
      {modal === "import" && <ImportModal onClose={() => setModal(null)} onJob={() => setSection("scan")} onDone={(m) => toast.show(m)} />}
      {modal === "doctor" && <DoctorModal onClose={() => setModal(null)} />}
      {modal === "scope" && <ScopeModal onClose={() => setModal(null)} />}
      {modal === "encdec" && <EncDecModal onClose={() => setModal(null)} />}
      {modal === "shortcuts" && <ShortcutHelp onClose={() => setModal(null)} />}

      {activeToast && (
        <div style={{ position: "fixed", bottom: 18, left: "50%", transform: "translateX(-50%)", background: "var(--surface)", border: "1px solid var(--line)", borderRadius: "var(--radius)", padding: "8px 14px", boxShadow: "var(--shadow-pop)", zIndex: 50, display: "flex", gap: 10, alignItems: "center" }}>
          <span>{activeToast.msg}</span>
          {activeToast.action && (
            <button className="linkish" onClick={() => { activeToast.action!.onClick(); toast.dismiss(activeToast.id); }}>{activeToast.action.label}</button>
          )}
        </div>
      )}
    </div>
  );
}
