import { useCallback, useEffect, useRef, useState } from "react";
import { postTick, postNote } from "./api";
import { ImportModal, ShortcutHelp, CommandPalette } from "./modals";
import { getSessions, getCredentials, SessionInfo, Credential } from "./api";
import { useEngagement } from "./useEngagement";
import { Dashboard, Findings, Hosts, Services, Exploitation, Credentials, Playbook, Timeline, Nav, FindingFilters } from "./views";
import { HostDrawer } from "./HostDrawer";
import { PresenceBar, ActivityButton, ChatButton, AddMenu, useCollab } from "./collab";
import { TabBar, TabId } from "./TabBar";
import { Sessions } from "./sessions";
import { ScanTab } from "./ScanTab";
import { ReportTab } from "./ReportTab";
import { CollabSidebar } from "./CollabSidebar";
import { toast, Toast } from "./toast";

// Tester identity (localStorage-persisted)
function useTester() {
  const [who, setWho] = useState(() => localStorage.getItem("recce.tester") || "");
  const [nameInput, setNameInput] = useState("");
  const tester = who || "someone";
  function saveTester(name: string) {
    const n = name.trim();
    if (!n) return;
    localStorage.setItem("recce.tester", n);
    setWho(n);
  }
  return { tester, who, setWho, nameInput, setNameInput, saveTester };
}

// Theme & density preferences
function usePreferences() {
  const [theme, setTheme] = useState(() => localStorage.getItem("recce.theme") || "light");
  const [density, setDensity] = useState(() => localStorage.getItem("recce.density") || "comfortable");

  useEffect(() => {
    document.documentElement.dataset.theme = theme === "dark" ? "dark" : "light";
    localStorage.setItem("recce.theme", theme);
  }, [theme]);

  useEffect(() => {
    document.documentElement.dataset.density = density;
    localStorage.setItem("recce.density", density);
  }, [density]);

  return { theme, setTheme, density, setDensity };
}

// Main App
const VALID_TABS: TabId[] = ["dashboard", "scan", "findings", "hosts", "services", "sessions", "timeline", "report", "exploitation", "credentials", "playbook"];
const isTab = (t: string): t is TabId => (VALID_TABS as string[]).includes(t);

// Read the initial UI state from the URL once, so a shared link opens in
// the state the sender left off — tab / drawer host / focused session / finding filters.
function readUrlState() {
  const p = new URLSearchParams(window.location.search);
  const tabParam = p.get("tab") || "";
  return {
    tab: isTab(tabParam) ? tabParam : "dashboard" as TabId,
    host: p.get("host") || null,
    session: p.get("session") || null,
    sev: p.get("sev") || "all",
    fhost: p.get("fhost") || "",
    q: p.get("q") || "",
  };
}

export default function App() {
  const initialUrl = useRef(readUrlState()).current;
  const [tab, setTab] = useState<TabId>(initialUrl.tab);

  // cross-tab filter state
  const [ff, setFf] = useState<FindingFilters>({
    sev: initialUrl.sev,
    host: initialUrl.fhost,
    kev: false,
    unreviewed: false,
    leads: false,
    q: initialUrl.q,
  });
  const [hostQ, setHostQ] = useState("");
  const [hostCov, setHostCov] = useState("all");
  const [hostWho, setHostWho] = useState("all");
  const [drawerIp, setDrawerIp] = useState<string | null>(initialUrl.host);
  const [sessionFocus, setSessionFocus] = useState<string | null>(initialUrl.session);

  // UI state
  const [showImport, setShowImport] = useState(false);
  const [activeToast, setActiveToast] = useState<Toast | null>(null);
  const [scanRunning, setScanRunning] = useState(false);
  const [, setScanLog] = useState<string[]>([]);
  const [scanPrefill, setScanPrefill] = useState<string | null>(null);
  const [exploitIntent, setExploitIntent] = useState<import("./views/shared").ExploitIntent | null>(null);

  useEffect(() => toast.subscribe(setActiveToast), []);

  // Sync core UI state to the URL so a shared link opens in the same state.
  // Uses replaceState so we don't spam browser history on every tab click.
  useEffect(() => {
    const p = new URLSearchParams();
    if (tab !== "dashboard") p.set("tab", tab);
    if (drawerIp) p.set("host", drawerIp);
    if (sessionFocus) p.set("session", sessionFocus);
    if (tab === "findings") {
      if (ff.sev !== "all") p.set("sev", ff.sev);
      if (ff.host) p.set("fhost", ff.host);
      if (ff.q) p.set("q", ff.q);
    }
    const q = p.toString();
    const url = q ? `?${q}` : window.location.pathname;
    window.history.replaceState(null, "", url);
  }, [tab, drawerIp, sessionFocus, ff.sev, ff.host, ff.q]);

  // Preferences & identity
  const { theme, setTheme, density, setDensity } = usePreferences();
  const { tester, who, setWho, nameInput, setNameInput, saveTester } = useTester();
  const collab = useCollab();

  const [showShortcuts, setShowShortcuts] = useState(false);
  const [showPalette, setShowPalette] = useState(false);
  const [paletteSessions, setPaletteSessions] = useState<SessionInfo[]>([]);
  const [paletteCreds, setPaletteCreds] = useState<Credential[]>([]);

  // Cmd/Ctrl-K opens a fuzzy-search palette over hosts, findings, sessions,
  // creds, and static actions. Sessions + creds pulled fresh on open so a
  // shell caught 10 seconds ago is instantly there.
  const openPalette = useCallback(() => {
    setShowPalette(true);
    getSessions().then(setPaletteSessions).catch(() => {});
    getCredentials().then(setPaletteCreds).catch(() => {});
  }, []);

  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName || "";
      const inInput = /^(INPUT|TEXTAREA|SELECT)$/.test(tag);

      // Cmd/Ctrl-K anywhere (even inside inputs) — the "jump to anything"
      // shortcut every modern app has. Also K for Kubernetes users' muscle
      // memory who think in "kubectl style" — same key.
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        openPalette();
        return;
      }

      if (e.altKey && e.key >= "1" && e.key <= "9") {
        e.preventDefault();
        try {
          const saved = localStorage.getItem("recce.tabs");
          const visible: TabId[] = saved ? JSON.parse(saved) : [];
          const idx = parseInt(e.key, 10) - 1;
          if (visible[idx]) setTab(visible[idx]);
        } catch {}
        return;
      }

      if (e.altKey && e.key.toLowerCase() === "i") {
        e.preventDefault();
        setShowImport((v) => !v);
        return;
      }

      if (e.key === "Escape") {
        if (showPalette) { setShowPalette(false); return; }
        if (showShortcuts) { setShowShortcuts(false); return; }
        if (drawerIp) { setDrawerIp(null); return; }
        return;
      }

      if (!inInput && e.key === "/") {
        const s = document.querySelector<HTMLInputElement>(".search");
        if (s) { e.preventDefault(); s.focus(); }
        return;
      }

      if (!inInput && e.key === "?") {
        e.preventDefault();
        setShowShortcuts((v) => !v);
        return;
      }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [showShortcuts, showPalette, drawerIp, openPalette]);

  // Notifications — route through the shared toast module so any component can
  // trigger one (including with an Undo action) without prop drilling.
  const note = useCallback((msg: string) => { toast.show(msg); }, []);

  // Engagement data: initial load + slow poll + live SSE. All owned by the hook.
  const { ov, findings, hosts, pb, err, refresh, setFindings, setHosts } =
    useEngagement(tester, note, collab);

  // Optimistic tick/note — with undo. On a big engagement this saves the tester
  // from hunting the row down after a misclick.
  const onTick = useCallback((key: string, reviewed: boolean) => {
    setFindings((fs) => fs.map((f) => (f.key === key ? { ...f, reviewed } : f)));
    setHosts((hs) => hs.map((h) => (h.key === key ? { ...h, reviewed } : h)));
    postTick(key, reviewed).catch(() => {});
    toast.show(reviewed ? "marked reviewed" : "reopened", {
      label: "Undo",
      onClick: () => {
        setFindings((fs) => fs.map((f) => (f.key === key ? { ...f, reviewed: !reviewed } : f)));
        setHosts((hs) => hs.map((h) => (h.key === key ? { ...h, reviewed: !reviewed } : h)));
        postTick(key, !reviewed).catch(() => {});
      },
    });
  }, []);

  const onNote = useCallback((key: string, text: string) => {
    setFindings((fs) => fs.map((f) => (f.key === key ? { ...f, notes: text } : f)));
    setHosts((hs) => hs.map((h) => (h.key === key ? { ...h, notes: text } : h)));
    postNote(key, text).catch(() => {});
  }, []);

  // Tab navigation
  const nav: Nav = {
    toFindings: (o) => {
      setFf({ sev: "all", host: "", kev: false, unreviewed: false, leads: false, q: "", ...o });
      setTab("findings");
    },
    toHosts: (o) => {
      setHostQ(o?.q ?? "");
      setHostWho(o?.owner ?? "all");
      setHostCov("all");
      setTab("hosts");
    },
    toAct: () => setTab("exploitation"),
    openHost: (ip) => setDrawerIp(ip),
    toSessions: () => setTab("sessions"),
    toScan: (target) => { if (target) setScanPrefill(target); setTab("scan"); },
    toExploitShell: (intent) => { setExploitIntent(intent); setSessionFocus(null); setTab("sessions"); },
  };

  // Badge counts
  const badges: Record<TabId, number | undefined> = {
    dashboard: undefined,
    scan: scanRunning ? 1 : undefined,
    findings: findings.filter((f) => f.tier !== "lead").length || undefined,
    hosts: hosts.length || undefined,
    services: ov?.services || undefined,
    sessions: undefined,
    timeline: undefined,
    report: undefined,
    exploitation: undefined,
    credentials: undefined,
    playbook: undefined,
  };

  return (
    <div className="app">
      {/* Header */}
      <div className="app-header">
        <div className="header-left">
          <h1>recce</h1>
          <TabBar active={tab} onSwitch={setTab} badges={badges} />
        </div>
        <div className="header-right">
          <PresenceBar onPick={(name) => nav.toHosts({ owner: name })} />
          <div className="header-actions">
            <AddMenu onDone={(m) => note(m)} />
            <button className="hdr-btn" onClick={() => setShowImport(!showImport)} title="Import tool output (Alt+I)">
              📥
            </button>
            <ActivityButton />
            <ChatButton />
          </div>
          <div className="header-util">
            <button className="theme-tog" onClick={() => setDensity(density === "compact" ? "comfortable" : "compact")}
                    title={density === "compact" ? "comfortable rows" : "compact rows"} aria-label="toggle density">
              {density === "compact" ? "☰" : "≡"}
            </button>
            <button className="theme-tog" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
                    title="toggle light / dark" aria-label="toggle theme">
              {theme === "dark" ? "☀" : "☾"}
            </button>
          </div>
          {who ? (
            <button className="whoami" onClick={() => setWho("")} title="click to change your name">{tester}</button>
          ) : (
            <form className="namegate" onSubmit={(e) => { e.preventDefault(); saveTester(nameInput); }}>
              <input placeholder="your name…" value={nameInput} onChange={(e) => setNameInput(e.target.value)} autoFocus />
              <button type="submit" disabled={!nameInput.trim()}>Set</button>
            </form>
          )}
        </div>
      </div>

      {/* Main content */}
      <div className="app-main">
        <div className="main-content">
          {tab === "dashboard" && (ov ? <Dashboard nav={nav} hosts={hosts} ov={ov} /> : <div className="loading">Loading…</div>)}
          {tab === "scan" && (
            <ScanTab tester={tester} onRunning={setScanRunning} onLog={setScanLog}
                     prefillTarget={scanPrefill} />
          )}
          {tab === "findings" && (
            <Findings
              findings={findings}
              f={ff}
              setF={(o) => setFf((p) => ({ ...p, ...o }))}
              onTick={onTick}
              onNote={onNote}
              nav={nav}
            />
          )}
          {tab === "hosts" && (ov ? (
            <Hosts
              hosts={hosts}
              ov={ov}
              q={hostQ}
              setQ={setHostQ}
              cov={hostCov}
              setCov={setHostCov}
              who={hostWho}
              setWho={setHostWho}
              onTick={onTick}
              onNote={onNote}
              nav={nav}
            />
          ) : <div className="loading">Loading…</div>)}
          {tab === "services" && <Services hosts={hosts} findings={findings} nav={nav} />}
          {tab === "timeline" && <Timeline nav={nav} />}
          {tab === "sessions" && <Sessions tester={tester} focus={sessionFocus}
            exploitIntent={exploitIntent} onExploitConsumed={() => setExploitIntent(null)}
            onScanHost={(ip) => { setScanPrefill(ip); setTab("scan"); }}
            onViewHost={(ip) => setDrawerIp(ip)} />}
          {tab === "report" && <ReportTab findings={findings} onRefresh={() => refresh().catch(() => {})} />}
          {tab === "exploitation" && <Exploitation nav={nav} />}
          {tab === "credentials" && <Credentials nav={nav} />}
          {tab === "playbook" && <Playbook pb={pb} nav={nav} />}
        </div>

        {/* Right sidebar: collab */}
        <div className="sidebar-collab">
          <CollabSidebar hosts={hosts} nav={nav} />
        </div>
      </div>

      {/* Notifications */}
      {activeToast && (
        <div className="flash-message">
          <span>{activeToast.msg}</span>
          {activeToast.action && (
            <button className="flash-action" onClick={() => {
              activeToast.action!.onClick();
              toast.dismiss(activeToast.id);
            }}>{activeToast.action.label}</button>
          )}
        </div>
      )}
      {err && <div className="error-banner">{err}</div>}

      {/* Modals */}
      {showImport && (
        <ImportModal
          onClose={() => setShowImport(false)}
          onJob={() => {
            note("Import started");
            setTab("scan");
          }}
          onDone={(msg) => note(msg)}
        />
      )}

      {showShortcuts && <ShortcutHelp onClose={() => setShowShortcuts(false)} />}

      {showPalette && (
        <CommandPalette
          onClose={() => setShowPalette(false)}
          hosts={hosts} findings={findings}
          sessions={paletteSessions} credentials={paletteCreds}
          onOpenHost={(ip) => { setDrawerIp(ip); }}
          onOpenFinding={(ip, _key) => { nav.toFindings({ host: ip }); }}
          onOpenSession={(id) => { setSessionFocus(id); setTab("sessions"); }}
          onGoto={(t) => setTab(t as TabId)}
          onToggleTheme={() => setTheme(theme === "dark" ? "light" : "dark")}
          onToggleImport={() => setShowImport((v) => !v)}
        />
      )}

      {/* Host detail drawer */}
      {drawerIp && (
        <HostDrawer
          ip={drawerIp}
          onClose={() => setDrawerIp(null)}
          onTick={onTick}
          onNote={onNote}
          onOpenShell={(id) => { setSessionFocus(id); setTab("sessions"); setDrawerIp(null); }}
        />
      )}
    </div>
  );
}
