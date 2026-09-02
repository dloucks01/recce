import { useCallback, useEffect, useRef, useState } from "react";
import { postTick, postNote } from "./api";
import { ImportModal, ShortcutHelp, CommandPalette, EncDecModal } from "./modals";
import { ToolsMenu } from "./ToolsMenu";
import { getSessions, getCredentials, getListeners, startListener, SessionInfo, Credential } from "./api";
import { useEngagement } from "./useEngagement";
import { Dashboard, Findings, Hosts, Services, Exploitation, Credentials, Playbook, Timeline, Topology, Nav, FindingFilters } from "./views";
import { KnownAssets } from "./views/KnownAssets";
import { ExploitSurface, ExploitSurfaceCallout } from "./views/ExploitSurface";
import { SuggestDigest } from "./views/SuggestDigest";
import { AttackChain } from "./views/AttackChain";
import { AttackChainCloud } from "./views/AttackChainCloud";
import { AttackChainWeb } from "./views/AttackChainWeb";
import { HostDrawer } from "./HostDrawer";
import { PresenceBar, ActivityButton, ChatButton, AddMenu, useCollab } from "./collab";
import { TabBar, TabId, SubTabBar, DataSub, AttackSub, PlanSub, AnySub,
         DATA_SUBS, ATTACK_SUBS, PLAN_SUBS, LEGACY_TO_NEW } from "./TabBar";
import { Skeleton } from "./ui";

/** Placeholder shown while the initial engagement Overview is loading. Mirrors
 * the shape of the real dashboard (stats row + priority card + panel) so the
 * layout doesn't shift when the data arrives. */
function DashboardSkeleton() {
  return (
    <div className="dash">
      <div className="dash-priority">
        <div className="stats stats-priority" style={{ display: "grid", gap: 12 }}>
          <Skeleton variant="block" height="70px" />
          <Skeleton variant="block" height="70px" />
          <Skeleton variant="block" height="70px" />
        </div>
        <Skeleton variant="block" height="140px" />
      </div>
      <div className="dash-snapshot">
        <Skeleton variant="block" height="90px" />
        <Skeleton variant="block" height="160px" />
      </div>
    </div>
  );
}
import { Sessions } from "./sessions";
import { ScanTab } from "./ScanTab";
import { ReportTab } from "./ReportTab";
import { CollabSidebar } from "./CollabSidebar";
import { AutocrackStatus } from "./components/AutocrackStatus";
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

// Theme & density preferences. Density is a tri-state: compact / normal /
// comfortable — driven by the row-y-* tokens in tokens.css.
type Density = "compact" | "normal" | "comfortable";
const DENSITY_ORDER: Density[] = ["compact", "normal", "comfortable"];
const DENSITY_ICON: Record<Density, string> = { compact: "☰", normal: "≡", comfortable: "⩸" };
const DENSITY_LABEL: Record<Density, string> = {
  compact: "compact rows",
  normal: "normal rows",
  comfortable: "comfortable rows",
};

function usePreferences() {
  const [theme, setTheme] = useState(() => localStorage.getItem("recce.theme") || "light");
  const [density, setDensity] = useState<Density>(() => {
    const raw = localStorage.getItem("recce.density");
    return (raw === "compact" || raw === "normal" || raw === "comfortable")
      ? raw : "comfortable";
  });

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

// Cycle through the density tri-state on click.
function cycleDensity(cur: Density): Density {
  const i = DENSITY_ORDER.indexOf(cur);
  return DENSITY_ORDER[(i + 1) % DENSITY_ORDER.length];
}

// Main App
const VALID_TABS: TabId[] = ["dashboard", "scan", "data", "findings", "attack", "plan",
                             "topology", "sessions", "timeline", "credentials", "report"];
const isTab = (t: string): t is TabId => (VALID_TABS as string[]).includes(t);

// Read the initial UI state from the URL once, so a shared link opens in
// the state the sender left off — tab / drawer host / focused session /
// finding filters. Legacy tab ids (hosts, services, assets, exploit,
// suggest, ad-chain, cloud-chain, web-chain, playbook) resolve to their
// new parent tab + sub-tab so old shared links keep working.
function readUrlState() {
  const p = new URLSearchParams(window.location.search);
  const raw = p.get("tab") || "";
  let tab: TabId = isTab(raw) ? raw : "dashboard";
  let subOverride: { tab: TabId; sub: AnySub } | null = null;
  if (!isTab(raw) && raw) {
    const mig = LEGACY_TO_NEW[raw];
    if (mig) {
      tab = mig.tab;
      if (mig.sub) subOverride = { tab: mig.tab, sub: mig.sub };
    }
  }
  // Explicit ?sub= overrides legacy mapping (new shared URLs).
  const subRaw = p.get("sub") || "";
  if (subRaw && isTab(tab)) subOverride = { tab, sub: subRaw as AnySub };
  return {
    tab,
    subOverride,
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

  // Sub-tabs per parent tab. Only Data / Attack / Plan have them.
  // Legacy URLs like ?tab=ad-chain arrive as tab=attack + a subOverride
  // seed from readUrlState (see LEGACY_TO_NEW for the migration map).
  const [dataSub, setDataSub] = useState<DataSub>(
    (initialUrl.subOverride?.tab === "data" ? initialUrl.subOverride.sub as DataSub : null)
    ?? "hosts");
  const [attackSub, setAttackSub] = useState<AttackSub>(
    (initialUrl.subOverride?.tab === "attack" ? initialUrl.subOverride.sub as AttackSub : null)
    ?? "surface");
  const [planSub, setPlanSub] = useState<PlanSub>(
    (initialUrl.subOverride?.tab === "plan" ? initialUrl.subOverride.sub as PlanSub : null)
    ?? "actions");

  // Helper: current sub-tab id for the active parent (or null when the
  // parent has no sub-tabs). Used only for URL sync.
  const currentSub: AnySub | null =
    tab === "data"   ? dataSub :
    tab === "attack" ? attackSub :
    tab === "plan"   ? planSub :
    null;

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
  const [showEncDec, setShowEncDec] = useState(false);
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
    // Persist the current sub-tab only when it's not the parent's default
    // (avoids ?sub=hosts / ?sub=surface / ?sub=actions cluttering every URL).
    if (currentSub) {
      const isDefault =
        (tab === "data" && currentSub === "hosts") ||
        (tab === "attack" && currentSub === "surface") ||
        (tab === "plan" && currentSub === "actions");
      if (!isDefault) p.set("sub", currentSub);
    }
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
  }, [tab, currentSub, drawerIp, sessionFocus, ff.sev, ff.host, ff.q]);

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
      setDataSub("hosts");
      setTab("data");
    },
    // Actions view = Exploitation cards, now the default sub of the Plan tab.
    toAct: () => { setPlanSub("actions"); setTab("plan"); },
    openHost: (ip) => setDrawerIp(ip),
    toSessions: () => setTab("sessions"),
    toScan: (target) => { if (target) setScanPrefill(target); setTab("scan"); },
    toExploitShell: async (intent) => {
      // Auto-start a listener if none is open — the tester clicked "🎯 shell"
      // meaning they want a callback right now, and hunting for the Listeners
      // panel first is friction. Try 4444 (msf's canonical default LPORT), fall
      // back to a kernel-picked port if 4444 is taken. If both fail we still
      // jump — the intent banner shows an amber "start one first" hint.
      try {
        const existing = await getListeners();
        if (existing.length === 0) {
          try { await startListener(4444, false); }
          catch { try { await startListener(0, false); } catch { /* banner will nag */ } }
        }
      } catch { /* listener list fetch failed — jump anyway */ }
      setExploitIntent(intent); setSessionFocus(null); setTab("sessions");
    },
  };

  // Badge counts — 11 top tabs. The Data tab shows the sub-tab that has
  // the most rows so the operator sees at-a-glance which pane will land.
  const badges: Partial<Record<TabId, number | undefined>> = {
    scan: scanRunning ? 1 : undefined,
    data: hosts.length || undefined,
    findings: findings.filter((f) => f.tier !== "lead").length || undefined,
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
            <button className="hdr-search" onClick={() => setShowPalette(true)}
                    title="Search + jump (Ctrl-K)">
              <span className="hdr-search-ico">⌕</span>
              <span className="hdr-search-hint">search</span>
              <kbd className="hdr-search-key">⌘K</kbd>
            </button>
            <ToolsMenu
              onImport={() => setShowImport(true)}
              onEncDec={() => setShowEncDec(true)}
            />
            <ActivityButton />
            <ChatButton />
            <AutocrackStatus />
          </div>
          <div className="header-util">
            <button className="theme-tog" onClick={() => setDensity(cycleDensity(density))}
                    title={`Density: ${DENSITY_LABEL[density]} — click to cycle`}
                    aria-label="cycle density">
              {DENSITY_ICON[density]}
            </button>
            <button className="theme-tog" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
                    title="toggle light / dark" aria-label="toggle theme">
              {theme === "dark" ? "☀" : "☾"}
            </button>
            <button className="theme-tog" onClick={() => setShowShortcuts(true)}
                    title="Keyboard shortcuts (?)" aria-label="shortcuts help">
              ?
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
          {tab === "dashboard" && (
            <>
              {/* Phase C — proven-exploitable callout above the standard Dashboard.
                  Renders nothing when no findings carry an exploit_note. */}
              <ExploitSurfaceCallout
                onOpenHost={(ip) => setDrawerIp(ip)}
                onJumpToSurface={() => { setAttackSub("surface"); setTab("attack"); }}
              />
              {ov ? <Dashboard nav={nav} hosts={hosts} ov={ov} /> : <DashboardSkeleton />}
            </>
          )}
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
          {/* Data tab — hosts / services / assets grouped so the "what's out
              there" trio shares one screen with a lightweight sub-tab row.  */}
          {tab === "data" && (
            <>
              <SubTabBar subs={DATA_SUBS} active={dataSub} onSwitch={setDataSub} />
              {dataSub === "hosts" && (ov ? (
                <Hosts hosts={hosts} ov={ov}
                  q={hostQ} setQ={setHostQ}
                  cov={hostCov} setCov={setHostCov}
                  who={hostWho} setWho={setHostWho}
                  onTick={onTick} onNote={onNote} nav={nav} />
              ) : <DashboardSkeleton />)}
              {dataSub === "services" && <Services hosts={hosts} findings={findings} nav={nav} />}
              {dataSub === "assets" && <KnownAssets />}
            </>
          )}
          {tab === "topology" && <Topology />}
          {tab === "timeline" && <Timeline nav={nav} />}
          {tab === "sessions" && <Sessions tester={tester} focus={sessionFocus}
            exploitIntent={exploitIntent} onExploitConsumed={() => setExploitIntent(null)}
            onScanHost={(ip) => { setScanPrefill(ip); setTab("scan"); }}
            onViewHost={(ip) => setDrawerIp(ip)} />}
          {tab === "report" && <ReportTab findings={findings} onRefresh={() => refresh().catch(() => {})} />}
          {/* Attack tab — Surface / Suggest / AD / Cloud / Web all live here as
              sub-tabs. Surface is the default landing per Phase C. */}
          {tab === "attack" && (
            <>
              <SubTabBar subs={ATTACK_SUBS} active={attackSub} onSwitch={setAttackSub} />
              {attackSub === "surface" && <ExploitSurface onOpenHost={(ip) => setDrawerIp(ip)} />}
              {attackSub === "suggest" && <SuggestDigest onOpenHost={(ip) => setDrawerIp(ip)} />}
              {attackSub === "ad"      && <AttackChain onOpenHost={(ip) => setDrawerIp(ip)} />}
              {attackSub === "cloud"   && <AttackChainCloud onOpenHost={(ip) => setDrawerIp(ip)} />}
              {attackSub === "web"     && <AttackChainWeb onOpenHost={(ip) => setDrawerIp(ip)} />}
            </>
          )}
          {tab === "credentials" && <Credentials nav={nav} />}
          {/* Plan tab — Actions (ranked action cards from Exploitation) +
              Phases (the phase-track Playbook narrative). */}
          {tab === "plan" && (
            <>
              <SubTabBar subs={PLAN_SUBS} active={planSub} onSwitch={setPlanSub} />
              {planSub === "actions" && <Exploitation nav={nav} />}
              {planSub === "phases"  && <Playbook pb={pb} nav={nav} />}
            </>
          )}
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

      {showEncDec && <EncDecModal onClose={() => setShowEncDec(false)} />}

      {showPalette && (
        <CommandPalette
          onClose={() => setShowPalette(false)}
          hosts={hosts} findings={findings}
          sessions={paletteSessions} credentials={paletteCreds}
          onOpenHost={(ip) => { setDrawerIp(ip); }}
          onOpenFinding={(ip, _key) => { nav.toFindings({ host: ip }); }}
          onOpenSession={(id) => { setSessionFocus(id); setTab("sessions"); }}
          onGoto={(t) => {
            // Route legacy tab ids ("hosts", "ad-chain", "playbook", …) into
            // their new parent tab + sub-tab so old palette entries still
            // work by muscle memory.
            if ((VALID_TABS as string[]).includes(t)) {
              setTab(t as TabId);
              return;
            }
            const mig = LEGACY_TO_NEW[t];
            if (!mig) return;
            setTab(mig.tab);
            if (mig.tab === "data" && mig.sub)   setDataSub(mig.sub as DataSub);
            if (mig.tab === "attack" && mig.sub) setAttackSub(mig.sub as AttackSub);
            if (mig.tab === "plan" && mig.sub)   setPlanSub(mig.sub as PlanSub);
          }}
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
