import { useCallback, useEffect, useState } from "react";
import { Finding, Host, Overview, fetchAll, postTick, postNote } from "./api";
import { Dashboard, Findings, Hosts, Act, Loot, Playbook, Nav } from "./views";
import { HostDrawer } from "./HostDrawer";
import { PresenceBar, ActivityButton, ChatButton, AddMenu, useCollab } from "./collab";
import { useEscape } from "./ui";
import { TabBar } from "./TabBar";
import { ScanTab } from "./ScanTab";
import { ReportTab } from "./ReportTab";
import { CollabSidebar } from "./CollabSidebar";

// ============================================================================
// HOOKS (extracted for reusability)
// ============================================================================

function useTester() {
  const [who, setWho] = useState(() => localStorage.getItem("recce.tester") || "");
  const [nameInput, setNameInput] = useState("");
  const tester = who || "someone";
  const saveTester = (name: string) => {
    const n = name.trim();
    if (n) {
      localStorage.setItem("recce.tester", n);
      setWho(n);
    }
  };
  return { tester, who, nameInput, setNameInput, saveTester };
}

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

// ============================================================================
// MAIN APP
// ============================================================================

export function App() {
  const { tester, who, nameInput, setNameInput, saveTester } = useTester();
  const { theme, setTheme } = usePreferences();
  const { c, me } = useCollab();

  const [overview, setOverview] = useState<Overview | null>(null);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [activeTab, setActiveTab] = useState<string>("dashboard");
  const [activeHost, setActiveHost] = useState<string>("");
  const [hostDrawerOpen, setHostDrawerOpen] = useState(false);
  const [loading, setLoading] = useState(true);

  // Polling for engagement data
  useEffect(() => {
    const poll = async () => {
      try {
        const all = await fetchAll();
        setOverview(all.overview);
        setHosts(all.hosts);
        setFindings(all.findings);
        setLoading(false);
      } catch (e) {
        console.error("Poll failed:", e);
      }
    };
    poll();
    const id = setInterval(poll, 20000);
    return () => clearInterval(id);
  }, []);

  const handleTick = useCallback(async (findingId: string) => {
    await postTick(findingId);
    setFindings((f) => f.map((v) => (v.id === findingId ? { ...v, reviewed: true } : v)));
  }, []);

  const handleNote = useCallback(async (findingId: string, text: string) => {
    await postNote(findingId, text);
  }, []);

  useEscape(() => setHostDrawerOpen(false));

  if (loading) return <div className="loading">Loading engagement...</div>;

  return (
    <div>
      {/* Header */}
      <div className="top">
        <div className="brand">
          <div className="dot" />
          recce
          <small>{overview?.total_hosts || 0} hosts</small>
        </div>
        <div className="whoami" onClick={() => setNameInput(who)}>
          {tester}
        </div>
        {nameInput && (
          <div className="namegate">
            <input
              autoFocus
              value={nameInput}
              onChange={(e) => setNameInput(e.target.value)}
              placeholder="Your name"
            />
            <button onClick={() => saveTester(nameInput)}>Save</button>
          </div>
        )}
        <PresenceBar />
        <ChatButton />
        <ActivityButton />
        <button onClick={() => setTheme(theme === "dark" ? "light" : "dark")}>
          {theme === "dark" ? "☀️" : "🌙"}
        </button>
        <AddMenu />
      </div>

      {/* Tab Bar & Content */}
      <TabBar active={activeTab} onChange={setActiveTab} />

      <main>
        {activeTab === "dashboard" && <Dashboard overview={overview} onHostClick={(ip) => { setActiveHost(ip); setHostDrawerOpen(true); }} />}
        {activeTab === "findings" && <Findings findings={findings} onTick={handleTick} onNote={handleNote} onHostClick={(ip) => { setActiveHost(ip); setHostDrawerOpen(true); }} />}
        {activeTab === "hosts" && <Hosts hosts={hosts} onHostClick={(ip) => { setActiveHost(ip); setHostDrawerOpen(true); }} />}
        {activeTab === "scan" && <ScanTab />}
        {activeTab === "report" && <ReportTab />}
        {activeTab === "act" && <Act />}
        {activeTab === "loot" && <Loot />}
        {activeTab === "playbook" && <Playbook />}
      </main>

      {/* Collaboration Sidebar */}
      <CollabSidebar hosts={hosts} />

      {/* Host Details Drawer */}
      {hostDrawerOpen && <HostDrawer ip={activeHost} onClose={() => setHostDrawerOpen(false)} />}
    </div>
  );
}

export default App;
