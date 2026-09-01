import { Fragment, useState, useEffect, useRef } from "react";

export type TabId = "dashboard" | "scan" | "findings" | "hosts" | "services" | "topology" | "sessions" | "timeline" | "report" | "plan" | "exploit" | "ad-chain" | "cloud-chain" | "web-chain" | "credentials" | "playbook" | "assets";

const TAB_LABELS: Record<TabId, string> = {
  dashboard: "Dashboard",
  scan: "Scan",
  findings: "Findings",
  hosts: "Hosts",
  services: "Services",
  topology: "Topology",
  sessions: "Sessions",
  timeline: "Timeline",
  report: "Report",
  // Historical action-plan view (was "exploit" before Phase C). Kept for
  // testers who use the archetype-driven attack-plan tree; the primary
  // "what should I run next" surface moved to the Exploit tab below.
  plan: "Plan",
  // Phase C — proven-exploitable findings + tester "next move" surface.
  // Default-visible: this IS the tab a pentester should land on for
  // "what should I do next given what recce has found". Was called
  // "Surface" during Phase C; renamed to Exploit in P0-4.
  exploit: "Exploit",
  // Phase D — end-to-end AD attack-chain walkthrough. Default-visible so
  // a tester on an AD engagement lands one click from the whole story.
  "ad-chain": "AD Chain",
  // P1-5 / P1-6 — sibling chain walkthroughs. Both default-visible next
  // to AD Chain so a tester lands one click from whichever compromise
  // story matches the engagement.
  "cloud-chain": "Cloud Chain",
  "web-chain": "Web Chain",
  credentials: "Creds",
  playbook: "Playbook",
  // Power-user surface (Phase 7b): unions of everything recce learned across
  // every enum path. Opt-in via the ⋮ menu; not in DEFAULT_VISIBLE.
  assets: "Assets",
};

// Default tab order follows the natural pen-test workflow, grouped into
// three phases separated by visual dividers:
//   PULSE   → dashboard
//   RECON   → scan, findings, hosts, services   (surface + drill + pivot)
//   ATTACK  → exploit, sessions, credentials    (plan + execute + loot)
//   DELIVER → report                            (final artifact)
//
// Playbook + Timeline are secondary — they live in the ⋮ menu by default
// and can be re-added. Testers who use them daily add them back once and
// localStorage remembers.
//
// Testers can still drag-and-drop within the visible set to reorder.
const ALL_TABS: TabId[] = ["dashboard", "scan", "findings", "hosts", "services", "topology",
                           "exploit", "ad-chain", "cloud-chain", "web-chain",
                           "plan", "sessions", "credentials", "report",
                           "playbook", "timeline", "assets"];
// The DEFAULT visible set. Everything after "report" is optional.
// `exploit` (Phase C — proven-exploitable + next-move surface) sits between
// findings/hosts and the ATTACK group so a fresh tester lands one click
// from "what should I do next".
// `ad-chain` / `cloud-chain` / `web-chain` are the three sibling attack-chain
// walkthroughs (Phase D + P1-5 + P1-6) — grouped together so a tester lands
// one click from whichever compromise story matches the engagement.
const DEFAULT_VISIBLE: TabId[] = ["dashboard", "scan", "findings", "hosts", "services", "topology",
                                   "exploit", "ad-chain", "cloud-chain", "web-chain",
                                   "plan", "sessions", "credentials", "report"];

// Visual group boundaries — a divider is inserted BEFORE these tab ids
// when they appear in the visible set. Purely presentational — no
// impact on ordering, drag, or state.
const GROUP_BOUNDARIES: Set<TabId> = new Set(["scan", "exploit", "report"]);

interface TabBarProps {
  active: TabId;
  onSwitch: (tab: TabId) => void;
  badges?: Record<TabId, number | undefined>;
}

export function TabBar({ active, onSwitch, badges }: TabBarProps) {
  const [tabs, setTabs] = useState<TabId[]>(() => {
    const saved = localStorage.getItem("recce.tabs");
    if (saved) {
      // Migrate stored tab ids to current names. Two historical renames:
      //   * "exploitation" (very old) -> "exploit"
      //   * P0-4 swap: old "exploit" (attack-plan panel) -> "plan"
      //                new "surface" (Exploit Surface) -> "exploit"
      // The order matters — the swap must happen atomically so we don't
      // land two "exploit" ids on the tab bar.
      let parsed: TabId[] = JSON.parse(saved).map((t: string): TabId => {
        if (t === "exploitation") return "plan";
        if (t === "exploit") return "plan";      // old attack-plan panel
        if (t === "surface")  return "exploit";  // new Exploit Surface
        return t as TabId;
      });
      // Dedup after migration (in case both ids were present).
      parsed = Array.from(new Set(parsed)) as TabId[];
      // Filter out any obsolete ids we no longer support.
      parsed = parsed.filter(t => ALL_TABS.includes(t));
      return parsed.length > 0 ? parsed : DEFAULT_VISIBLE;
    }
    // First visit: show the workflow-natural default set. Playbook +
    // Timeline live under ⋮ ("more") — testers can add them back.
    return DEFAULT_VISIBLE;
  });
  const [dragging, setDragging] = useState<TabId | null>(null);
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    localStorage.setItem("recce.tabs", JSON.stringify(tabs));
  }, [tabs]);

  useEffect(() => {
    if (!menuOpen) return;
    function close(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false);
    }
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [menuOpen]);

  function handleDragStart(tab: TabId) {
    setDragging(tab);
  }

  function handleDragOver(e: React.DragEvent) {
    e.preventDefault();
  }

  function handleDrop(target: TabId) {
    if (dragging === null || dragging === target) return;
    const dragIdx = tabs.indexOf(dragging);
    const targetIdx = tabs.indexOf(target);
    const newTabs = [...tabs];
    newTabs.splice(dragIdx, 1);
    newTabs.splice(targetIdx, 0, dragging);
    setTabs(newTabs);
    setDragging(null);
  }

  function toggleTab(tab: TabId) {
    if (tabs.includes(tab)) {
      if (tabs.length > 1) {
        setTabs(tabs.filter((t) => t !== tab));
        if (tab === active && tabs.length > 0) onSwitch(tabs[0]);
      }
    } else {
      setTabs([...tabs, tab]);
    }
  }

  const hiddenTabs = ALL_TABS.filter((t) => !tabs.includes(t));

  return (
    <div className="tabbar">
      <div className="tabs-scroll">
        {tabs.map((tab, i) => (
          <Fragment key={tab}>
            {i > 0 && GROUP_BOUNDARIES.has(tab) &&
              <span className="tab-group-divider" aria-hidden="true" />
            }
            <button
              className={`tab ${tab === active ? "active" : ""} ${dragging === tab ? "dragging" : ""}`}
              onClick={() => onSwitch(tab)}
              draggable
              onDragStart={() => handleDragStart(tab)}
              onDragOver={handleDragOver}
              onDrop={() => handleDrop(tab)}
              title={`${TAB_LABELS[tab]}${dragging ? " — drag to reorder" : ""}`}
            >
              {TAB_LABELS[tab]}
              {badges?.[tab] ? (
                <span className="badge">{badges[tab]}</span>
              ) : null}
            </button>
          </Fragment>
        ))}
      </div>
      <div className="tab-menu" ref={menuRef}>
        <button
          className="tab-toggle"
          title="Show/hide tabs"
          aria-label="tab options"
          onClick={() => setMenuOpen(!menuOpen)}
        >
          ⋮
        </button>
        {menuOpen && (
          <div className="tab-menu-popup">
            {hiddenTabs.map((tab) => (
              <button
                key={tab}
                className="tab-menu-item"
                onClick={() => toggleTab(tab)}
              >
                ▢ {TAB_LABELS[tab]}
              </button>
            ))}
            {hiddenTabs.length > 0 && <div className="divider" />}
            <div className="tab-menu-label">Visible:</div>
            {tabs.map((tab) => (
              <button
                key={tab}
                className="tab-menu-item active"
                onClick={() => toggleTab(tab)}
              >
                ☑ {TAB_LABELS[tab]}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
