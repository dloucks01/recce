import { useState, useEffect } from "react";

export type TabId = "dashboard" | "scan" | "findings" | "hosts" | "sessions" | "report" | "exploitation" | "credentials" | "playbook";

const TAB_LABELS: Record<TabId, string> = {
  dashboard: "Dashboard",
  scan: "Scan",
  findings: "Findings",
  hosts: "Hosts",
  sessions: "Sessions",
  report: "Report",
  exploitation: "Exploitation",
  credentials: "Credentials",
  playbook: "Playbook",
};

const DEFAULT_TABS: TabId[] = ["dashboard", "scan", "findings", "hosts", "sessions", "report", "exploitation"];

interface TabBarProps {
  active: TabId;
  onSwitch: (tab: TabId) => void;
  badges?: Record<TabId, number | undefined>;
}

export function TabBar({ active, onSwitch, badges }: TabBarProps) {
  const [tabs, setTabs] = useState<TabId[]>(() => {
    const saved = localStorage.getItem("recce.tabs");
    return saved ? JSON.parse(saved) : DEFAULT_TABS;
  });
  const [dragging, setDragging] = useState<TabId | null>(null);

  useEffect(() => {
    localStorage.setItem("recce.tabs", JSON.stringify(tabs));
  }, [tabs]);

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

  const allTabs: TabId[] = Object.keys(TAB_LABELS) as TabId[];
  const hiddenTabs = allTabs.filter((t) => !tabs.includes(t));

  return (
    <div className="tabbar">
      <div className="tabs-scroll">
        {tabs.map((tab) => (
          <button
            key={tab}
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
        ))}
      </div>
      {hiddenTabs.length > 0 && (
        <div className="tab-menu">
          <button
            className="tab-toggle"
            title="Show/hide tabs"
            aria-label="tab options"
          >
            ⋮
          </button>
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
        </div>
      )}
    </div>
  );
}
