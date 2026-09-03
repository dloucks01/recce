import { Fragment, useState, useEffect, useRef } from "react";

/**
 * IA restructure (Sept 2026): the workbench collapsed 18 tabs into 11 by
 * folding overlapping surfaces into sub-tabs on three parent tabs:
 *
 *   * Data      = hosts | services | assets       (the "what's out there" trio)
 *   * Attack    = surface | suggest | ad | cloud | web
 *                                                 (all the "what to do next" surfaces)
 *   * Plan      = actions | phases                (Exploitation card view + Playbook track)
 *
 * The old tab ids (hosts, services, assets, exploit, suggest, ad-chain,
 * cloud-chain, web-chain, playbook) are migrated on read from either
 * localStorage OR ?tab= URL so a shared link opens on the right sub-tab.
 */
export type TabId =
  | "dashboard" | "scan" | "data" | "findings" | "attack" | "plan"
  | "topology" | "sessions" | "timeline" | "credentials" | "report";

export type DataSub = "hosts" | "services" | "assets";
export type AttackSub = "surface" | "suggest" | "ad" | "cloud" | "web";
export type PlanSub = "actions" | "phases";
export type AnySub = DataSub | AttackSub | PlanSub;

const TAB_LABELS: Record<TabId, string> = {
  dashboard: "Dashboard",
  scan: "Scan",
  data: "Data",
  findings: "Findings",
  attack: "Attack",
  plan: "Plan",
  topology: "Topology",
  sessions: "Sessions",
  timeline: "Timeline",
  credentials: "Creds",
  report: "Report",
};

// Sub-tab labels per parent tab. Order matters — this is display order.
export const DATA_SUBS: { id: DataSub; label: string; blurb: string }[] = [
  { id: "hosts",    label: "Hosts",    blurb: "one row per host, drilldown to per-service" },
  { id: "services", label: "Services", blurb: "port × service pivot across the whole scope" },
  { id: "assets",   label: "Assets",   blurb: "unions of every known thing recce learned" },
];
export const ATTACK_SUBS: { id: AttackSub; label: string; blurb: string }[] = [
  { id: "surface",  label: "Surface",  blurb: "proven-exploitable findings — click to prove or shell" },
  { id: "suggest",  label: "Suggest",  blurb: "ranked next moves + paste-ready commands" },
  { id: "ad",       label: "AD",       blurb: "Active Directory attack chain (Kerberos → domain admin)" },
  { id: "cloud",    label: "Cloud",    blurb: "cloud pivot chain (IMDS → cross-account → data exfil)" },
  { id: "web",      label: "Web",      blurb: "web-only chain (RCE → foothold → cred replay)" },
];
export const PLAN_SUBS: { id: PlanSub; label: string; blurb: string }[] = [
  { id: "actions",  label: "Actions",  blurb: "ranked action cards for what to run right now" },
  { id: "phases",   label: "Phases",   blurb: "phase track (recon → enum → vuln → …) + narrative" },
];

// Migration map: legacy tab ids -> (new parent tab, sub-tab). Used on
// localStorage load AND when a shared URL uses an old ?tab= value.
export const LEGACY_TO_NEW: Record<string, { tab: TabId; sub?: AnySub }> = {
  // Data trio
  hosts:    { tab: "data",   sub: "hosts" },
  services: { tab: "data",   sub: "services" },
  assets:   { tab: "data",   sub: "assets" },
  // Attack quintet
  exploit:      { tab: "attack", sub: "surface" },
  suggest:      { tab: "attack", sub: "suggest" },
  "ad-chain":   { tab: "attack", sub: "ad" },
  "cloud-chain":{ tab: "attack", sub: "cloud" },
  "web-chain":  { tab: "attack", sub: "web" },
  // Plan pair
  playbook: { tab: "plan",   sub: "phases" },
  // "plan" mapped to the Actions sub-tab (was the old Exploitation view).
  // The bare "plan" id also collides with the new top-tab id — the
  // resolver below prefers the new id when input is exactly "plan".
};

const ALL_TABS: TabId[] = ["dashboard", "scan", "data", "findings", "attack", "plan",
                           "topology", "sessions", "timeline", "credentials", "report"];

// The DEFAULT visible set (all 11 in workflow order — the trim is
// dramatic enough on its own that nothing further needs hiding by
// default). Testers who want a tighter bar hide via the ⋮ menu.
const DEFAULT_VISIBLE: TabId[] = ALL_TABS;

// Visual group boundaries — a divider is inserted BEFORE these tab ids.
const GROUP_BOUNDARIES: Set<TabId> = new Set(["scan", "attack", "report"]);

interface TabBarProps {
  active: TabId;
  onSwitch: (tab: TabId) => void;
  badges?: Partial<Record<TabId, number | undefined>>;
}

export function TabBar({ active, onSwitch, badges }: TabBarProps) {
  const [tabs, setTabs] = useState<TabId[]>(() => {
    const saved = localStorage.getItem("recce.tabs");
    if (saved) {
      try {
        // Migrate stored tab ids. Two eras of renames:
        //   * old "exploitation" -> "plan" -> collapsed to "plan" tab
        //   * P0-4 swap: old "exploit" (attack-plan) -> "plan"; new "surface" -> "exploit"
        //   * 2026-09 IA restructure: hosts/services/assets -> data; exploit/
        //     suggest/ad-chain/cloud-chain/web-chain -> attack; playbook -> plan
        let parsed: string[] = JSON.parse(saved);
        // Map every legacy id to its new parent tab.
        const mapped = parsed.map((t): TabId => {
          if ((ALL_TABS as string[]).includes(t)) return t as TabId;
          const migration = LEGACY_TO_NEW[t];
          if (migration) return migration.tab;
          if (t === "exploitation" || t === "surface") return "attack";
          return "dashboard";                       // fall back rather than drop
        });
        // Dedup after migration (multiple legacy ids may now map to the
        // same parent — the tabbar can only show one instance).
        const seen = new Set<TabId>();
        const unique: TabId[] = [];
        for (const t of mapped) {
          if (!seen.has(t)) { seen.add(t); unique.push(t); }
        }
        return unique.length > 0 ? unique : DEFAULT_VISIBLE;
      } catch {
        return DEFAULT_VISIBLE;
      }
    }
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

  function handleDragStart(tab: TabId) { setDragging(tab); }
  function handleDragOver(e: React.DragEvent) { e.preventDefault(); }
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
          title="Customize which tabs are visible"
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


// -----------------------------------------------------------------------
// SubTabBar — a small pill row rendered inside a parent tab (Data / Attack /
// Plan) when that tab has sub-tabs. Kept in-file so the tab-mechanics stay
// together; styles reuse the existing .tabbar + .tab classes with a "sub"
// modifier for the smaller visual weight.
// -----------------------------------------------------------------------
interface SubTabBarProps<T extends string> {
  subs: { id: T; label: string; blurb?: string }[];
  active: T;
  onSwitch: (id: T) => void;
}

export function SubTabBar<T extends string>({ subs, active, onSwitch }: SubTabBarProps<T>) {
  return (
    <div className="subtabbar" role="tablist">
      {subs.map((s) => (
        <button
          key={s.id}
          role="tab"
          aria-selected={s.id === active}
          className={`subtab ${s.id === active ? "active" : ""}`}
          onClick={() => onSwitch(s.id)}
          title={s.blurb || s.label}
        >
          {s.label}
        </button>
      ))}
    </div>
  );
}
