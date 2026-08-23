import { useCallback, useEffect, useRef, useState } from "react";
import {
  Finding, Host, Overview, fetchAll, postTick, postNote, postImport,
  fetchPlaybook, Playbook as PlaybookData,
} from "./api";
import { Dashboard, Findings, Hosts, Act, Loot, Playbook, Nav, FindingFilters } from "./views";
import { HostDrawer } from "./HostDrawer";
import { PresenceBar, ActivityButton, ChatButton, AddMenu, useCollab } from "./collab";
import { useEscape } from "./ui";
import { TabBar, TabId } from "./TabBar";
import { Sessions } from "./Sessions";
import { ScanTab } from "./ScanTab";
import { ReportTab } from "./ReportTab";
import { CollabSidebar } from "./CollabSidebar";

const POLL_MS = 20000; // constantly-updating analysis: re-pull on a slow heartbeat

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

// Import modal (DRY from existing App.tsx)
const IMPORT_TOOLS: [string, string][] = [
  ["auto", "Auto-detect"],
  ["nmap", "nmap / masscan  (.xml / .gnmap / .nmap)"],
  ["nessus", "Nessus  (.nessus export)"],
  ["openvas", "OpenVAS / Greenbone  (GVM XML)"],
  ["nuclei", "nuclei  (JSON / JSONL)"],
  ["testssl", "testssl.sh  (JSON)"],
  ["nxc", "netexec / crackmapexec  (smb / ldap / mssql / winrm)"],
  ["kerberoast", "impacket GetUserSPNs  (Kerberoast)"],
  ["asrep", "impacket GetNPUsers  (AS-REP)"],
  ["secretsdump", "impacket secretsdump  (NTLM hashes)"],
  ["creds", "Credential list  (user:password per line)"],
  ["bloodhound", "BloodHound / Certipy  (.zip / certipy .json)"],
  ["loot", "recce on-target enum  (recce-enum.sh/.ps1)"],
  ["fieldkit", "fieldkit findings  (findings.json)"],
];

const isBinaryFile = (name: string) => /\.zip$/i.test(name);

function ImportModal(
  { onClose, onJob, onDone }: { onClose: () => void; onJob: (id: string) => void; onDone: (msg: string) => void }
) {
  const [kind, setKind] = useState("auto");
  const [text, setText] = useState("");
  const [filename, setFilename] = useState("");
  const [encoding, setEncoding] = useState("");
  const [busy, setBusy] = useState(false);
  const [drag, setDrag] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [prev, setPrev] = useState<
    { kind: string; count: number; detail: string; sample: string[]; warning: string } | null
  >(null);
  useEscape(onClose, !busy);

  function readFile(file: File) {
    const r = new FileReader();
    setFilename(file.name);
    setPrev(null);
    setErr(null);
    r.onload = () => {
      const url = String(r.result || "");
      setText(url.slice(url.indexOf(",") + 1));
      setEncoding("base64");
    };
    r.readAsDataURL(file);
    if (isBinaryFile(file.name) && kind === "auto") setKind("bloodhound");
  }

  async function doPreview() {
    if (!text.trim() || busy) return;
    setBusy(true);
    setErr(null);
    setPrev(null);
    try {
      const res = await postImport(text, filename, kind, encoding, true);
      if (res.mode === "preview") setPrev(res);
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  }

  async function go() {
    if (!text.trim() || busy) return;
    setBusy(true);
    setErr(null);
    try {
      const res = await postImport(text, filename, kind, encoding);
      if (res.mode === "job") {
        onJob(res.id);
        onClose();
      } else if (res.mode === "done") {
        onDone(res.summary || `imported ${res.added} item(s)`);
        onClose();
      }
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="modal-backdrop" onClick={onClose} />
      <div className="modal" role="dialog" aria-label="Import tool output">
        <div className="modal-h">
          <h3>Import tool output</h3>
          <button className="drawer-x" onClick={onClose} aria-label="close">
            ✕
          </button>
        </div>
        <p className="modal-sub">
          Drop a file or paste output from any supported tool. recce folds it into this engagement and every open
          browser updates — no terminal needed.
        </p>
        <label className="imp-field">
          Tool
          <select value={kind} onChange={(e) => {
            setKind(e.target.value);
            setPrev(null);
          }} disabled={busy}>
            {IMPORT_TOOLS.map(([k, label]) => (
              <option key={k} value={k}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <div
          className={"dropzone" + (drag ? " over" : "")}
          onDragOver={(e) => {
            e.preventDefault();
            setDrag(true);
          }}
          onDragLeave={() => setDrag(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDrag(false);
            const f = e.dataTransfer.files[0];
            if (f) readFile(f);
          }}
        >
          <span>⭱ Drop a file here, or </span>
          <label className="filepick">
            browse
            <input
              type="file"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) readFile(f);
              }}
              hidden
            />
          </label>
          {filename && <span className="imp-fn">· {filename}</span>}
        </div>
        <textarea
          className="imp-paste"
          placeholder="…or paste the tool output here"
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            setEncoding("");
            setPrev(null);
          }}
          disabled={busy}
        />
        {prev && (
          <div className={"imp-preview" + (prev.warning ? " warn" : "")}>
            <div>
              <b>{prev.kind}</b>
              {prev.detail ? ` · ${prev.detail}` : ` · ${prev.count} item(s)`}
            </div>
            {prev.sample?.length > 0 && <ul>{prev.sample.map((s, i) => <li key={i}>{s}</li>)}</ul>}
            {prev.warning && <div className="warn-msg">{prev.warning}</div>}
          </div>
        )}
        {err && <div className="ranmsg warn-msg">{err}</div>}
        <div className="modal-actions">
          <button className="toggle" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="toggle" onClick={doPreview} disabled={busy || !text.trim()}>
            Preview
          </button>
          <button className="run" onClick={go} disabled={busy || !text.trim()}>
            {busy ? "Importing…" : "Import"}
          </button>
        </div>
      </div>
    </>
  );
}

// Main App
export default function App() {
  const [ov, setOv] = useState<Overview | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [pb, setPb] = useState<PlaybookData | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tab, setTab] = useState<TabId>("dashboard");

  // cross-tab filter state
  const [ff, setFf] = useState<FindingFilters>({
    sev: "all",
    host: "",
    kev: false,
    unreviewed: false,
    leads: false,
    q: "",
  });
  const [hostQ, setHostQ] = useState("");
  const [hostCov, setHostCov] = useState("all");
  const [hostWho, setHostWho] = useState("all");
  const [drawerIp, setDrawerIp] = useState<string | null>(null);

  // UI state
  const [showImport, setShowImport] = useState(false);
  const [flash, setFlash] = useState<string | null>(null);
  const [scanRunning, setScanRunning] = useState(false);
  const [, setScanLog] = useState<string[]>([]);
  const flashTimer = useRef<number | undefined>(undefined);

  // Preferences & identity
  const { theme, setTheme, density, setDensity } = usePreferences();
  const { tester, who, setWho, nameInput, setNameInput, saveTester } = useTester();
  const collab = useCollab();

  // "/" key to focus search
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName || "";
      if (e.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test(tag)) {
        const s = document.querySelector<HTMLInputElement>(".search");
        if (s) {
          e.preventDefault();
          s.focus();
        }
      }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);

  // Notifications
  const note = useCallback((msg: string) => {
    setFlash(msg);
    window.clearTimeout(flashTimer.current);
    flashTimer.current = window.setTimeout(() => setFlash(null), 4000);
  }, []);

  // Data refresh
  const refresh = useCallback(async () => {
    const [o, f, h] = await fetchAll();
    setOv(o);
    setFindings(f);
    setHosts(h);
    fetchPlaybook().then(setPb).catch(() => {});
  }, []);

  useEffect(() => {
    refresh().catch((e) => setErr(String(e)));
  }, [refresh]);

  // Slow poll
  useEffect(() => {
    const id = window.setInterval(() => {
      refresh().catch(() => {});
    }, POLL_MS);
    return () => window.clearInterval(id);
  }, [refresh]);

  // Live cross-user events
  useEffect(() => {
    const es = new EventSource("/api/events");
    es.onmessage = (m) => {
      let d: any;
      try {
        d = JSON.parse(m.data);
      } catch {
        return;
      }
      if (d.type === "tick") {
        setFindings((fs) => fs.map((f) => (f.key === d.key ? { ...f, reviewed: d.reviewed } : f)));
        setHosts((hs) => hs.map((h) => (h.key === d.key ? { ...h, reviewed: d.reviewed } : h)));
        if (d.tester !== tester) note(`${d.tester} ${d.reviewed ? "checked off" : "reopened"} an item`);
      } else if (d.type === "note") {
        setFindings((fs) => fs.map((f) => (f.key === d.key ? { ...f, notes: d.note } : f)));
        setHosts((hs) => hs.map((h) => (h.key === d.key ? { ...h, notes: d.note } : h)));
        if (d.tester !== tester) note(`${d.tester} left a note`);
      } else if (d.type === "scan_started") {
        note(`${d.tester} started a ${d.targets} scan`);
      } else if (d.type === "scan") {
        note(`${d.tester}'s scan ${d.status}`);
        refresh().catch(() => {});
      } else if (d.type === "import") {
        if (d.tester !== tester) note(`${d.tester} imported ${d.kind} output`);
        refresh().catch(() => {});
      } else if (["assign", "label", "port_status", "dismiss", "add"].includes(d.type)) {
        collab.refresh();
        if (d.type === "add") refresh().catch(() => {});
        if (d.by && d.by !== tester) {
          if (d.type === "assign") note(`${d.by} ${d.tester ? "claimed" : "released"} ${d.ip}`);
          else if (d.type === "add") note(`${d.by} added a ${d.what}`);
        }
      } else if (d.type === "chat" && d.msg) {
        collab.pushChat(d.msg);
        if (d.msg.tester !== tester) note(`💬 ${d.msg.tester}: ${d.msg.text || "sent an image"}`.slice(0, 80));
      }
    };
    return () => es.close();
  }, [tester, note, refresh, collab]);

  // Optimistic tick/note
  const onTick = useCallback((key: string, reviewed: boolean) => {
    setFindings((fs) => fs.map((f) => (f.key === key ? { ...f, reviewed } : f)));
    setHosts((hs) => hs.map((h) => (h.key === key ? { ...h, reviewed } : h)));
    postTick(key, reviewed).catch(() => {});
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
    toAct: () => setTab("act"),
    openHost: (ip) => setDrawerIp(ip),
  };

  // Badge counts
  const badges: Record<TabId, number | undefined> = {
    dashboard: undefined,
    scan: scanRunning ? 1 : undefined,
    findings: findings.filter((f) => f.tier !== "lead").length || undefined,
    hosts: hosts.length || undefined,
    sessions: undefined,
    report: undefined,
    act: undefined,
    loot: undefined,
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
          <button className="action-btn" onClick={() => setShowImport(!showImport)} title="Import tool output">
            📥 Import
          </button>
          <ActivityButton />
          <ChatButton />
          <AddMenu onDone={(m) => note(m)} />
          <button className="theme-tog" onClick={() => setDensity(density === "compact" ? "comfortable" : "compact")}
                  title={density === "compact" ? "comfortable rows" : "compact rows"} aria-label="toggle density">
            {density === "compact" ? "☰" : "≡"}
          </button>
          <button className="theme-tog" onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
                  title="toggle light / dark" aria-label="toggle theme">
            {theme === "dark" ? "☀" : "☾"}
          </button>
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
            <ScanTab tester={tester} onRunning={setScanRunning} onLog={setScanLog} />
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
          {tab === "sessions" && <Sessions tester={tester} />}
          {tab === "report" && <ReportTab onRefresh={() => refresh().catch(() => {})} />}
          {tab === "act" && <Act nav={nav} />}
          {tab === "loot" && <Loot />}
          {tab === "playbook" && <Playbook pb={pb} nav={nav} />}
        </div>

        {/* Right sidebar: collab */}
        <div className="sidebar-collab">
          <CollabSidebar hosts={hosts} nav={nav} />
        </div>
      </div>

      {/* Notifications */}
      {flash && <div className="flash-message">{flash}</div>}
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

      {/* Host detail drawer */}
      {drawerIp && (
        <HostDrawer
          ip={drawerIp}
          onClose={() => setDrawerIp(null)}
          onTick={onTick}
          onNote={onNote}
        />
      )}
    </div>
  );
}
