import { useCallback, useEffect, useRef, useState } from "react";
import {
  Finding, Host, Overview, fetchAll, postTick, postNote, postScan, postImport,
} from "./api";
import { Dashboard, Findings, Hosts, Targets, Act, Loot, Nav, FindingFilters } from "./views";
import { HostDrawer } from "./HostDrawer";

type Tab = "dashboard" | "findings" | "act" | "loot" | "hosts" | "targets";
type TgFilter = "all" | "todo" | "enumerated" | "access" | "reviewed";
const POLL_MS = 20000; // constantly-updating analysis: re-pull on a slow heartbeat

// One-click export. Regenerates the deliverables server-side (same builder as
// `recce report`) and downloads the file. Excel is the primary action; the rest
// sit under the caret.
const EXPORTS: [string, string][] = [
  ["xlsx", "Excel workbook"], ["html", "HTML report"],
  ["docx", "Findings write-ups (Word)"],
  ["csv", "Services CSV"], ["md", "Markdown"],
];
function Export({ onError }: { onError: (m: string) => void }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  async function dl(kind: string) {
    setOpen(false); setBusy(kind);
    try {
      const r = await fetch(`/api/report/${kind}`);
      if (!r.ok) throw new Error(`${r.status}`);
      const blob = await r.blob();
      const cd = r.headers.get("content-disposition") || "";
      const name = /filename="?([^"]+)"?/.exec(cd)?.[1] || `recce.${kind}`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = name;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
    } catch {
      onError("export failed — is the engagement still loading?");
    } finally { setBusy(null); }
  }
  return (
    <div className="export">
      <button className="exp-main" onClick={() => dl("xlsx")} disabled={!!busy}
              title="download the Excel workbook">
        {busy ? "Exporting…" : "⭳ Excel"}
      </button>
      <button className="exp-caret" onClick={() => setOpen((v) => !v)} disabled={!!busy}
              aria-label="other formats">▾</button>
      {open && (
        <>
          <div className="exp-backdrop" onClick={() => setOpen(false)} />
          <div className="exp-menu">
            {EXPORTS.map(([k, label]) => (
              <button key={k} onClick={() => dl(k)}>{label}</button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

// Tools a teammate can drop output from. "auto" lets the server sniff the format.
const IMPORT_TOOLS: [string, string][] = [
  ["auto", "Auto-detect"],
  ["nmap", "nmap / masscan  (.xml / .gnmap / .nmap)"],
  ["nxc", "netexec / crackmapexec  (nxc smb)"],
  ["kerberoast", "impacket GetUserSPNs  (Kerberoast)"],
  ["asrep", "impacket GetNPUsers  (AS-REP)"],
  ["secretsdump", "impacket secretsdump  (NTLM hashes)"],
  ["creds", "Credential list  (user:password per line)"],
  ["loot", "recce on-target enum  (recce-enum.sh/.ps1)"],
  ["fieldkit", "fieldkit findings  (findings.json)"],
];

// Import panel: drop a file or paste output from any supported tool; the server
// folds it into the live engagement and every browser updates.
function ImportModal(
  { onClose, onJob, onDone }:
  { onClose: () => void; onJob: (id: string) => void; onDone: (msg: string) => void }
) {
  const [kind, setKind] = useState("auto");
  const [text, setText] = useState("");
  const [filename, setFilename] = useState("");
  const [busy, setBusy] = useState(false);
  const [drag, setDrag] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  function readFile(file: File) {
    const r = new FileReader();
    r.onload = () => { setText(String(r.result || "")); setFilename(file.name); };
    r.readAsText(file);
  }
  async function go() {
    if (!text.trim() || busy) return;
    setBusy(true); setErr(null);
    try {
      const res = await postImport(text, filename, kind);
      if (res.mode === "job") { onJob(res.id); onClose(); }
      else { onDone(res.summary || `imported ${res.added} item(s)`); onClose(); }
    } catch (e) { setErr(String(e instanceof Error ? e.message : e)); }
    finally { setBusy(false); }
  }
  return (
    <>
      <div className="modal-backdrop" onClick={onClose} />
      <div className="modal" role="dialog" aria-label="Import tool output">
        <div className="modal-h">
          <h3>Import tool output</h3>
          <button className="drawer-x" onClick={onClose} aria-label="close">✕</button>
        </div>
        <p className="modal-sub">
          Drop a file or paste output from any supported tool. recce folds it into this
          engagement and every open browser updates — no terminal needed.
        </p>
        <label className="imp-field">Tool
          <select value={kind} onChange={(e) => setKind(e.target.value)} disabled={busy}>
            {IMPORT_TOOLS.map(([k, label]) => <option key={k} value={k}>{label}</option>)}
          </select>
        </label>
        <div className={"dropzone" + (drag ? " over" : "")}
             onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
             onDragLeave={() => setDrag(false)}
             onDrop={(e) => { e.preventDefault(); setDrag(false); const f = e.dataTransfer.files[0]; if (f) readFile(f); }}>
          <span>⭱ Drop a file here, or </span>
          <label className="filepick">browse
            <input type="file" onChange={(e) => { const f = e.target.files?.[0]; if (f) readFile(f); }} hidden />
          </label>
          {filename && <span className="imp-fn">· {filename}</span>}
        </div>
        <textarea className="imp-paste" placeholder="…or paste the tool output here"
                  value={text} onChange={(e) => setText(e.target.value)} disabled={busy} />
        {err && <div className="ranmsg warn-msg">{err}</div>}
        <div className="modal-actions">
          <button className="toggle" onClick={onClose} disabled={busy}>Cancel</button>
          <button className="run" onClick={go} disabled={busy || !text.trim()}>
            {busy ? "Importing…" : "Import"}
          </button>
        </div>
      </div>
    </>
  );
}

export default function App() {
  const [ov, setOv] = useState<Overview | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [err, setErr] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("dashboard");

  // cross-tab filter state (lifted so the dashboard can drill into a filtered view)
  const [ff, setFf] = useState<FindingFilters>({ sev: "all", host: "", kev: false, unreviewed: false, leads: false, q: "" });
  const [hostQ, setHostQ] = useState(""); const [hostSev, setHostSev] = useState("all");
  const [tgQ, setTgQ] = useState(""); const [tgFilter, setTgFilter] = useState<TgFilter>("all");
  const [drawerIp, setDrawerIp] = useState<string | null>(null);

  // theme: light is the default; dark is opt-in (persisted).
  const [theme, setTheme] = useState(() => localStorage.getItem("recce.theme") || "light");
  useEffect(() => {
    document.documentElement.dataset.theme = theme === "dark" ? "dark" : "light";
    localStorage.setItem("recce.theme", theme);
  }, [theme]);

  // tester identity
  const [who, setWho] = useState(() => localStorage.getItem("recce.tester") || "");
  const [nameInput, setNameInput] = useState("");
  const tester = who || "someone";
  function saveTester(name: string) {
    const n = name.trim(); if (!n) return;
    localStorage.setItem("recce.tester", n); setWho(n);
  }

  // scan job state
  const [targets, setTargets] = useState("");
  const [profile, setProfile] = useState("quick");
  const [log, setLog] = useState<string[]>([]);
  const [running, setRunning] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  const [showImport, setShowImport] = useState(false);
  const [flash, setFlash] = useState<string | null>(null);
  const flashTimer = useRef<number | undefined>(undefined);
  const note = useCallback((msg: string) => {
    setFlash(msg);
    window.clearTimeout(flashTimer.current);
    flashTimer.current = window.setTimeout(() => setFlash(null), 4000);
  }, []);

  const refresh = useCallback(async () => {
    const [o, f, h] = await fetchAll();
    setOv(o); setFindings(f); setHosts(h);
  }, []);

  useEffect(() => { refresh().catch((e) => setErr(String(e))); }, [refresh]);
  useEffect(() => { logRef.current?.scrollTo(0, logRef.current.scrollHeight); }, [log]);

  // slow poll so the analysis keeps updating even without an explicit event
  useEffect(() => {
    const id = window.setInterval(() => { refresh().catch(() => {}); }, POLL_MS);
    return () => window.clearInterval(id);
  }, [refresh]);

  // live cross-user channel
  useEffect(() => {
    const es = new EventSource("/api/events");
    es.onmessage = (m) => {
      let d: any; try { d = JSON.parse(m.data); } catch { return; }
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
      }
    };
    return () => es.close();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tester]);

  // optimistic tick / note (server broadcast reconciles everyone)
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

  const nav: Nav = {
    toFindings: (o) => {
      setFf({ sev: "all", host: "", kev: false, unreviewed: false, leads: false, q: "", ...o });
      setTab("findings");
    },
    toHosts: (o) => { setHostQ(o?.q ?? ""); setHostSev(o?.sev ?? "all"); setTab("hosts"); },
    toTargets: () => setTab("targets"),
    toAct: () => setTab("act"),
    openHost: (ip) => setDrawerIp(ip),
  };

  // Stream a background job's output into the live console. Shared by scans and
  // file-backed imports (nmap / on-target loot) so both show the same progress.
  const streamJob = useCallback((id: string) => {
    setLog([]); setRunning(true);
    const es = new EventSource(`/api/jobs/${id}/events`);
    es.onmessage = (m) => {
      const d = JSON.parse(m.data);
      if (d.line !== undefined) setLog((l) => [...l, d.line]);
      if (d.done) { es.close(); setRunning(false); refresh().catch(() => {}); }
    };
    es.onerror = () => { es.close(); setRunning(false); };
  }, [refresh]);

  async function runScan() {
    if (!targets.trim() || running) return;
    try { const { id } = await postScan(targets, profile); streamJob(id); }
    catch (e) { setLog([`error: ${e}`]); }
  }

  if (err) return <div className="err">Could not reach the recce API: {err}</div>;
  if (!ov) return <div className="loading">Loading engagement…</div>;

  // Ordered to follow the operator's path: overview -> what's wrong -> what to DO ->
  // what we EXTRACTED -> host/target detail.
  const TABS: [Tab, string][] = [
    ["dashboard", "Dashboard"], ["findings", "Findings"], ["act", "Act"],
    ["loot", "Credentials"], ["hosts", "Hosts"], ["targets", "Targets"],
  ];

  return (
    <div className="app">
      <header className="top">
        <span className="brand"><span className="dot" />recce <small>{ov.name}</small></span>
        <nav className="tabs main-tabs">
          {TABS.map(([t, label]) => (
            <button key={t} className={"tab" + (tab === t ? " sel" : "")} onClick={() => setTab(t)}>{label}</button>
          ))}
        </nav>
        <button className="theme-tog" onClick={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}
                title="toggle light / dark" aria-label="toggle theme">
          {theme === "dark" ? "☀" : "☾"}
        </button>
        {who ? (
          <button className="whoami" onClick={() => setWho("")} title="click to change">{tester}</button>
        ) : (
          <form className="namegate" onSubmit={(e) => { e.preventDefault(); saveTester(nameInput); }}>
            <input placeholder="your name…" value={nameInput} onChange={(e) => setNameInput(e.target.value)} autoFocus />
            <button type="submit" disabled={!nameInput.trim()}>Set</button>
          </form>
        )}
      </header>

      {flash && <div className="flash">{flash}</div>}

      <main>
        <section className="scanbar">
          <input className="scan-in" placeholder="targets to scan — 10.0.0.0/24, host.corp.local …"
                 value={targets} onChange={(e) => setTargets(e.target.value)}
                 onKeyDown={(e) => e.key === "Enter" && runScan()} disabled={running} />
          <select value={profile} onChange={(e) => setProfile(e.target.value)} disabled={running}>
            <option value="quick">quick</option><option value="standard">standard</option><option value="thorough">thorough</option>
          </select>
          <button className="run" onClick={runScan} disabled={running || !targets.trim()}>
            {running ? "Scanning…" : "Run scan"}
          </button>
          <button className="import-btn" onClick={() => setShowImport(true)}
                  title="import output from nmap / netexec / impacket / on-target loot">
            ⭱ Import
          </button>
          <Export onError={(m) => note(m)} />
        </section>

        {(running || log.length > 0) && (
          <div className="console" ref={logRef}>
            {log.map((l, i) => <div key={i} className="ln">{l}</div>)}
            {running && <div className="ln cursor">▋</div>}
          </div>
        )}

        {tab === "dashboard" && <Dashboard ov={ov} nav={nav} />}
        {tab === "findings" && (
          <Findings findings={findings} f={ff} setF={(o) => setFf((p) => ({ ...p, ...o }))}
                    nav={nav} onTick={onTick} onNote={onNote} />
        )}
        {tab === "act" && <Act nav={nav} />}
        {tab === "loot" && <Loot />}
        {tab === "hosts" && (
          <Hosts hosts={hosts} q={hostQ} sev={hostSev} setQ={setHostQ} setSev={setHostSev}
                 nav={nav} onTick={onTick} onNote={onNote} />
        )}
        {tab === "targets" && (
          <Targets hosts={hosts} ov={ov} q={tgQ} filter={tgFilter} setQ={setTgQ} setFilter={setTgFilter}
                   nav={nav} onTick={onTick} onNote={onNote} />
        )}
      </main>

      {showImport && (
        <ImportModal
          onClose={() => setShowImport(false)}
          onJob={(id) => streamJob(id)}
          onDone={(msg) => { note(msg); refresh().catch(() => {}); }}
        />
      )}

      <HostDrawer ip={drawerIp} onClose={() => setDrawerIp(null)} onTick={onTick} onNote={onNote} />
    </div>
  );
}
