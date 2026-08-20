import { useCallback, useEffect, useRef, useState } from "react";
import {
  Finding, Host, Overview, fetchAll, postTick, postNote, postScan, postImport,
  fetchPlaybook, Playbook as PlaybookData,
} from "./api";
import { Dashboard, Findings, Hosts, Act, Loot, Playbook, Nav, FindingFilters } from "./views";
import { HostDrawer } from "./HostDrawer";
import { PresenceBar, ActivityButton, ChatButton, AddMenu, MyQueue, useCollab } from "./collab";
import { useEscape } from "./ui";

type Tab = "dashboard" | "playbook" | "hosts" | "findings" | "act" | "loot";
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

// SharpHound collections are binary zips — read them as base64 so they survive JSON.
const isBinaryFile = (name: string) => /\.zip$/i.test(name);

// Import panel: drop a file or paste output from any supported tool; the server
// folds it into the live engagement and every browser updates.
function ImportModal(
  { onClose, onJob, onDone }:
  { onClose: () => void; onJob: (id: string) => void; onDone: (msg: string) => void }
) {
  const [kind, setKind] = useState("auto");
  const [text, setText] = useState("");
  const [filename, setFilename] = useState("");
  const [encoding, setEncoding] = useState("");   // "base64" for binary (zip) uploads
  const [busy, setBusy] = useState(false);
  const [drag, setDrag] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [prev, setPrev] = useState<
    { kind: string; count: number; detail: string; sample: string[]; warning: string } | null>(null);
  useEscape(onClose, !busy);

  function readFile(file: File) {
    const r = new FileReader();
    setFilename(file.name); setPrev(null); setErr(null);
    // Always read as base64 so a UTF-16 (the default of a Windows PowerShell redirect),
    // BOM'd, or binary file reaches the server intact; the server decodes with detection.
    r.onload = () => {
      const url = String(r.result || "");
      setText(url.slice(url.indexOf(",") + 1));   // strip the data: URL prefix -> base64
      setEncoding("base64");
    };
    r.readAsDataURL(file);
    if (isBinaryFile(file.name) && kind === "auto") setKind("bloodhound");
  }
  async function doPreview() {
    if (!text.trim() || busy) return;
    setBusy(true); setErr(null); setPrev(null);
    try {
      const res = await postImport(text, filename, kind, encoding, true);
      if (res.mode === "preview") setPrev(res);
    } catch (e) { setErr(String(e instanceof Error ? e.message : e)); }
    finally { setBusy(false); }
  }
  async function go() {
    if (!text.trim() || busy) return;
    setBusy(true); setErr(null);
    try {
      const res = await postImport(text, filename, kind, encoding);
      if (res.mode === "job") { onJob(res.id); onClose(); }
      else if (res.mode === "done") { onDone(res.summary || `imported ${res.added} item(s)`); onClose(); }
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
          <select value={kind} onChange={(e) => { setKind(e.target.value); setPrev(null); }} disabled={busy}>
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
                  value={text} onChange={(e) => { setText(e.target.value); setEncoding(""); setPrev(null); }}
                  disabled={busy} />
        {prev && (
          <div className={"imp-preview" + (prev.warning ? " warn" : "")}>
            <div><b>{prev.kind}</b>{prev.detail ? ` · ${prev.detail}` : ` · ${prev.count} item(s)`}</div>
            {prev.sample?.length > 0 && (
              <ul>{prev.sample.map((s, i) => <li key={i}>{s}</li>)}</ul>
            )}
            {prev.warning && <div className="warn-msg">{prev.warning}</div>}
          </div>
        )}
        {err && <div className="ranmsg warn-msg">{err}</div>}
        <div className="modal-actions">
          <button className="toggle" onClick={onClose} disabled={busy}>Cancel</button>
          <button className="toggle" onClick={doPreview} disabled={busy || !text.trim()}>Preview</button>
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
  const [pb, setPb] = useState<PlaybookData | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("dashboard");

  // cross-tab filter state (lifted so the dashboard can drill into a filtered view)
  const [ff, setFf] = useState<FindingFilters>({ sev: "all", host: "", kev: false, unreviewed: false, leads: false, q: "" });
  const [hostQ, setHostQ] = useState(""); const [hostCov, setHostCov] = useState("all");
  const [hostWho, setHostWho] = useState("all");   // all | unclaimed | queue | tester name
  const [drawerIp, setDrawerIp] = useState<string | null>(null);

  // theme: light is the default; dark is opt-in (persisted).
  const [theme, setTheme] = useState(() => localStorage.getItem("recce.theme") || "light");
  useEffect(() => {
    document.documentElement.dataset.theme = theme === "dark" ? "dark" : "light";
    localStorage.setItem("recce.theme", theme);
  }, [theme]);

  // row density: comfortable (default) or compact, for scanning large host lists
  const [density, setDensity] = useState(() => localStorage.getItem("recce.density") || "comfortable");
  useEffect(() => {
    document.documentElement.dataset.density = density;
    localStorage.setItem("recce.density", density);
  }, [density]);

  // "/" focuses the current view's search box (unless you're already typing)
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName || "";
      if (e.key === "/" && !/^(INPUT|TEXTAREA|SELECT)$/.test(tag)) {
        const s = document.querySelector<HTMLInputElement>(".search");
        if (s) { e.preventDefault(); s.focus(); }
      }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);

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
  const [scanOpen, setScanOpen] = useState(false);
  useEscape(() => setScanOpen(false), scanOpen);
  const [flash, setFlash] = useState<string | null>(null);
  const flashTimer = useRef<number | undefined>(undefined);
  const note = useCallback((msg: string) => {
    setFlash(msg);
    window.clearTimeout(flashTimer.current);
    flashTimer.current = window.setTimeout(() => setFlash(null), 4000);
  }, []);

  const collab = useCollab();
  const refresh = useCallback(async () => {
    const [o, f, h] = await fetchAll();
    setOv(o); setFindings(f); setHosts(h);
    fetchPlaybook().then(setPb).catch(() => {});
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
    toHosts: (o) => { setHostQ(o?.q ?? ""); setHostWho(o?.owner ?? "all"); setHostCov("all"); setTab("hosts"); },
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

  if (err) return (
    <div className="boot">
      <div className="boot-brand"><span className="dot" />recce</div>
      <div className="boot-err">Could not reach the recce API</div>
      <div className="boot-msg">{err}</div>
    </div>
  );
  if (!ov) return (
    <div className="boot">
      <div className="boot-brand"><span className="dot" />recce</div>
      <div className="boot-bar"><span /></div>
      <div className="boot-msg">Loading engagement…</div>
    </div>
  );

  // Ordered to follow the operator's path: overview -> what's wrong -> what to DO ->
  // Ordered to narrow the operator's focus: overview -> inventory -> what's wrong ->
  // what to DO -> what we EXTRACTED.
  const TABS: [Tab, string][] = [
    ["dashboard", "Dashboard"], ["playbook", "Playbook"], ["hosts", "Hosts"], ["findings", "Findings"],
    ["act", "Act"], ["loot", "Credentials"],
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
        {pb?.next && (
          <button className="nextchip" onClick={() => setTab("playbook")}
                  title={`${pb.next.label}${pb.next.cmd ? ` — ${pb.next.cmd}` : ""}`}>
            <span className="nc-lab">▶ next</span>
            <span className="nc-txt">{pb.next.label}</span>
          </button>
        )}
        <MyQueue hosts={hosts} onOpen={() => nav.toHosts({ owner: "queue" })} />
        <PresenceBar onPick={(name) => nav.toHosts({ owner: name })} />
        <ChatButton />
        <ActivityButton onOpenHost={(ip) => nav.openHost(ip)} />
        <button className="theme-tog" onClick={() => setDensity((d) => (d === "compact" ? "comfortable" : "compact"))}
                title={density === "compact" ? "comfortable rows" : "compact rows"} aria-label="toggle density">
          {density === "compact" ? "☰" : "≡"}
        </button>
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
        <section className="actionbar">
          <div className="scanctl">
            <button className={"btn scanbtn" + (running ? " busy" : "")}
                    onClick={() => (running ? undefined : setScanOpen((v) => !v))} disabled={running}
                    title="run enum / vulns / full scan">
              {running ? "Scanning…" : "▶ Scan"}
            </button>
            {scanOpen && !running && (
              <>
                <div className="exp-backdrop" onClick={() => setScanOpen(false)} />
                <div className="scanpop">
                  <input className="scan-in" autoFocus placeholder="targets — 10.0.0.0/24, host.corp.local …"
                         value={targets} onChange={(e) => setTargets(e.target.value)}
                         onKeyDown={(e) => { if (e.key === "Enter" && targets.trim()) { runScan(); setScanOpen(false); } }} />
                  <div className="scanpop-row">
                    <select value={profile} onChange={(e) => setProfile(e.target.value)}>
                      <option value="quick">quick</option><option value="standard">standard</option><option value="thorough">thorough</option>
                    </select>
                    <button className="btn primary" onClick={() => { runScan(); setScanOpen(false); }} disabled={!targets.trim()}>Run</button>
                  </div>
                </div>
              </>
            )}
          </div>
          <button className="btn" onClick={() => setShowImport(true)}
                  title="import output from nmap / netexec / impacket / on-target loot">⭱ Import</button>
          <AddMenu onDone={(m) => note(m)} />
          <Export onError={(m) => note(m)} />
        </section>

        {(running || log.length > 0) && (
          <div className="console" ref={logRef}>
            {log.map((l, i) => <div key={i} className="ln">{l}</div>)}
            {running && <div className="ln cursor">▋</div>}
          </div>
        )}

        {tab === "dashboard" && <Dashboard ov={ov} hosts={hosts} nav={nav} />}
        {tab === "playbook" && <Playbook pb={pb} nav={nav} />}
        {tab === "findings" && (
          <Findings findings={findings} f={ff} setF={(o) => setFf((p) => ({ ...p, ...o }))}
                    nav={nav} onTick={onTick} onNote={onNote} />
        )}
        {tab === "act" && <Act nav={nav} />}
        {tab === "loot" && <Loot />}
        {tab === "hosts" && (
          <Hosts hosts={hosts} ov={ov} q={hostQ} who={hostWho} cov={hostCov}
                 setQ={setHostQ} setWho={setHostWho} setCov={setHostCov}
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
