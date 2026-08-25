import { useEffect, useState } from "react";
import { postImport, uploadEvidence, getJSON, Host,
         ParserSpec, ParserTestResult,
         testUserParser, saveUserParser, draftParserWithLLM } from "../api";
import { useEscape } from "../ui";

// Tool catalog is grouped by category so the dropdown reads like a menu of
// what recce can eat, not an alphabet soup. Auto-detect stays first — 95% of
// imports go through it. Each new IP1/2/3 tool lives under its category.
const IMPORT_TOOLS: Array<[string, string]> = [
  ["auto", "Auto-detect"],
  // — general scanners —
  ["nmap", "nmap / masscan  (.xml / .gnmap / .nmap)"],
  ["nessus", "Nessus  (.nessus export)"],
  ["openvas", "OpenVAS / Greenbone  (GVM XML)"],
  ["nuclei", "nuclei  (JSON / JSONL)"],
  // — web scanners (IP1 + existing) —
  ["burp", "Burp Suite  (Issues XML)"],
  ["zap", "OWASP ZAP  (XML)"],
  ["nikto", "Nikto  (XML: nikto -Format xml)"],
  ["wpscan", "WPScan  (JSON: wpscan --format json)"],
  ["whatweb", "WhatWeb  (JSON log)"],
  ["wafw00f", "wafw00f  (text)"],
  ["testssl", "testssl.sh  (JSON)"],
  ["sslyze", "sslyze  (JSON: sslyze --json_out)"],
  // — content discovery (IP3) —
  ["ffuf", "ffuf  (JSON: ffuf -o out.json)"],
  ["gobuster", "gobuster  (JSON / text)"],
  // — AD + SMB (IP1/IP2 + existing) —
  ["enum4linux", "enum4linux(-ng)  (text or --json)"],
  ["kerbrute", "kerbrute userenum  (text)"],
  ["nxc", "netexec / crackmapexec  (smb / ldap / mssql / winrm)"],
  ["kerberoast", "impacket GetUserSPNs  (Kerberoast)"],
  ["asrep", "impacket GetNPUsers  (AS-REP)"],
  ["secretsdump", "impacket secretsdump  (NTLM hashes)"],
  ["impacket-adusers", "impacket GetADUsers  (user directory dump)"],
  ["impacket-delegation", "impacket findDelegation  (constrained/unconstrained)"],
  ["bloodhound", "BloodHound / Certipy  (.zip / certipy .json)"],
  // — container / SBOM (IP3) —
  ["trivy", "Trivy  (JSON: trivy -f json)"],
  ["grype", "Grype  (JSON: grype -o json)"],
  // — misc + creds —
  ["creds", "Credential list  (user:password per line)"],
  ["loot", "recce on-target enum  (recce-enum.sh/.ps1)"],
  ["fieldkit", "fieldkit findings  (findings.json)"],
];

const isBinaryFile = (name: string) => /\.zip$/i.test(name);

// Skeleton the Build-parser textarea starts with — a working example the
// tester can adapt rather than staring at an empty form.
function _defaultParserJson(): string {
  const skel = {
    name: "my-parser",
    description: "one-line what this parser is for",
    detect: {
      filename_glob: "*.mytool",
      content_substr: "my-tool"
    },
    match: {
      target_re: "^Host:\\s+(?P<target>\\S+)",
      port_default: 80
    },
    findings: [
      { marker_re: "^\\[CRIT\\]\\s+(?P<title>.+?)(?:\\s+at\\s+(?P<port>\\d+))?$",
        severity: "critical" },
      { marker_re: "^\\[HIGH\\]\\s+(?P<title>.+)$",
        severity: "high" }
    ]
  };
  return JSON.stringify(skel, null, 2);
}

// Queue entry for the multi-file drop workflow. Each file is imported
// separately (each format has its own parser); the queue drives sequential
// upload with a per-item outcome ledger the tester can see.
type QueueEntry = {
  file: File;
  status: "queued" | "uploading" | "done" | "error";
  outcome?: string;   // "12 findings folded" / error text
};

export function ImportModal(
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
  // Multi-file drop queue — populated by dropping >1 file, or by "Add more"
  const [queue, setQueue] = useState<QueueEntry[]>([]);
  // Attach-as-evidence mode — the escape hatch for unparseable files.
  // Build-parser mode — declarative parser authoring (Phase 3).
  const [mode, setMode] = useState<"parse" | "evidence" | "build">("parse");
  const [evHost, setEvHost] = useState("");
  const [evNote, setEvNote] = useState("");
  const [hosts, setHosts] = useState<Host[]>([]);
  // Parser-builder state (P3). Kept minimal: raw JSON textarea + a "Test"
  // button that dry-runs against the paste sample.
  const [pbJson, setPbJson] = useState<string>(_defaultParserJson());
  const [pbTestResult, setPbTestResult] = useState<ParserTestResult | null>(null);
  const [pbLlmBusy, setPbLlmBusy] = useState(false);
  const [pbLlmHint, setPbLlmHint] = useState("");
  useEffect(() => {
    if (mode === "evidence" && hosts.length === 0) {
      getJSON<{ items: Host[] }>("/api/hosts?limit=500")
        .then(r => setHosts(r.items || [])).catch(() => {});
    }
  }, [mode, hosts.length]);
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

  // Read a File and return its (base64 payload, encoding) pair — used by the
  // queue path where we don't touch the paste textarea.
  function readFileAsBase64(file: File): Promise<string> {
    return new Promise((resolve, reject) => {
      const r = new FileReader();
      r.onload = () => {
        const url = String(r.result || "");
        resolve(url.slice(url.indexOf(",") + 1));
      };
      r.onerror = () => reject(r.error);
      r.readAsDataURL(file);
    });
  }

  async function runQueue() {
    if (busy || queue.length === 0) return;
    setBusy(true); setErr(null);
    let done = 0, failed = 0;
    for (let i = 0; i < queue.length; i++) {
      // mutate progressively so the UI reflects live state
      setQueue(q => q.map((e, idx) => idx === i ? { ...e, status: "uploading" } : e));
      try {
        const data = await readFileAsBase64(queue[i].file);
        const res = await postImport(data, queue[i].file.name, "auto", "base64");
        if (res.mode === "job") {
          setQueue(q => q.map((e, idx) => idx === i ? { ...e, status: "done", outcome: `queued as job ${res.id}` } : e));
        } else if (res.mode === "done") {
          setQueue(q => q.map((e, idx) => idx === i ? { ...e, status: "done", outcome: res.summary || `+${res.added}` } : e));
        } else {
          setQueue(q => q.map((e, idx) => idx === i ? { ...e, status: "done", outcome: `${res.count} preview` } : e));
        }
        done++;
      } catch (e) {
        setQueue(q => q.map((e2, idx) => idx === i ? { ...e2, status: "error", outcome: String(e instanceof Error ? e.message : e) } : e2));
        failed++;
      }
    }
    setBusy(false);
    onDone(`Multi-import: ${done} succeeded, ${failed} failed`);
    // Leave the queue visible so the tester can see the results; close on manual dismiss
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

  // ---- Build-parser (Phase 3) handlers -----------------------------------

  function _parsePbJson(): { spec: ParserSpec | null; err: string | null } {
    try { return { spec: JSON.parse(pbJson) as ParserSpec, err: null }; }
    catch (e) { return { spec: null, err: String(e instanceof Error ? e.message : e) }; }
  }

  async function pbTest() {
    setPbTestResult(null); setErr(null);
    const { spec, err: parseErr } = _parsePbJson();
    if (!spec) { setErr(`JSON: ${parseErr}`); return; }
    setBusy(true);
    try {
      const r = await testUserParser(spec, text || "");
      setPbTestResult(r);
    } catch (e) { setErr(String(e instanceof Error ? e.message : e)); }
    finally { setBusy(false); }
  }

  async function pbSave() {
    setErr(null);
    const { spec, err: parseErr } = _parsePbJson();
    if (!spec) { setErr(`JSON: ${parseErr}`); return; }
    setBusy(true);
    try {
      const r = await saveUserParser(spec);
      onDone(`Parser saved: ${r.name} → ${r.path}`);
      onClose();
    } catch (e) { setErr(String(e instanceof Error ? e.message : e)); }
    finally { setBusy(false); }
  }

  async function pbLlmDraft() {
    if (!text.trim()) { setErr("Paste some tool output first — the LLM drafts from a sample"); return; }
    setPbLlmBusy(true); setErr(null);
    try {
      const spec = await draftParserWithLLM(text, pbLlmHint);
      setPbJson(JSON.stringify(spec, null, 2));
      setPbTestResult(null);
    } catch (e) { setErr(String(e instanceof Error ? e.message : e)); }
    finally { setPbLlmBusy(false); }
  }

  async function attachEvidence() {
    if (!text || !filename || !evHost.trim() || busy) return;
    setBusy(true); setErr(null);
    try {
      // The dropzone already gave us base64 in `text` (encoding='base64').
      // If the user pasted plain text into the textarea, encode it.
      const b64 = encoding === "base64" ? text : btoa(text);
      const r = await uploadEvidence(evHost.trim(), filename, b64, evNote);
      onDone(`Attached evidence: ${r.path} (${r.bytes}B)`);
      onClose();
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
          Drop a file or paste output from any supported tool. recce folds it into this engagement and every open
          browser updates — no terminal needed.
        </p>
        <div className="imp-mode-tabs">
          <button className={"imp-mode-tab" + (mode === "parse" ? " sel" : "")}
                  onClick={() => setMode("parse")} disabled={busy}>
            Parse into findings
          </button>
          <button className={"imp-mode-tab" + (mode === "evidence" ? " sel" : "")}
                  onClick={() => setMode("evidence")} disabled={busy}>
            Attach as evidence
          </button>
          <button className={"imp-mode-tab" + (mode === "build" ? " sel" : "")}
                  onClick={() => setMode("build")} disabled={busy}
                  title="Add a custom-tool parser without touching Python">
            Build parser
          </button>
        </div>
        {mode === "parse" && (
          <label className="imp-field">
            Tool
            <select value={kind} onChange={(e) => { setKind(e.target.value); setPrev(null); }} disabled={busy}>
              {IMPORT_TOOLS.map(([k, label]) => (
                <option key={k} value={k}>{label}</option>
              ))}
            </select>
          </label>
        )}
        {mode === "build" && (
          <>
            <p className="modal-sub">
              Author a parser without touching Python. Paste your tool's output in the box below
              (used as the test sample), edit the JSON spec, hit <b>Test</b> to see what would
              extract, then <b>Save</b> to persist it to <code>{"<engagement>/parsers/<name>.json"}</code>.
              If Ollama is running (or <code>RECCE_LLM_URL</code> is set), <b>Draft with LLM</b>
              builds the JSON from your sample.
            </p>
            <label className="imp-field">
              Parser JSON
              <textarea className="imp-paste" style={{minHeight: 200, fontFamily: "var(--mono)"}}
                        value={pbJson} onChange={e => { setPbJson(e.target.value); setPbTestResult(null); }}
                        disabled={busy || pbLlmBusy} />
            </label>
            <label className="imp-field">
              LLM hint (optional)
              <input value={pbLlmHint} onChange={e => setPbLlmHint(e.target.value)}
                     placeholder="'this is nikto -o out.xml' — one sentence for the model"
                     disabled={busy || pbLlmBusy} />
            </label>
            {pbTestResult && (
              <div className={"imp-preview" + (pbTestResult.ok ? "" : " warn")}>
                <div>
                  <b>Test:</b>{" "}
                  {pbTestResult.ok
                    ? `${pbTestResult.count} finding(s) would extract`
                    : `error — ${pbTestResult.error}`}
                </div>
                {pbTestResult.sample?.length > 0 && (
                  <ul>{pbTestResult.sample.map((s, i) => (
                    <li key={i}>[{s.severity}] {s.title} @ {s.ip}{s.port ? ":" + s.port : ""}</li>
                  ))}</ul>
                )}
              </div>
            )}
          </>
        )}

        {mode === "evidence" && (
          <>
            <label className="imp-field">
              Host
              <select value={evHost} onChange={(e) => setEvHost(e.target.value)} disabled={busy}>
                <option value="">— pick a host —</option>
                {hosts.map(h => (
                  <option key={h.ip} value={h.ip}>
                    {h.ip}{h.hostname ? ` (${h.hostname})` : ""}{h.os ? ` · ${h.os.slice(0, 30)}` : ""}
                  </option>
                ))}
              </select>
            </label>
            <label className="imp-field">
              Note (optional)
              <input value={evNote} onChange={(e) => setEvNote(e.target.value)} disabled={busy}
                     placeholder="what's in this file? which finding does it evidence?" />
            </label>
            <p className="muted small" style={{marginTop:0}}>
              Escape hatch for files that can't be parsed — screenshots, PDFs, packet captures,
              vendor reports, proprietary formats. Saved to <code>{"<engagement>/evidence/<host>/"}</code>
              and a "Manual evidence" finding lands on the host so it shows up in Findings + Report.
            </p>
          </>
        )}
        <div className={"dropzone" + (drag ? " over" : "")}
             onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
             onDragLeave={() => setDrag(false)}
             onDrop={(e) => {
               e.preventDefault(); setDrag(false);
               const files = Array.from(e.dataTransfer.files);
               if (files.length === 1) {
                 // single file — populate the paste box + preview flow (unchanged)
                 readFile(files[0]);
               } else if (files.length > 1) {
                 // multi-file — queue them all, run through auto-detect each
                 setQueue(q => [...q, ...files.map(f => ({ file: f, status: "queued" as const }))]);
                 setFilename("");
                 setText("");
                 setPrev(null);
               }
             }}>
          <span>⭱ Drop a file here (or several), or </span>
          <label className="filepick">
            browse
            <input type="file" multiple onChange={(e) => {
              const files = Array.from(e.target.files || []);
              if (files.length === 1) readFile(files[0]);
              else if (files.length > 1) {
                setQueue(q => [...q, ...files.map(f => ({ file: f, status: "queued" as const }))]);
              }
            }} hidden />
          </label>
          {filename && <span className="imp-fn">· {filename}</span>}
        </div>

        {queue.length > 0 && (
          <div className="imp-queue">
            <div className="imp-queue-h">
              <span>Multi-file queue · {queue.length} file(s)</span>
              <button className="linkish" onClick={() => setQueue([])} disabled={busy}>clear</button>
            </div>
            <ul>
              {queue.map((e, i) => (
                <li key={i} className={`imp-queue-item status-${e.status}`}>
                  <span className="imp-queue-icon">
                    {e.status === "queued" ? "○" : e.status === "uploading" ? "…" :
                     e.status === "done" ? "✓" : "✗"}
                  </span>
                  <span className="imp-queue-name">{e.file.name}</span>
                  <span className="imp-queue-outcome">{e.outcome || ""}</span>
                </li>
              ))}
            </ul>
            <button className="run" onClick={runQueue} disabled={busy || queue.every(e => e.status !== "queued")}>
              {busy ? "Importing…" : `▶ Import all (${queue.filter(e => e.status === "queued").length} queued)`}
            </button>
          </div>
        )}
        <textarea className="imp-paste" placeholder="…or paste the tool output here"
                  value={text}
                  onChange={(e) => { setText(e.target.value); setEncoding(""); setPrev(null); }}
                  disabled={busy} />
        {prev && (
          <div className={"imp-preview" + (prev.warning ? " warn" : "")}>
            <div><b>{prev.kind}</b>{prev.detail ? ` · ${prev.detail}` : ` · ${prev.count} item(s)`}</div>
            {prev.sample?.length > 0 && <ul>{prev.sample.map((s, i) => <li key={i}>{s}</li>)}</ul>}
            {prev.warning && <div className="warn-msg">{prev.warning}</div>}
          </div>
        )}
        {err && <div className="ranmsg warn-msg">{err}</div>}
        <div className="modal-actions">
          <button className="toggle" onClick={onClose} disabled={busy}>Cancel</button>
          {mode === "parse" && (
            <>
              <button className="toggle" onClick={doPreview} disabled={busy || !text.trim()}>Preview</button>
              <button className="run" onClick={go} disabled={busy || !text.trim()}>
                {busy ? "Importing…" : "Import"}
              </button>
            </>
          )}
          {mode === "evidence" && (
            <button className="run" onClick={attachEvidence}
                    disabled={busy || !text || !filename || !evHost.trim()}>
              {busy ? "Attaching…" : "▶ Attach to host"}
            </button>
          )}
          {mode === "build" && (
            <>
              <button className="toggle" onClick={pbLlmDraft}
                      disabled={busy || pbLlmBusy || !text.trim()}
                      title="Ask a local LLM (Ollama by default) to draft this spec from the pasted sample">
                {pbLlmBusy ? "Drafting…" : "✨ Draft with LLM"}
              </button>
              <button className="toggle" onClick={pbTest} disabled={busy || pbLlmBusy || !pbJson.trim()}>
                Test
              </button>
              <button className="run" onClick={pbSave} disabled={busy || pbLlmBusy || !pbJson.trim()}>
                {busy ? "Saving…" : "▶ Save parser"}
              </button>
            </>
          )}
        </div>
      </div>
    </>
  );
}
