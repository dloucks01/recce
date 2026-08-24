import { useState } from "react";
import { postImport } from "../api";
import { useEscape } from "../ui";

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
          Drop a file or paste output from any supported tool. recce folds it into this engagement and every open
          browser updates — no terminal needed.
        </p>
        <label className="imp-field">
          Tool
          <select value={kind} onChange={(e) => { setKind(e.target.value); setPrev(null); }} disabled={busy}>
            {IMPORT_TOOLS.map(([k, label]) => (
              <option key={k} value={k}>{label}</option>
            ))}
          </select>
        </label>
        <div className={"dropzone" + (drag ? " over" : "")}
             onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
             onDragLeave={() => setDrag(false)}
             onDrop={(e) => {
               e.preventDefault(); setDrag(false);
               const f = e.dataTransfer.files[0];
               if (f) readFile(f);
             }}>
          <span>⭱ Drop a file here, or </span>
          <label className="filepick">
            browse
            <input type="file" onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) readFile(f);
            }} hidden />
          </label>
          {filename && <span className="imp-fn">· {filename}</span>}
        </div>
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
          <button className="toggle" onClick={doPreview} disabled={busy || !text.trim()}>Preview</button>
          <button className="run" onClick={go} disabled={busy || !text.trim()}>
            {busy ? "Importing…" : "Import"}
          </button>
        </div>
      </div>
    </>
  );
}
