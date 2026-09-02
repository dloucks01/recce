import { useEffect, useRef, useState } from "react";
import { postVerify, postFieldkitExport, postBackup } from "./api";
import { toast } from "./toast";

/**
 * Tools menu — a single header button ("🧰 Tools") that opens a dropdown
 * of tool actions. Kept centralized so tools stay legible on narrow
 * viewports and one menu holds the full IT-parity surface (import,
 * encoder, doctor, verify, scope editor, fieldkit ZIP, backup ZIP).
 *
 * Callers pass the modal-open callbacks; the file-download and vulndb-
 * refresh actions run inline (they don't have a modal — the toast is the
 * feedback).
 */
export function ToolsMenu(
  { onImport, onEncDec, onDoctor, onScope }:
  { onImport: () => void; onEncDec: () => void; onDoctor: () => void; onScope: () => void; }
) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<string>("");
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function close(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    function esc(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", esc);
    };
  }, [open]);

  const download = async (kind: "fieldkit" | "backup") => {
    setBusy(kind);
    try {
      const blob = kind === "fieldkit"
        ? await postFieldkitExport()
        : await postBackup();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      // The backend picks the filename; use a sensible fallback since the
      // Content-Disposition parsing would double the code weight here.
      const name = kind === "fieldkit"
        ? `recce-fieldkit-${new Date().toISOString().slice(0, 10)}.zip`
        : `recce-backup-${new Date().toISOString().slice(0, 10)}.zip`;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast.show(`${kind === "fieldkit" ? "Field kit" : "Engagement backup"} downloaded`);
    } catch (e) {
      toast.show(`Failed: ${(e as Error).message}`);
    } finally {
      setBusy("");
      setOpen(false);
    }
  };

  const verify = async () => {
    setBusy("verify");
    try {
      await postVerify();
      toast.show("Vuln-DB refresh kicked off (job runs in the background)");
    } catch (e) {
      toast.show(`Verify failed: ${(e as Error).message}`);
    } finally {
      setBusy("");
      setOpen(false);
    }
  };

  return (
    <div className="tools-menu" ref={ref}>
      <button
        className="hdr-btn tools-btn"
        onClick={() => setOpen((v) => !v)}
        title="Tools (Alt+T)"
        aria-haspopup="menu"
        aria-expanded={open}
      >
        🧰 <span className="tools-label">Tools</span>
        <span className="tools-caret">▾</span>
      </button>
      {open && (
        <div className="tools-popup" role="menu">
          <button
            className="tools-item"
            onClick={() => { setOpen(false); onImport(); }}
            role="menuitem"
          >
            <span className="tools-item-ico">📥</span>
            <span className="tools-item-body">
              <span className="tools-item-name">Import tool output</span>
              <span className="tools-item-desc">Paste or drop nmap / nxc / nuclei / … output</span>
            </span>
            <kbd className="tools-item-key">Alt+I</kbd>
          </button>
          <button
            className="tools-item"
            onClick={() => { setOpen(false); onEncDec(); }}
            role="menuitem"
          >
            <span className="tools-item-ico">🔀</span>
            <span className="tools-item-body">
              <span className="tools-item-name">Encoder / Decoder</span>
              <span className="tools-item-desc">base64, JWT, hex, hash, gzip, URL, JSON, XOR… (41 ops)</span>
            </span>
          </button>
          <div className="tools-divider" />
          <button
            className="tools-item"
            onClick={() => { setOpen(false); onDoctor(); }}
            role="menuitem"
          >
            <span className="tools-item-ico">🩺</span>
            <span className="tools-item-body">
              <span className="tools-item-name">Engagement doctor</span>
              <span className="tools-item-desc">Audit for missing scans, stale data, skipped phases</span>
            </span>
          </button>
          <button
            className="tools-item"
            onClick={() => { setOpen(false); onScope(); }}
            role="menuitem"
          >
            <span className="tools-item-ico">🎯</span>
            <span className="tools-item-body">
              <span className="tools-item-name">Scope editor</span>
              <span className="tools-item-desc">Add / remove in-scope subnets mid-engagement</span>
            </span>
          </button>
          <button
            className="tools-item"
            onClick={verify}
            disabled={!!busy}
            role="menuitem"
          >
            <span className="tools-item-ico">🔄</span>
            <span className="tools-item-body">
              <span className="tools-item-name">
                {busy === "verify" ? "Verifying…" : "Refresh vuln-DB"}
              </span>
              <span className="tools-item-desc">Re-run CVE + version checks against every finding</span>
            </span>
          </button>
          <div className="tools-divider" />
          <button
            className="tools-item"
            onClick={() => download("fieldkit")}
            disabled={!!busy}
            role="menuitem"
          >
            <span className="tools-item-ico">📦</span>
            <span className="tools-item-body">
              <span className="tools-item-name">
                {busy === "fieldkit" ? "Building ZIP…" : "Export field kit (.zip)"}
              </span>
              <span className="tools-item-desc">Airgap take-away: scans + findings + commands</span>
            </span>
          </button>
          <button
            className="tools-item"
            onClick={() => download("backup")}
            disabled={!!busy}
            role="menuitem"
          >
            <span className="tools-item-ico">💾</span>
            <span className="tools-item-body">
              <span className="tools-item-name">
                {busy === "backup" ? "Building ZIP…" : "Backup engagement (.zip)"}
              </span>
              <span className="tools-item-desc">Full engagement snapshot: sqlite + raw + report</span>
            </span>
          </button>
        </div>
      )}
    </div>
  );
}
