import { useEffect, useRef, useState } from "react";

/**
 * Tools menu — a single header button ("🧰 Tools") that opens a dropdown
 * of tool actions (Import tool output, Encoder/Decoder, etc.). Replaces
 * the previous approach of scattering each tool's icon across the header
 * so we stay legible on narrow viewports.
 *
 * Callers pass the tool actions; the menu handles the open/close +
 * outside-click-to-dismiss + keyboard behavior.
 */
export function ToolsMenu(
  { onImport, onEncDec }:
  { onImport: () => void; onEncDec: () => void }
) {
  const [open, setOpen] = useState(false);
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
        </div>
      )}
    </div>
  );
}
