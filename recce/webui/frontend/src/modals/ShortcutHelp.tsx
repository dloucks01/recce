import { useEscape } from "../ui";

const SHORTCUTS: [string, string][] = [
  ["Alt + 1-9", "Switch to Nth visible tab"],
  ["Alt + I", "Toggle import modal"],
  ["/", "Focus search"],
  ["Esc", "Close panel / drawer"],
  ["?", "Show this help"],
];

export function ShortcutHelp({ onClose }: { onClose: () => void }) {
  useEscape(onClose);
  return (
    <>
      <div className="modal-backdrop" onClick={onClose} />
      <div className="modal shortcut-help" role="dialog" aria-label="Keyboard shortcuts">
        <div className="modal-h">
          <h3>Keyboard shortcuts</h3>
          <button className="drawer-x" onClick={onClose} aria-label="close">✕</button>
        </div>
        <div className="shortcut-list">
          {SHORTCUTS.map(([key, desc]) => (
            <div key={key} className="shortcut-row">
              <kbd>{key}</kbd>
              <span>{desc}</span>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}
