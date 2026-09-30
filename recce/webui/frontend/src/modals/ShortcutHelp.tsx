import { useEscape } from "../ui";

const SHORTCUTS: [string, string][] = [
  ["Cmd/Ctrl + K", "Command palette — jump to any host, finding, session, or section"],
  ["/", "Open the command palette"],
  ["Esc", "Close the palette, a menu, or a drawer"],
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
