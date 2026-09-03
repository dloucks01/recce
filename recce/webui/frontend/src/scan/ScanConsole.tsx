import { RefObject, useState } from "react";

/**
 * Live scan console. **P7-B2** rework: was rendered below the Scan-tab
 * workbench body, which pushed the target field + Launch button
 * off-screen during a live scan. Now a floating drawer pinned to the
 * viewport bottom — you can keep working while a scan runs.
 *
 * Three states:
 *   * closed        — parent's `showLog` is false, nothing renders
 *   * minimized     — a compact pill at bottom-right showing "▲ Scan
 *                     running · N lines"; click to expand
 *   * expanded      — the drawer opens, showing the output body + a
 *                     Stop-chain button (when a chain is running) + a
 *                     minimize + close pair
 *
 * Behavior parity with the older embed: SSE-fed log lines, stop-chain
 * routes through the same `onStopChain` callback, close hides via
 * `onClose` (parent's `showLog` state).
 */
export function ScanConsole(
  { log, running, chainRunning, chainStopping, onStopChain, logRef, onClose }:
  {
    log: string[];
    running: boolean;
    chainRunning: boolean;
    chainStopping?: boolean;
    onStopChain?: () => void;
    logRef: RefObject<HTMLDivElement>;
    onClose: () => void;
  }
) {
  const [minimized, setMinimized] = useState(false);
  const active = running || chainRunning;

  if (minimized) {
    return (
      <button className="scan-console-pill"
              onClick={() => setMinimized(false)}
              title="expand the scan console">
        {active && <span className="scan-pulse-sm" />}
        <span className="scan-console-pill-label">
          {active ? "Scan running" : "Scan output"}
          <span className="muted"> · {log.length} lines</span>
        </span>
        <span className="scan-console-pill-icon">▲</span>
      </button>
    );
  }

  return (
    <div className="scan-console-drawer">
      <div className="scan-console-bar">
        <span className="scan-console-title">
          {active && <span className="scan-pulse-sm" />}
          Output · {log.length} lines
        </span>
        <div className="scan-console-actions">
          {chainRunning && onStopChain && (
            <button className="scan-console-stop"
                    onClick={onStopChain}
                    disabled={chainStopping}
                    title="Cancel the current scan and skip any remaining scans in the chain">
              {chainStopping ? "Stopping…" : "⏹ Stop chain"}
            </button>
          )}
          <button className="scan-console-min"
                  onClick={() => setMinimized(true)}
                  title="Minimize — scans keep running in the background">
            ▽
          </button>
          <button className="scan-console-close" onClick={onClose}
                  title="Hide the console (scans keep running in the background)">
            ×
          </button>
        </div>
      </div>
      <div className="scan-console-body" ref={logRef}>
        {log.map((line, i) => (
          <div key={i} className="scan-console-line">{line}</div>
        ))}
        {active && (
          <div className="scan-console-line scan-console-cursor">_</div>
        )}
        {!active && log.length > 0 && (
          <div className="scan-console-line scan-console-done">— done —</div>
        )}
      </div>
    </div>
  );
}
