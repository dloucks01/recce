import { RefObject } from "react";

/**
 * Live console strip that ScanTab hangs off its own log state. Extracted from
 * ScanTab so the primary control-flow code is easier to read; behavior is
 * identical apart from the Stop-chain button (see props).
 *
 * Props:
 *   log            — array of stdout/stderr lines already collected
 *   running        — the primary scan is still emitting lines
 *   chainRunning   — a chained follow-up scan is still emitting
 *   chainStopping  — Stop button was clicked; disable it until the loop exits
 *   onStopChain    — signal from the parent to cancel the running chain
 *                    (cancels the in-flight job + breaks the outer loop)
 *   logRef         — ref for auto-scrolling the console body to the bottom
 *   onClose        — dismiss the console (parent controls visibility)
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
  const active = running || chainRunning;
  return (
    <div className="scan-console">
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
