import { RefObject } from "react";

/**
 * Live console strip that ScanTab hangs off its own log state. Extracted from
 * ScanTab so the primary control-flow code is easier to read; behavior is
 * identical.
 *
 * Props:
 *   log         — array of stdout/stderr lines already collected
 *   running     — the primary scan is still emitting lines
 *   chainRunning — a chained follow-up scan is still emitting
 *   logRef      — ref for auto-scrolling the console body to the bottom
 *   onClose     — dismiss the console (parent controls visibility)
 */
export function ScanConsole(
  { log, running, chainRunning, logRef, onClose }:
  {
    log: string[];
    running: boolean;
    chainRunning: boolean;
    logRef: RefObject<HTMLDivElement>;
    onClose: () => void;
  }
) {
  return (
    <div className="scan-console">
      <div className="scan-console-bar">
        <span className="scan-console-title">
          {(running || chainRunning) && <span className="scan-pulse-sm" />}
          Output · {log.length} lines
        </span>
        <button className="scan-console-close" onClick={onClose}>×</button>
      </div>
      <div className="scan-console-body" ref={logRef}>
        {log.map((line, i) => (
          <div key={i} className="scan-console-line">{line}</div>
        ))}
        {(running || chainRunning) && (
          <div className="scan-console-line scan-console-cursor">_</div>
        )}
        {!running && !chainRunning && log.length > 0 && (
          <div className="scan-console-line scan-console-done">— done —</div>
        )}
      </div>
    </div>
  );
}
