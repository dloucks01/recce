import { useEffect, useRef, useState } from "react";

type EngagementRow = {
  path: string;
  dir_name: string;
  engagement: string;
  current: boolean;
  mtime: number;
};
type EngagementsResp = {
  current: string;
  parent: string;
  engagements: EngagementRow[];
};

/**
 * P7-B4 (read-only): shows the currently-served engagement name in the
 * header. When peer engagements exist in the same parent directory, the
 * badge becomes a dropdown that lists them + shows the exact
 * `recce serve` command to restart against the picked one.
 *
 * True in-place switching (kill the current server, respawn on the new
 * -o dir, rebind sessions) is a bigger project — deferred to a future
 * arc. This ships the visibility so an operator running several
 * concurrent engagements can at least SEE what else exists without a
 * shell hunt through the parent directory.
 */
export function EngagementBadge() {
  const [state, setState] = useState<EngagementsResp | null>(null);
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetch("/api/engagements").then((r) => r.ok ? r.json() : null)
      .then((d) => setState(d))
      .catch(() => setState(null));
  }, []);

  useEffect(() => {
    if (!open) return;
    function close(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, [open]);

  if (!state || !state.engagements.length) return null;
  const current = state.engagements.find((e) => e.current) || state.engagements[0];
  const siblings = state.engagements.filter((e) => !e.current);
  const label = current.engagement || current.dir_name;

  // No siblings — just render a passive badge, no dropdown affordance.
  if (siblings.length === 0) {
    return (
      <span className="engagement-badge" title={`current engagement · ${current.path}`}>
        📂 {label}
      </span>
    );
  }

  return (
    <div className="engagement-menu" ref={ref}>
      <button className="engagement-badge engagement-badge-btn"
              onClick={() => setOpen((v) => !v)}
              title={`current engagement · ${siblings.length} peer(s) available`}>
        📂 {label} <span className="engagement-caret">▾</span>
      </button>
      {open && (
        <div className="engagement-popup" role="menu">
          <div className="engagement-popup-h muted small">
            Serving from: <span className="mono">{state.parent}</span>
          </div>
          <div className="engagement-row engagement-row-current">
            <span className="engagement-row-mark">●</span>
            <span className="engagement-row-name">{current.engagement || current.dir_name}</span>
            <span className="muted small">current</span>
          </div>
          <div className="engagement-divider" />
          {siblings.map((s) => (
            <div key={s.path} className="engagement-row">
              <span className="engagement-row-mark">○</span>
              <div className="engagement-row-body">
                <div className="engagement-row-name">{s.engagement || s.dir_name}</div>
                <div className="muted small mono">{s.dir_name}</div>
              </div>
              <button className="engagement-row-copy"
                      title="Copy the recce serve command for this engagement"
                      onClick={() => {
                        const cmd = `recce serve -o ${s.path} --port 8443`;
                        navigator.clipboard?.writeText(cmd);
                      }}>
                📋 copy
              </button>
            </div>
          ))}
          <div className="engagement-popup-foot muted small">
            In-place switch not implemented yet — restart <span className="mono">recce serve</span> with the new <span className="mono">-o</span>.
          </div>
        </div>
      )}
    </div>
  );
}
