import { useState } from "react";
import { Playbook as PlaybookData } from "../api";
import { Nav } from "./shared";

// The shared engagement plan: where we are (phase track), what's next (the live
// next-action branches), and the attack-path narrative — all derived from the datastore,
// identical for every tester, live over SSE.
export function Playbook({ pb, nav }: { pb: PlaybookData | null; nav: Nav }) {
  const [copied, setCopied] = useState("");
  if (!pb) return <div className="empty">Loading the playbook…</div>;
  const icon = (s: string) =>
    s === "done" ? "✔" : s === "current" ? "▶" : s === "active" ? "●" : s === "ready" ? "○" : "·";
  const copy = (cmd: string) => {
    navigator.clipboard?.writeText(cmd);
    setCopied(cmd); setTimeout(() => setCopied(""), 1200);
  };
  const showCmd = (s: string) => s === "current" || s === "active" || s === "ready";
  return (
    <div className="playbook">
      <div className="pb-top">
        <div className="pb-col">
          <h3>Where we are</h3>
          <ol className="pb-track">
            {pb.phases.map((p) => (
              <li key={p.key} className={"pb-step " + p.state}>
                <span className="pb-ic">{icon(p.state)}</span>
                <div className="pb-body">
                  <div className="pb-lab">{p.label} <span className="pb-badge">{p.state}</span></div>
                  <div className="pb-detail">{p.detail}</div>
                  {p.cmd && showCmd(p.state) && (
                    <code className="pb-cmd" onClick={() => copy(p.cmd)} title="click to copy">
                      {p.cmd}{copied === p.cmd ? "  ✓ copied" : ""}
                    </code>
                  )}
                </div>
              </li>
            ))}
          </ol>
        </div>
        <div className="pb-col">
          <h3>What's next</h3>
          {pb.branches.length === 0 ? (
            <p className="muted">Nothing outstanding — regenerate the report.</p>
          ) : (
            <ul className="pb-branches">
              {pb.branches.map((b, i) => (
                <li key={i}>
                  <div className="pb-branch-lab">{b.label}</div>
                  <div className="pb-why">{b.why}</div>
                  <code className="pb-cmd" onClick={() => copy(b.cmd)} title="click to copy">
                    {b.cmd}{copied === b.cmd ? "  ✓" : ""}
                  </code>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
      <div className="pb-pathsec">
        <h3 className="pb-path-h">
          Attack path <button className="linkish" onClick={nav.toAct}>see the graph →</button>
        </h3>
        {pb.path.length === 0 ? (
          <p className="muted">No confirmed chain yet — confirm findings with <code>sweep</code>.</p>
        ) : (
          <div className="pb-path">{pb.path.map((line, i) => <p key={i}>{line}</p>)}</div>
        )}
      </div>
    </div>
  );
}
