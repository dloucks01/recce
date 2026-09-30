import { useState } from "react";
import { TRIAGE_LABELS } from "../api";
import { useCollab } from "./CollabContext";
import { hue, initials } from "./_shared";

export function AssignControl({ ip }: { ip: string }) {
  const { c, me, assign } = useCollab();
  const owner = c.assignments[ip] || "";
  if (owner) {
    return (
      <span className={"owner" + (owner === me ? " mine" : "")} title={`claimed by ${owner}`}
            onClick={(e) => { e.stopPropagation(); assign(ip, ""); }}>
        <span className="avatar sm" style={{ background: `hsl(${hue(owner)} 55% 45%)` }}>{initials(owner)}</span>
        {owner === me ? "you" : owner} <span className="rel">✕</span>
      </span>
    );
  }
  return (
    <button className="claim" onClick={(e) => { e.stopPropagation(); assign(ip, me); }}
            title="claim this host">claim</button>
  );
}

const LABEL_SHORT: Record<string, string> = { interesting: "interesting", "needs-review": "review", "out-of-scope": "OOS" };

// Compact triage control: shows only the ACTIVE labels as chips, plus a 🏷 button
// that opens a small picker — so an untagged host is just a quiet tag icon.
export function LabelChips({ ip }: { ip: string }) {
  const { c, label } = useCollab();
  const on = c.labels[ip] || [];
  const [open, setOpen] = useState(false);
  return (
    <span className="tagctl" onClick={(e) => e.stopPropagation()}>
      {on.map((l) => (
        <span key={l} className={"ltag l-" + l} title={`${l} — click to remove`}
              onClick={() => label(ip, l, false)}>{LABEL_SHORT[l] || l}</span>
      ))}
      <button className={"tagbtn" + (on.length ? " has" : "")} onClick={() => setOpen((v) => !v)}
              title="triage labels" aria-label="triage labels">🏷</button>
      {open && (
        <>
          <div className="exp-backdrop" onClick={() => setOpen(false)} />
          <div className="tagpop">
            {TRIAGE_LABELS.map((l) => {
              const active = on.includes(l);
              return (
                <button key={l} className={"lchip l-" + l + (active ? " on" : "")}
                        onClick={() => label(ip, l, !active)}>{active ? "✓ " : ""}{l}</button>
              );
            })}
          </div>
        </>
      )}
    </span>
  );
}

const PSTATES: [string, string, string][] = [
  ["todo", "☐", "not started"], ["wip", "◐", "in progress"], ["done", "☑", "done"],
];

export function PortStatus({ ip, port }: { ip: string; port: number }) {
  const { c, portStatus } = useCollab();
  const cur = c.port_status[`${ip}:${port}`] || "todo";
  return (
    <span className="portstatus">
      {PSTATES.map(([v, glyph, label]) => (
        <button key={v} className={"psbtn ps-" + v + (cur === v ? " on" : "")}
                onClick={(e) => { e.stopPropagation(); portStatus(ip, port, cur === v ? "" : v); }}
                title={label}>{glyph}</button>
      ))}
    </span>
  );
}
