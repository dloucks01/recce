import { useEffect, useState } from "react";
import { ActCard, ActPlan, AttackCoverage, AttackPath, getAct, getAttack, getAttackPath, postActRun } from "../api";
import { Nav, ARCH_ICON, archLabel, ARCHETYPES } from "./shared";

// "I found things — what do I DO?" The ranked, guided action plan, so the UI
// carries the operator from findings to next moves instead of stopping at a list.

function ActCardRow({ c, nav }: { c: ActCard; nav: Nav }) {
  const [copied, setCopied] = useState(false);
  const copy = () => navigator.clipboard?.writeText(c.command).then(() => {
    setCopied(true); setTimeout(() => setCopied(false), 1200);
  });
  const host = c.target && c.target !== "engagement" ? c.target.split(":")[0] : "";
  return (
    <div className={"actcard tier-" + c.tier}>
      <div className="actcard-h">
        <span className="arch">{ARCH_ICON[c.archetype] || "•"} {archLabel(c.archetype)}</span>
        <span className="acttitle">{c.title}{c.count > 1 ? ` ·+${c.count - 1}` : ""}</span>
        {host && <span className="mono host-link" onClick={() => nav.openHost(host)} title="host detail">{c.target}</span>}
        {host && nav.toScan && (
          <button className="linkish" onClick={() => nav.toScan!(host)}
                  title="jump to Scan tab with this target">scan</button>
        )}
        <span className="actscore" title="impact × confidence × leverage">{c.score}</span>
      </div>
      <div className="actyield">→ {c.yields}
        {c.verify_first && <span className="tag warn"> candidate — verify</span>}
        {c.needs.length > 0 && <span className="muted"> · needs: {c.needs.join(", ")}</span>}
      </div>
      <div className="actcmd"><code>{c.command}</code>
        <button className="copy" onClick={copy}>{copied ? "✓ copied" : "copy"}</button>
      </div>
      <div className="acttags">
        {c.attack_id && <span className="tag atk"
          title={`${c.attack_name || "MITRE ATT&CK technique"} — reference (airgap-safe; no external link)`}>ATT&CK {c.attack_id}</span>}
        {c.cwe && <span className="tag">{c.cwe}</span>}
        <span className={"tag safety " + c.safety.replace(/[^a-z]/g, "")}>{c.safety}</span>
      </div>
    </div>
  );
}

export function Act({ nav }: { nav: Nav }) {
  const [plan, setPlan] = useState<ActPlan | null>(null);
  const [atk, setAtk] = useState<AttackCoverage | null>(null);
  const [apath, setApath] = useState<AttackPath | null>(null);
  const [showSvg, setShowSvg] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [arch, setArch] = useState<string>("all");   // archetype filter (declutter)
  const [running, setRunning] = useState(false);
  const [ranMsg, setRanMsg] = useState<string | null>(null);
  const load = () => getAct().then(setPlan).catch((e) => setErr(String(e)));
  useEffect(() => {
    load();
    getAttack().then(setAtk).catch(() => {});
    getAttackPath().then(setApath).catch(() => {});
  }, []);

  async function runAuto() {
    setRunning(true); setRanMsg(null);
    try {
      const r = await postActRun();
      setRanMsg(r.looted > 0
        ? `Collected ${r.looted} new credential(s) — see Credentials tab. Spray plan refreshed.`
        : "No new credentials collected (already captured, or hosts unreachable).");
      await load();
    } catch { setRanMsg("run failed — is the engagement reachable?"); }
    finally { setRunning(false); }
  }

  if (err) return <div className="err">{err}</div>;
  if (!plan) return <div className="loading">Building the action plan…</div>;
  if (plan.top.length === 0)
    return <div className="empty">Nothing actionable yet — run a scan, then the deep modules, and the plan builds itself.</div>;
  const keep = (c: ActCard) => arch === "all" || c.archetype === arch;
  return (
    <div className="actview">
      <div className="act-controls">
        <div className="chips">
          <button className={"chip" + (arch === "all" ? " sel" : "")} onClick={() => setArch("all")}>all</button>
          {ARCHETYPES.map((a) => (
            <button key={a} className={"chip" + (arch === a ? " sel" : "")} onClick={() => setArch(a)}>{archLabel(a)}</button>
          ))}
        </div>
        <button className="run auto-loot" onClick={runAuto} disabled={running}
                title="collect credentials from the read-only unauth services + refresh the spray plan (intrusive actions are never auto-run)">
          {running ? "Collecting…" : "⚡ Collect credentials (read-only)"}
        </button>
        {nav.toSessions && (
          <button className="toggle" onClick={nav.toSessions}>Sessions →</button>
        )}
      </div>
      {ranMsg && <div className="ranmsg">{ranMsg}</div>}
      <section className="panel top-actions">
        <div className="panel-h"><h3>★ Top priorities</h3><span className="muted">highest impact you can act on now</span></div>
        {plan.top.filter(keep).map((c, i) => <ActCardRow key={i} c={c} nav={nav} />)}
      </section>
      {plan.tiers.map((t) => {
        const cards = t.cards.filter(keep);
        if (cards.length === 0) return null;
        return (
          <section className="panel" key={t.tier}>
            <div className="panel-h"><h3 className="tier-label">{t.label}</h3><span className="muted">{cards.length}</span></div>
            {cards.map((c, i) => <ActCardRow key={i} c={c} nav={nav} />)}
          </section>
        );
      })}
      {apath && apath.step_count > 0 && (
        <section className="panel">
          <div className="panel-h">
            <h3>Attack path <span className="tag">projected</span></h3>
            <span className="muted">
              {apath.step_count} step(s) across {apath.stages.length} stage(s) — grounded in confirmed findings, not executed
            </span>
            <button className="linkish" style={{marginLeft: "auto"}} onClick={() => setShowSvg(v => !v)}>
              {showSvg ? "hide graph" : "show graph"}
            </button>
          </div>

          {apath.narrative.length > 0 && (
            <div className="apath-narrative">
              {apath.narrative.map((line, i) => <p key={i}>{line}</p>)}
            </div>
          )}

          <div className="apath-stages">
            {apath.stages.map((sg) => (
              <div className="apath-stage" key={sg.stage}>
                <div className="apath-stage-h">
                  <span className={"apath-stage-dot s-" + sg.stage.replace(/\s+/g, "-").toLowerCase()} />
                  <span className="apath-stage-name">{sg.stage}</span>
                  <span className="muted">{sg.steps.length}</span>
                </div>
                <div className="apath-steps">
                  {sg.steps.map((step) => (
                    <div key={step.key} className="apath-step">
                      <div className="apath-step-t">
                        <span className="apath-step-title">{step.title}</span>
                        <button className="mono host-link" onClick={() => nav.openHost(step.ip)} title="open host detail">
                          {step.ip}{step.hostname ? ` · ${step.hostname}` : ""}
                        </button>
                      </div>
                      {step.why && <div className="apath-step-why muted">{step.why}</div>}
                      {step.cmd && (
                        <div className="apath-step-cmd">
                          <code>{step.cmd}</code>
                          <button className="copy" onClick={() => navigator.clipboard?.writeText(step.cmd)}>copy</button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {showSvg && (
            <div className="apath-wrap">
              <img className="apath" src="/api/attackpath.svg" alt="Attack path" />
            </div>
          )}
        </section>
      )}
      {atk && atk.tactics.length > 0 && (
        <section className="panel">
          <div className="panel-h"><h3>MITRE ATT&CK coverage</h3>
            <span className="muted">{atk.technique_count} techniques · {atk.tactic_count} tactics</span></div>
          <div className="atkgrid">
            {atk.tactics.map((tac) => (
              <div className="atktac" key={tac.tactic}>
                <div className="atktac-h">{tac.tactic} <span className="muted">{tac.tactic_id}</span></div>
                {tac.techniques.map((te) => (
                  <span className="atktech" key={te.id}
                     title={`${te.hosts.length} host(s) · MITRE ATT&CK technique (reference)`}>{te.id} {te.name} <span className="muted">×{te.hosts.length}</span></span>
                ))}
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
