// Exploit PoC browser — recce's per-finding proof scripts for the current scope.
// Lists each generated artifact (web PoC / build recipe / pwntools skeleton); pick
// one to read its source, with what it proves + build/deliver steps, and copy or
// download it. Every script is a proof (benign marker + ROE-swap line), built from
// a published technique with the target's real parameters — not weaponized code.
import { useEffect, useMemo, useState } from "react";
import { getPocScripts, PocArtifact, PocResp } from "../api";
import { copyText } from "../util";
import { toast } from "../toast";

const KIND_LABEL: Record<string, string> = {
  web: "web", recipe: "recipe", pwntools: "pwntools",
};

function download(a: PocArtifact) {
  try {
    const blob = new Blob([a.source], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const el = document.createElement("a");
    el.href = url; el.download = a.filename;
    document.body.appendChild(el); el.click(); el.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch { toast.show("download failed"); }
}

export function PocModal({ scope, target = "", title, onClose }:
  { scope: "engagement" | "host" | "finding"; target?: string; title: string; onClose: () => void }) {
  const [data, setData] = useState<PocResp | null>(null);
  const [err, setErr] = useState("");
  const [sel, setSel] = useState(0);

  useEffect(() => {
    let cancel = false;
    setData(null); setErr(""); setSel(0);
    getPocScripts(scope, target)
      .then((d) => { if (!cancel) setData(d); })
      .catch((e) => { if (!cancel) setErr(String(e?.message || e)); });
    return () => { cancel = true; };
  }, [scope, target]);

  useEffect(() => {
    const k = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);

  const arts = data?.artifacts || [];
  const cur = useMemo(() => arts[Math.min(sel, arts.length - 1)], [arts, sel]);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal poc-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-h">
          <h3>Exploit PoCs — {title}</h3>
          <button className="icon-btn" onClick={onClose} title="close (Esc)">✕</button>
        </div>
        <div className="modal-sub" style={{ margin: "6px 0 10px" }}>
          Real proof scripts for confirmed findings — published techniques with this target's
          parameters filled in, each with a benign proof + an ROE-swap line. Run only within your ROE.
        </div>

        {err ? <div className="empty">Couldn't build PoCs: {err}</div>
          : !data ? <div className="loading">Generating…</div>
          : arts.length === 0 ? <div className="empty">No PoC scripts for this scope — recce emits them for web exposures, memory-corruption findings, and the built-in recipe classes (LD_PRELOAD, DLL-hijack, redis/pg RCE…).</div>
          : (
            <div className="poc-grid">
              <div className="poc-list">
                {arts.map((a, i) => (
                  <button key={a.filename} className={"poc-item" + (i === sel ? " on" : "")} onClick={() => setSel(i)}>
                    <div className="row" style={{ gap: 6, alignItems: "baseline" }}>
                      <span className={"chip poc-kind poc-" + a.kind}>{KIND_LABEL[a.kind] || a.kind}</span>
                      <span className="mono ellip" style={{ fontSize: 11, flex: 1 }}>{a.filename}</span>
                    </div>
                    <div className="muted ellip" style={{ fontSize: 11 }}>{a.host} · {a.proves}</div>
                  </button>
                ))}
              </div>
              <div className="poc-view">
                {cur && (
                  <>
                    <div className="row wrap" style={{ gap: 6, alignItems: "baseline", marginBottom: 6 }}>
                      <b className="mono" style={{ fontSize: 12 }}>{cur.filename}</b>
                      <span className="chip">{cur.lang}</span>
                      <span className="grow" style={{ flex: 1 }} />
                      <button className="btn sm" onClick={() => copyText(cur.source).then((ok) => toast.show(ok ? "copied" : "copy failed"))}>Copy</button>
                      <button className="btn sm primary" onClick={() => download(cur)}>Download</button>
                    </div>
                    {cur.proof && <div className="muted" style={{ fontSize: 11, marginBottom: 4 }}><b>Proves:</b> {cur.proof}</div>}
                    {cur.build.length > 0 && <div className="muted" style={{ fontSize: 11, marginBottom: 4 }}><b>Build:</b> <span className="mono">{cur.build.join("  ·  ")}</span></div>}
                    {cur.deliver && <div className="muted" style={{ fontSize: 11, marginBottom: 6 }}><b>Deliver:</b> {cur.deliver}</div>}
                    <pre className="playbook-pre">{cur.source}</pre>
                  </>
                )}
              </div>
            </div>
          )}

        <div className="modal-actions">
          {data && arts.length > 0 && <span className="muted" style={{ fontSize: 11, marginRight: "auto" }}>{arts.length} PoC script(s) · {data.meta.hosts} host(s)</span>}
          <button className="btn sm" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
}
