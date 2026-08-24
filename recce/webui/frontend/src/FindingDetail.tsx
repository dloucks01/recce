import { useState } from "react";
import { VulnDetail } from "./api";
import { SevTag, NoteCell } from "./ui";

function CopyBtn({ text, label }: { text: string; label: string }) {
  const [ok, setOk] = useState(false);
  return (
    <button
      className="fd-copy"
      onClick={() => {
        navigator.clipboard?.writeText(text).then(() => {
          setOk(true);
          setTimeout(() => setOk(false), 1200);
        });
      }}
    >
      {ok ? "Copied" : label}
    </button>
  );
}

export function FindingDetail(
  { v, onNote }: { v: VulnDetail; onNote: (key: string, text: string) => void }
) {
  return (
    <div className="dv-detail">
      {/* ---- Metadata ---- */}
      <div className="fd-meta">
        <div className="fd-meta-row">
          <SevTag severity={v.severity} />
          {v.source && <span className="fd-source">{v.source}</span>}
          {v.tier && <span className={"fd-tier tier " + v.tier}>{v.tier}</span>}
          {v.kev && <span className="badge kev">KEV</span>}
        </div>
        <div className="fd-kv">
          <div className="fd-kv-item">
            <span className="fd-kv-label">Port</span>
            <span className="fd-kv-value mono">{v.port ?? "—"}</span>
          </div>
          <div className="fd-kv-item">
            <span className="fd-kv-label">Quality</span>
            <span className="fd-kv-value mono">{v.qod}{v.qod_type ? ` ${v.qod_type}` : ""}</span>
          </div>
          {v.epss > 0 && (
            <div className="fd-kv-item">
              <span className="fd-kv-label">EPSS</span>
              <span className="fd-kv-value mono">{v.epss}%</span>
            </div>
          )}
          {v.cwes.length > 0 && (
            <div className="fd-kv-item">
              <span className="fd-kv-label">CWE</span>
              <span className="fd-kv-value mono">{v.cwes.join(", ")}</span>
            </div>
          )}
          {v.cve && (
            <div className="fd-kv-item">
              <span className="fd-kv-label">CVE</span>
              <span className="fd-kv-value mono">{v.cve}</span>
            </div>
          )}
        </div>
      </div>

      {/* ---- Evidence ---- */}
      {v.output && (
        <div className="fd-evidence">
          <div className="fd-evidence-header">
            <span className="fd-section-label">Evidence / Tool Output</span>
            <CopyBtn text={v.output} label="Copy evidence" />
          </div>
          <pre className="fd-evidence-code">{v.output}</pre>
        </div>
      )}

      {/* ---- Remediation ---- */}
      {v.remediation && (
        <div className="fd-remediation">
          <div className="fd-section-label">Remediation</div>
          <div className="fd-remediation-body">{v.remediation}</div>
        </div>
      )}

      {/* ---- Actions ---- */}
      <div className="fd-actions">
        <span className="fd-section-label">Actions</span>
        <div className="fd-action-row">
          {v.output && <CopyBtn text={v.output} label="Copy output" />}
          {v.cves && v.cves.length > 0 && (
            <CopyBtn text={v.cves.join(", ")} label={`Copy ${v.cves.length > 1 ? "CVEs" : "CVE"}`} />
          )}
          {v.remediation && <CopyBtn text={v.remediation} label="Copy fix" />}
        </div>
      </div>

      {/* ---- Notes ---- */}
      <div className="fd-notes">
        <span className="fd-section-label">Notes</span>
        <NoteCell value={v.notes} onSave={(t) => onNote(v.key, t)} />
      </div>
    </div>
  );
}
