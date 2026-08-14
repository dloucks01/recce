import { VulnDetail } from "./api";
import { NoteCell } from "./ui";

// The expanded detail of a single finding — shared by the host drawer and the
// Findings table so both show identical drill-down (raw output, fix, QoD/CWE/EPSS).
export function FindingDetail(
  { v, onNote }: { v: VulnDetail; onNote: (key: string, text: string) => void }
) {
  return (
    <div className="dv-detail">
      <div className="kv">
        <span>Port</span><b className="mono">{v.port ?? "—"}</b>
        <span>QoD</span><b className="mono">{v.qod} {v.qod_type}</b>
        {v.epss > 0 && <><span>EPSS</span><b className="mono">{v.epss}%</b></>}
        {v.cwes.length > 0 && <><span>CWE</span><b className="mono">{v.cwes.join(", ")}</b></>}
      </div>
      {v.output && <pre className="dv-output">{v.output}</pre>}
      {v.remediation && <div className="dv-fix"><b>Fix:</b> {v.remediation}</div>}
      <div className="dv-note"><NoteCell value={v.notes} onSave={(t) => onNote(v.key, t)} /></div>
    </div>
  );
}
