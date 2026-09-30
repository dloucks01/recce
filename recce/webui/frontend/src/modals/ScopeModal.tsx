import { useCallback, useEffect, useState } from "react";
import { Modal } from "../ui";
import { ScopeEntry, getScope, postScope, deleteScope } from "../api";
import { toast } from "../toast";

/**
 * Scope editor — the /api/scope endpoint has always supported GET/POST/
 * DELETE, but scope could only be set at CLI enum-time until now. This
 * modal lets a tester add or remove an in-scope subnet mid-engagement.
 */
export function ScopeModal({ onClose }: { onClose: () => void }) {
  const [scope, setScope] = useState<ScopeEntry[] | null>(null);
  const [subnet, setSubnet] = useState<string>("");
  const [note, setNote] = useState<string>("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>("");

  const refresh = useCallback(async () => {
    try {
      setScope(await getScope());
      setErr("");
    } catch (e) {
      setErr((e as Error).message);
    }
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const add = async () => {
    const s = subnet.trim();
    if (!s) return;
    setBusy(true);
    try {
      await postScope(s, note.trim());
      setSubnet("");
      setNote("");
      await refresh();
      toast.show(`Added ${s} to scope`);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const remove = async (s: string) => {
    if (!confirm(`Remove ${s} from scope? Hosts already discovered in it stay in the engagement.`)) return;
    setBusy(true);
    try {
      await deleteScope(s);
      await refresh();
      toast.show(`Removed ${s} from scope`);
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title="Engagement Scope"
           subtitle="In-scope subnets. Scans that don't specify targets sweep the union of these."
           onClose={onClose} size="md">
      {err && <div className="error-banner">{err}</div>}
      <div className="scope-list">
        {scope === null ? <div className="empty">Loading…</div> :
         scope.length === 0 ? <div className="empty">No subnets in scope yet.</div> :
         scope.map(entry => (
           <div key={entry.subnet} className="scope-row">
             <span className="mono">{entry.subnet}</span>
             <span className="muted">{entry.size} host(s)</span>
             <button className="btn danger sm" onClick={() => remove(entry.subnet)}
                     disabled={busy}
                     title={`remove ${entry.subnet}`}>
               Remove
             </button>
           </div>
         ))
        }
      </div>
      <div className="scope-add">
        <h4>Add subnet</h4>
        <div className="scope-add-row">
          <input placeholder="10.0.0.0/24 or 10.0.0.5-10.0.0.99 or 10.0.0.5"
                 value={subnet}
                 onChange={(e) => setSubnet(e.target.value)}
                 onKeyDown={(e) => { if (e.key === "Enter" && !busy) add(); }}
                 autoFocus />
          <input placeholder="note (optional)"
                 value={note}
                 onChange={(e) => setNote(e.target.value)}
                 onKeyDown={(e) => { if (e.key === "Enter" && !busy) add(); }} />
          <button className="btn primary" onClick={add} disabled={busy || !subnet.trim()}>
            Add
          </button>
        </div>
        <p className="muted small">
          CIDRs / ranges / single IPs / hostnames all accepted; parsed the
          same way <code>recce enum</code> parses its target argument.
        </p>
      </div>
    </Modal>
  );
}
