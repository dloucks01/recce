import { useEffect, useState, useMemo } from "react";
import { Modal } from "../ui";

type Op = {
  name: string;
  description: string;
  requires_key: boolean;
};

type Props = {
  onClose: () => void;
};

// Small helper so the modal doesn't fight the shared api.ts (which is
// oriented at typed helpers per endpoint). encdec ops are simple JSON.
async function _post(path: string, body: unknown) {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return r.json();
}

async function _get(path: string) {
  const r = await fetch(path);
  return r.json();
}

export function EncDecModal({ onClose }: Props) {
  const [ops, setOps] = useState<Op[]>([]);
  const [op, setOp] = useState<string>("base64-decode");
  const [input, setInput] = useState<string>("");
  const [key, setKey] = useState<string>("");
  const [output, setOutput] = useState<string>("");
  const [err, setErr] = useState<string>("");
  const [busy, setBusy] = useState<boolean>(false);
  const [filter, setFilter] = useState<string>("");

  // Recipe (chain) mode
  const [chainMode, setChainMode] = useState<boolean>(false);
  const [chainSteps, setChainSteps] = useState<{ op: string; key?: string }[]>([]);
  const [chainOutputs, setChainOutputs] = useState<string[]>([]);

  useEffect(() => {
    _get("/api/encdec/ops")
      .then((r) => setOps(r.ops || []))
      .catch((e) => setErr(String(e)));
  }, []);

  const currentOp = useMemo(() => ops.find((o) => o.name === op), [ops, op]);

  const filteredOps = useMemo(() => {
    if (!filter.trim()) return ops;
    const f = filter.toLowerCase();
    return ops.filter(
      (o) => o.name.toLowerCase().includes(f) || o.description.toLowerCase().includes(f),
    );
  }, [ops, filter]);

  async function runOp() {
    setBusy(true);
    setErr("");
    setOutput("");
    try {
      const r = await _post("/api/encdec", {
        op,
        input,
        key: currentOp?.requires_key ? key : "",
      });
      if (r.ok) {
        setOutput(r.output);
      } else {
        setErr(r.error || "operation failed");
      }
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  }

  async function runChain() {
    setBusy(true);
    setErr("");
    setOutput("");
    setChainOutputs([]);
    try {
      const r = await _post("/api/encdec/chain", { input, steps: chainSteps });
      if (r.ok) {
        setOutput(r.output);
        setChainOutputs(r.step_outputs || []);
      } else {
        setErr(`step ${r.failed_step_index ?? "?"}: ${r.error || "chain failed"}`);
        setChainOutputs(r.step_outputs || []);
      }
    } catch (e) {
      setErr(String(e instanceof Error ? e.message : e));
    } finally {
      setBusy(false);
    }
  }

  function addChainStep() {
    setChainSteps((s) => [...s, { op }]);
  }

  function swapInputWithOutput() {
    setInput(output);
    setOutput("");
    setChainOutputs([]);
  }

  return (
    <Modal
      title="Encoder / Decoder"
      subtitle="Same toolbox as the CLI (recce encdec <op>). All operations run locally — no data leaves the box. Filter to find an op fast; toggle Recipe mode to chain steps."
      onClose={onClose}
      size="lg"
      headerActions={
        <label style={{ fontSize: 12, display: "flex", alignItems: "center", gap: 6 }}>
          <input
            type="checkbox"
            checked={chainMode}
            onChange={(e) => {
              setChainMode(e.target.checked);
              setChainOutputs([]);
              setOutput("");
            }}
          />
          Recipe mode
        </label>
      }
    >
      <div className="encdec-body">

          <label className="imp-field">
            Operation
            <input
              type="text"
              placeholder="Filter (base64, jwt, hash…)"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              style={{ marginBottom: 6 }}
              disabled={busy}
            />
            <select
              value={op}
              onChange={(e) => setOp(e.target.value)}
              disabled={busy}
              style={{ minHeight: 140 }}
              size={filteredOps.length > 8 ? 10 : Math.max(4, filteredOps.length)}
            >
              {filteredOps.map((o) => (
                <option key={o.name} value={o.name}>
                  {o.name} — {o.description}
                </option>
              ))}
            </select>
          </label>

          {currentOp?.requires_key && !chainMode && (
            <label className="imp-field">
              Key {op === "rot-n" ? "(integer)" : op.startsWith("xor") ? "(hex)" : ""}
              <input
                value={key}
                onChange={(e) => setKey(e.target.value)}
                disabled={busy}
                placeholder={op === "rot-n" ? "13" : op.startsWith("xor") ? "deadbeef" : "shared secret"}
              />
            </label>
          )}

          {chainMode && (
            <div className="imp-field">
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <b>Steps ({chainSteps.length}):</b>
                <button className="toggle" onClick={addChainStep} disabled={busy}>
                  + add "{op}"
                </button>
                <button className="toggle" onClick={() => setChainSteps([])} disabled={busy}>
                  clear
                </button>
              </div>
              {chainSteps.length === 0 && (
                <p className="muted small" style={{ marginTop: 6 }}>
                  Pick an op above, hit "+ add" to build up the recipe.
                </p>
              )}
              <ol style={{ marginTop: 6, paddingLeft: 22 }}>
                {chainSteps.map((s, i) => {
                  const meta = ops.find((o) => o.name === s.op);
                  return (
                    <li key={i} style={{ marginBottom: 4 }}>
                      <code>{s.op}</code>
                      {meta?.requires_key && (
                        <input
                          value={s.key || ""}
                          onChange={(e) => {
                            const v = e.target.value;
                            setChainSteps((prev) =>
                              prev.map((st, j) => (j === i ? { ...st, key: v } : st)),
                            );
                          }}
                          placeholder="key"
                          style={{ marginLeft: 8, width: 160 }}
                          disabled={busy}
                        />
                      )}
                      <button
                        className="linkish"
                        onClick={() =>
                          setChainSteps((prev) => prev.filter((_, j) => j !== i))
                        }
                        disabled={busy}
                        style={{ marginLeft: 8 }}
                      >
                        remove
                      </button>
                    </li>
                  );
                })}
              </ol>
            </div>
          )}

          <label className="imp-field">
            Input
            <textarea
              className="imp-paste"
              style={{ minHeight: 130, fontFamily: "var(--mono)" }}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              disabled={busy}
              placeholder="paste the string to encode / decode…"
            />
          </label>

          {err && <div className="ranmsg warn-msg">{err}</div>}

          {output && (
            <label className="imp-field">
              Output
              <textarea
                className="imp-paste"
                style={{ minHeight: 130, fontFamily: "var(--mono)" }}
                value={output}
                readOnly
              />
            </label>
          )}

          {chainMode && chainOutputs.length > 0 && (
            <details style={{ marginTop: 4 }}>
              <summary style={{ cursor: "pointer" }}>
                Per-step output ({chainOutputs.length} stages)
              </summary>
              <ol style={{ paddingLeft: 22, fontFamily: "var(--mono)", fontSize: 12 }}>
                {chainOutputs.map((s, i) => (
                  <li key={i} style={{ marginBottom: 4 }}>
                    <code>
                      {chainSteps[i]?.op || "?"}: {s.slice(0, 200)}
                      {s.length > 200 ? "…" : ""}
                    </code>
                  </li>
                ))}
              </ol>
            </details>
          )}
        </div>

        <div className="modal-actions">
          <button className="toggle" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          {output && (
            <button
              className="toggle"
              onClick={swapInputWithOutput}
              disabled={busy}
              title="Move output into input for chaining another op manually"
            >
              ↩ Output → Input
            </button>
          )}
          {output && (
            <button
              className="toggle"
              onClick={() => navigator.clipboard.writeText(output)}
              disabled={busy}
            >
              📋 Copy output
            </button>
          )}
          {chainMode ? (
            <button
              className="run"
              onClick={runChain}
              disabled={busy || chainSteps.length === 0 || !input}
            >
              {busy ? "Running…" : "▶ Run recipe"}
            </button>
          ) : (
            <button
              className="run"
              onClick={runOp}
              disabled={busy || !op || !input || (currentOp?.requires_key && !key)}
            >
              {busy ? "Running…" : "▶ Apply"}
            </button>
          )}
        </div>
    </Modal>
  );
}
