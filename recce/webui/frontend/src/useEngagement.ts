import { useCallback, useEffect, useState } from "react";
import { Finding, Host, Overview, Playbook as PlaybookData, fetchAll, fetchPlaybook } from "./api";
import type { CollabCtx } from "./collab/CollabContext";

const POLL_MS = 20000;

// One hook to own engagement state — the slow poll, the initial load, and the
// live-events SSE stream that broadcasts cross-tab. App.tsx just consumes.
export function useEngagement(tester: string, note: (msg: string) => void, collab: CollabCtx) {
  const [ov, setOv] = useState<Overview | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [pb, setPb] = useState<PlaybookData | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const [o, f, h] = await fetchAll();
    setOv(o); setFindings(f); setHosts(h);
    fetchPlaybook().then(setPb).catch(() => {});
  }, []);

  // Initial load — surface any error to the caller through the returned state.
  useEffect(() => { refresh().catch((e) => setErr(String(e))); }, [refresh]);

  // Slow safety-net poll; SSE is the primary live-update path.
  useEffect(() => {
    const id = window.setInterval(() => { refresh().catch(() => {}); }, POLL_MS);
    return () => window.clearInterval(id);
  }, [refresh]);

  // Live cross-user events.
  useEffect(() => {
    const es = new EventSource("/api/events");
    es.onmessage = (m) => {
      let d: any;
      try { d = JSON.parse(m.data); } catch { return; }
      if (d.type === "tick") {
        setFindings((fs) => fs.map((f) => (f.key === d.key ? { ...f, reviewed: d.reviewed } : f)));
        setHosts((hs) => hs.map((h) => (h.key === d.key ? { ...h, reviewed: d.reviewed } : h)));
        if (d.tester !== tester) note(`${d.tester} ${d.reviewed ? "checked off" : "reopened"} an item`);
      } else if (d.type === "note") {
        setFindings((fs) => fs.map((f) => (f.key === d.key ? { ...f, notes: d.note } : f)));
        setHosts((hs) => hs.map((h) => (h.key === d.key ? { ...h, notes: d.note } : h)));
        if (d.tester !== tester) note(`${d.tester} left a note`);
      } else if (d.type === "scan_started") {
        note(`${d.tester} started a ${d.targets} scan`);
      } else if (d.type === "scan") {
        note(`${d.tester}'s scan ${d.status}`);
        refresh().catch(() => {});
      } else if (d.type === "import") {
        if (d.tester !== tester) note(`${d.tester} imported ${d.kind} output`);
        refresh().catch(() => {});
      } else if (d.type === "session" && d.event === "enum_done") {
        // Explicit success/failure for on-target enum ingest — used to be
        // silent, leaving the operator wondering whether their `Enumerate`
        // click did anything. `refresh()` folds the newly-ingested findings
        // into the tab that's open.
        note(d.message || `On-target enum ingested for ${d.host_ip}`);
        refresh().catch(() => {});
      } else if (d.type === "session" && d.event === "enum_failed") {
        note(`⚠️ ${d.message || `On-target enum ingest failed for ${d.host_ip}`}`);
      } else if (["assign", "label", "port_status", "dismiss", "add"].includes(d.type)) {
        collab.refresh();
        if (d.type === "add") refresh().catch(() => {});
        if (d.by && d.by !== tester) {
          if (d.type === "assign") note(`${d.by} ${d.tester ? "claimed" : "released"} ${d.ip}`);
          else if (d.type === "add") note(`${d.by} added a ${d.what}`);
        }
      } else if (d.type === "chat" && d.msg) {
        collab.pushChat(d.msg);
        if (d.msg.tester !== tester) note(`💬 ${d.msg.tester}: ${d.msg.text || "sent an image"}`.slice(0, 80));
      }
      // P7-C3: fine-grained action events, surfaced as toasts. Every event
      // below already fires today (broker-side) but was silent on the
      // client. Kept intentionally short — a toast is 3-6s of screen
      // real estate — with the full detail sitting on the Findings /
      // Sessions / Credentials tab.
      else if (d.type === "spray_hit") {
        // Fresh cred captured mid-spray. Refresh() lands the row in the
        // Credentials tab; the toast tells the operator to look.
        refresh().catch(() => {});
        note(`🔑 spray hit · ${d.user}@${d.ip}${d.admin ? " (admin)" : ""}`);
      } else if (d.type === "spray") {
        // End-of-spray summary — only nudge when nothing was already
        // announced per-hit (else the operator has already seen N toasts).
        if (d.hits > 0) note(`Spray done · ${d.hits} hit(s)`);
        else note("Spray done · no hits");
      } else if (d.type === "act_run") {
        note(`Act/run done · ${d.looted} looted`);
        refresh().catch(() => {});
      } else if (d.type === "job_started") {
        // Only announce jobs OTHER testers started — you launched your own
        // and already saw the response.
        if (d.tester && d.tester !== tester) note(`${d.tester} started ${d.kind}`);
      } else if (d.type === "session" && d.event === "caught") {
        note(`⌨ shell caught from ${d.ip}`);
        refresh().catch(() => {});
      } else if (d.type === "session" && d.event === "lost") {
        note(`⚠️ session lost · ${d.id}`);
      } else if (d.type === "prove_verdict") {
        const icon = d.verdict === "proven" ? "✅"
                   : d.verdict === "refuted" ? "❌"
                   : d.verdict === "error" ? "⚠️" : "🤷";
        note(`${icon} prove · ${d.verdict}`);
        refresh().catch(() => {});
      } else if (d.type === "evidence") {
        // Someone dropped a file onto a host row (screenshot, output).
        if (d.by && d.by !== tester) note(`📎 ${d.by} attached evidence to ${d.ip}`);
      } else if (d.type === "delete") {
        // Only announce deletions OTHER testers did — mine surface via the
        // component that initiated them.
        if (d.by && d.by !== tester) note(`${d.by} deleted a ${d.what}`);
      } else if (d.type === "bulk_review" && d.by && d.by !== tester) {
        note(`${d.by} ${d.reviewed ? "checked off" : "reopened"} ${d.count} finding(s)`);
      }
    };
    return () => es.close();
  }, [tester, note, refresh, collab]);

  return { ov, findings, hosts, pb, err, refresh, setFindings, setHosts };
}
