import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import {
  Collab, ChatMsg, getCollab, getChat, postChat, pingPresence, postAssign,
  postLabel, postPortStatus, postDismiss,
} from "../api";
import { toast } from "../toast";

const EMPTY: Collab = { assignments: {}, labels: {}, port_status: {}, dismissed: {}, activity: [], online: [], roster: [] };

export type CollabCtx = {
  c: Collab;
  refresh: () => void;
  me: string;
  assign: (ip: string, tester: string) => void;
  label: (ip: string, label: string, on: boolean) => void;
  portStatus: (ip: string, port: number, status: string) => void;
  dismiss: (key: string, on: boolean) => void;
  chat: ChatMsg[];
  unread: number;
  sendChat: (text: string, image: string, file?: { data: string; name: string } | null) => Promise<void>;
  pushChat: (m: ChatMsg) => void;
  markChatRead: () => void;
  // True (and consumes) if `mid` is one of this client's own in-flight mutations —
  // lets the SSE handler drop the echo of a change we already applied optimistically.
  consumeMid: (mid: string) => boolean;
};

const Ctx = createContext<CollabCtx | null>(null);
export const useCollab = () => useContext(Ctx)!;
const me = () => localStorage.getItem("recce.tester") || "someone";

export function CollabProvider({ children }: { children: React.ReactNode }) {
  const [c, setC] = useState<Collab>(EMPTY);
  const refresh = useCallback(() => { getCollab().then(setC).catch(() => {}); }, []);
  useEffect(() => {
    refresh();
    pingPresence().then(refresh);
    const poll = window.setInterval(refresh, 15000);
    const beat = window.setInterval(() => pingPresence(), 20000);
    return () => { window.clearInterval(poll); window.clearInterval(beat); };
  }, [refresh]);

  // chat: history loaded once; live messages arrive via SSE (pushChat, called by App)
  const [chat, setChat] = useState<ChatMsg[]>([]);
  const [unread, setUnread] = useState(0);
  useEffect(() => { getChat().then(setChat).catch(() => {}); }, []);

  // Ask once for permission so mentions can fire a browser notification later.
  useEffect(() => {
    if ("Notification" in window && Notification.permission === "default") {
      Notification.requestPermission().catch(() => {});
    }
  }, []);

  const pushChat = useCallback((m: ChatMsg) => {
    setChat((cs) => (cs.some((x) => x.id === m.id) ? cs : [...cs, m]));
    if (m.tester !== me()) {
      setUnread((u) => u + 1);
      // Escalate @-mentions to a browser Notification so they land even when
      // the tab isn't focused. Case-insensitive whole-token match.
      const meName = me();
      const re = new RegExp("@" + meName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\b", "i");
      if (meName && meName !== "someone" && re.test(m.text || "")) {
        if ("Notification" in window && Notification.permission === "granted") {
          try {
            new Notification(`${m.tester} mentioned you`, { body: m.text, tag: "recce-mention" });
          } catch { /* browser may block */ }
        }
      }
    }
  }, []);
  const markChatRead = useCallback(() => setUnread(0), []);
  const sendChat = useCallback(async (text: string, image: string, file?: { data: string; name: string } | null) => {
    const m = await postChat(text, image, file);
    pushChat(m);
  }, [pushChat]);

  // Our own in-flight mutation ids — the SSE echo of these is dropped (we already
  // applied them optimistically + reconcile via the POST below), so no double-fetch.
  const pendingMids = useRef<Set<string>>(new Set());
  const consumeMid = useCallback((mid: string) => {
    if (mid && pendingMids.current.has(mid)) {
      pendingMids.current.delete(mid);
      return true;
    }
    return false;
  }, []);

  // optimistic local update, then reconcile from the server broadcast
  const opt = (fn: (d: Collab) => Collab, callFactory: (mid: string) => Promise<unknown>) => {
    const mid = (crypto?.randomUUID?.() || `m-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    pendingMids.current.add(mid);
    window.setTimeout(() => pendingMids.current.delete(mid), 10000);   // never leak
    setC((d) => fn(structuredClone(d)));
    Promise.resolve(callFactory(mid)).then(refresh).catch(refresh);
  };
  const value: CollabCtx = {
    c, refresh, me: me(),
    assign: (ip, tester) => {
      const prev = c.assignments[ip] || "";
      opt((d) => { if (tester) d.assignments[ip] = tester; else delete d.assignments[ip]; return d; }, (mid) => postAssign(ip, tester, mid));
      toast.show(
        tester ? `${tester === me() ? "you" : tester} claimed ${ip}` : `${ip} released`,
        { label: "Undo", onClick: () => value.assign(ip, prev) },
      );
    },
    label: (ip, l, on) => opt((d) => { const s = new Set(d.labels[ip] || []); on ? s.add(l) : s.delete(l); d.labels[ip] = [...s]; return d; }, (mid) => postLabel(ip, l, on, mid)),
    portStatus: (ip, port, status) => opt((d) => { const k = `${ip}:${port}`; if (status) d.port_status[k] = status; else delete d.port_status[k]; return d; }, (mid) => postPortStatus(ip, port, status, mid)),
    dismiss: (key, on) => {
      opt((d) => { if (on) d.dismissed[key] = me(); else delete d.dismissed[key]; return d; }, (mid) => postDismiss(key, on, mid));
      toast.show(on ? "dismissed" : "restored", { label: "Undo", onClick: () => value.dismiss(key, !on) });
    },
    chat, unread, sendChat, pushChat, markChatRead, consumeMid,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
