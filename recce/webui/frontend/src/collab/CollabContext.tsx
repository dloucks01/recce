import { createContext, useCallback, useContext, useEffect, useState } from "react";
import {
  Collab, ChatMsg, getCollab, getChat, postChat, pingPresence, postAssign,
  postLabel, postPortStatus, postDismiss,
} from "../api";
import { toast } from "../toast";

const EMPTY: Collab = { assignments: {}, labels: {}, port_status: {}, dismissed: {}, activity: [], online: [] };

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

  // optimistic local update, then reconcile from the server broadcast
  const opt = (fn: (d: Collab) => Collab, call: Promise<unknown>) => {
    setC((d) => fn(structuredClone(d)));
    Promise.resolve(call).then(refresh).catch(refresh);
  };
  const value: CollabCtx = {
    c, refresh, me: me(),
    assign: (ip, tester) => {
      const prev = c.assignments[ip] || "";
      opt((d) => { if (tester) d.assignments[ip] = tester; else delete d.assignments[ip]; return d; }, postAssign(ip, tester));
      toast.show(
        tester ? `${tester === me() ? "you" : tester} claimed ${ip}` : `${ip} released`,
        { label: "Undo", onClick: () => value.assign(ip, prev) },
      );
    },
    label: (ip, l, on) => opt((d) => { const s = new Set(d.labels[ip] || []); on ? s.add(l) : s.delete(l); d.labels[ip] = [...s]; return d; }, postLabel(ip, l, on)),
    portStatus: (ip, port, status) => opt((d) => { const k = `${ip}:${port}`; if (status) d.port_status[k] = status; else delete d.port_status[k]; return d; }, postPortStatus(ip, port, status)),
    dismiss: (key, on) => {
      opt((d) => { if (on) d.dismissed[key] = me(); else delete d.dismissed[key]; return d; }, postDismiss(key, on));
      toast.show(on ? "dismissed" : "restored", { label: "Undo", onClick: () => value.dismiss(key, !on) });
    },
    chat, unread, sendChat, pushChat, markChatRead,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
