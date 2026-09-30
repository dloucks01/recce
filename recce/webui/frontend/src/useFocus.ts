import { useEffect, useRef, useState } from "react";
import { postFocus, myTester } from "./api";

// Track co-presence on an entity ("host:<ip>" / "finding:<key>") for collision
// awareness. Returns the OTHER operators viewing it and, separately, those with
// the advisory edit soft-lock (actively modifying it). Pings while mounted, clears
// on unmount. `editing` flips the caller's own soft-lock (e.g. while a note field
// is focused). Ephemeral and advisory — never blocks anyone.
export function useFocus(entity: string, editing = false): { viewers: string[]; editors: string[] } {
  const [state, setState] = useState<{ viewers: string[]; editors: string[] }>(
    { viewers: [], editors: [] });
  const editingRef = useRef(editing);
  editingRef.current = editing;

  useEffect(() => {
    if (!entity) return;
    let alive = true;
    const me = myTester();
    const ping = async () => {
      const r = await postFocus(entity, true, editingRef.current);
      if (alive) {
        setState({
          viewers: r.testers.filter((x) => x !== me),
          editors: r.editing.filter((x) => x !== me),
        });
      }
    };
    ping();
    const id = window.setInterval(ping, 8000);   // keepalive < server focus TTL (25s)
    return () => {
      alive = false;
      window.clearInterval(id);
      postFocus(entity, false);                  // clear my focus when the drawer closes
    };
  }, [entity]);

  // Re-ping promptly when the edit soft-lock toggles, so teammates see it fast.
  useEffect(() => {
    if (!entity) return;
    postFocus(entity, true, editing).then((r) => {
      const me = myTester();
      setState({ viewers: r.testers.filter((x) => x !== me), editors: r.editing.filter((x) => x !== me) });
    }).catch(() => {});
  }, [entity, editing]);

  return state;
}
