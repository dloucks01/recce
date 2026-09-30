// Tiny pub/sub for global toasts — App.tsx subscribes and renders.
// Any component can trigger a toast without prop-drilling `note` through the tree.
//
// Usage:
//   import { toast } from "./toast";
//   toast.show("dismissed 12 findings", { label: "Undo", onClick: () => …, ms: 6000 });

export type ToastAction = { label: string; onClick: () => void };
export type Toast = { id: number; msg: string; action?: ToastAction; ms: number };

type Listener = (t: Toast | null) => void;

let nextId = 1;
const listeners = new Set<Listener>();
let current: Toast | null = null;
let timer: number | undefined;

function emit(t: Toast | null) {
  current = t;
  listeners.forEach(l => l(t));
}

export const toast = {
  show(msg: string, action?: ToastAction & { ms?: number }) {
    window.clearTimeout(timer);
    const ms = action?.ms ?? (action ? 6000 : 4000);
    const t: Toast = { id: nextId++, msg, action: action && { label: action.label, onClick: action.onClick }, ms };
    emit(t);
    timer = window.setTimeout(() => { if (current?.id === t.id) emit(null); }, ms);
    return t.id;
  },
  dismiss(id?: number) {
    if (id === undefined || current?.id === id) {
      window.clearTimeout(timer);
      emit(null);
    }
  },
  subscribe(fn: Listener): () => void {
    listeners.add(fn);
    fn(current);
    return () => { listeners.delete(fn); };
  },
};
