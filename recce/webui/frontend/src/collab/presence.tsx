import { useCollab } from "./CollabContext";
import { hue, initials } from "./_shared";

export function PresenceBar({ onPick }: { onPick?: (name: string) => void }) {
  const { c, me } = useCollab();
  if (!c.online.length) return null;
  return (
    <div className="presence" title={`online: ${c.online.join(", ")}`}>
      {c.online.slice(0, 6).map((n) => (
        <span key={n} className={"avatar" + (n === me ? " me" : "") + (onPick ? " clk" : "")}
              style={{ background: `hsl(${hue(n)} 55% 45%)` }}
              title={onPick ? `${n} — show their hosts` : n}
              onClick={onPick ? () => onPick(n) : undefined}>{initials(n)}</span>
      ))}
      {c.online.length > 6 && <span className="avatar more">+{c.online.length - 6}</span>}
    </div>
  );
}
