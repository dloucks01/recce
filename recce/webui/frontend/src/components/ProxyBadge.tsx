import { useEffect, useState } from "react";
import { getProxy, ProxyState } from "../api";

/**
 * Compact header pill that reports whether recce is currently pivoting
 * every outbound request through a proxy (--proxy=socks5h://…). Only
 * renders when a proxy is actually configured — otherwise the header
 * stays clean.
 *
 * The proxy is set at serve-time (CLI flag), so the badge is read-only
 * — poll every 15s in case the operator restarts the server behind us.
 */
export function ProxyBadge() {
  const [proxy, setProxy] = useState<ProxyState | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function tick() {
      try {
        const p = await getProxy();
        if (cancelled) return;
        setProxy(p);
        setFailed(false);
      } catch {
        if (cancelled) return;
        setFailed(true);
      }
    }
    tick();
    const id = window.setInterval(tick, 15_000);
    return () => { cancelled = true; window.clearInterval(id); };
  }, []);

  if (failed || !proxy || !proxy.enabled) return null;
  const short = proxy.url.replace(/^([a-z0-9]+):\/\//i, (_m, s) => `${s}://`).slice(0, 32);
  return (
    <span className="proxy-badge"
          title={`Pivoting through ${proxy.url} (${proxy.kind})`}>
      🛰 {short}
    </span>
  );
}
