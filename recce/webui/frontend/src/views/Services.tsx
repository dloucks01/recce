import { useMemo, useState } from "react";
import { Host, Finding } from "../api";
import { SevBar } from "../ui";
import { Nav } from "./shared";

type ServiceGroup = {
  name: string;
  product: string;
  hosts: { ip: string; hostname: string; port: number; proto: string; product: string }[];
  findingsBySev: Record<string, number>;
  findingsTotal: number;
};

export function Services(
  { hosts, findings, nav }:
  { hosts: Host[]; findings: Finding[]; nav: Nav }
) {
  const [q, setQ] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const groups = useMemo(() => {
    const map = new Map<string, ServiceGroup>();
    for (const h of hosts) {
      for (const p of h.ports) {
        const svc = p.service || `port-${p.port}`;
        let g = map.get(svc);
        if (!g) {
          g = { name: svc, product: p.product || "", hosts: [], findingsBySev: {}, findingsTotal: 0 };
          map.set(svc, g);
        }
        g.hosts.push({ ip: h.ip, hostname: h.hostname, port: p.port, proto: p.proto, product: p.product });
        if (p.product && !g.product) g.product = p.product;
      }
    }
    // tally findings per service by matching ip+port
    for (const f of findings) {
      if (f.port == null) continue;
      for (const [, g] of map) {
        if (g.hosts.some(h => h.ip === f.ip && h.port === f.port)) {
          g.findingsBySev[f.severity] = (g.findingsBySev[f.severity] || 0) + 1;
          g.findingsTotal++;
          break;
        }
      }
    }
    return [...map.values()].sort((a, b) => b.findingsTotal - a.findingsTotal || b.hosts.length - a.hosts.length);
  }, [hosts, findings]);

  const filtered = useMemo(() => {
    if (!q) return groups;
    const lq = q.toLowerCase();
    return groups.filter(g =>
      g.name.toLowerCase().includes(lq) ||
      g.product.toLowerCase().includes(lq) ||
      g.hosts.some(h => h.ip.includes(lq) || h.hostname.toLowerCase().includes(lq))
    );
  }, [groups, q]);

  const toggle = (name: string) => setExpanded(s => {
    const n = new Set(s);
    n.has(name) ? n.delete(name) : n.add(name);
    return n;
  });

  if (hosts.length === 0) return (
    <div className="firstrun">
      <div className="fr-emoji">🔌</div>
      <h3>No services yet</h3>
      <p>Services appear here once hosts with open ports are discovered.
        Run a <b>Scan</b> or <b>Import</b> results to get started.</p>
    </div>
  );

  const uniquePorts = groups.reduce((n, g) => n + g.hosts.length, 0);

  return (
    <>
      <section className="stats">
        <div className="stat">
          <div className="k">Services</div>
          <div className="v">{groups.length}</div>
        </div>
        <div className="stat">
          <div className="k">Open ports</div>
          <div className="v">{uniquePorts}</div>
        </div>
        <div className="stat">
          <div className="k">Hosts</div>
          <div className="v">{hosts.filter(h => h.ports.length > 0).length}</div>
        </div>
        <div className="stat">
          <div className="k">Findings</div>
          <div className="v">{groups.reduce((n, g) => n + g.findingsTotal, 0)}</div>
        </div>
      </section>

      <section className="panel">
        <div className="panel-h">
          <h3>Services</h3>
          <input className="search" placeholder="filter services, products, hosts…"
                 value={q} onChange={e => setQ(e.target.value)} />
        </div>

        <div className="svc-list">
          {filtered.map(g => {
            const isOpen = expanded.has(g.name);
            const uniqueHosts = new Set(g.hosts.map(h => h.ip)).size;
            const ports = [...new Set(g.hosts.map(h => h.port))].sort((a, b) => a - b);
            return (
              <div key={g.name} className="svc-group">
                <div className="svc-group-h" onClick={() => toggle(g.name)}>
                  <span className={`sess-group-caret${isOpen ? "" : " closed"}`}>&#9662;</span>
                  <span className="svc-name">{g.name}</span>
                  <span className="svc-ports mono">{ports.join(", ")}</span>
                  {g.product && <span className="svc-product">{g.product}</span>}
                  <span className="muted">{uniqueHosts} host{uniqueHosts !== 1 ? "s" : ""}</span>
                  <SevBar findings={g.findingsBySev} />
                </div>
                {isOpen && (
                  <div className="svc-hosts">
                    {g.hosts
                      .slice().sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }))
                      .map((h, i) => (
                      <div key={`${h.ip}:${h.port}:${i}`} className="svc-host-row">
                        <button className="linkish mono" onClick={() => nav.openHost(h.ip)}>
                          {h.ip}
                        </button>
                        {h.hostname && <span className="svc-hn">{h.hostname}</span>}
                        <span className="badge">{h.proto}/{h.port}</span>
                        {h.product && <span className="muted">{h.product}</span>}
                        <div className="svc-host-actions">
                          {nav.toScan && (
                            <button className="linkish" onClick={() => nav.toScan!(h.ip)}>scan</button>
                          )}
                          <button className="linkish" onClick={() => nav.toFindings({ host: h.ip })}>findings</button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
          {filtered.length === 0 && <div className="muted" style={{ padding: "16px" }}>No services match your filter.</div>}
        </div>
      </section>
    </>
  );
}
