// Phase 7b — shared-surface GUI. Each sub-tab is a filterable table over one
// of recce's cross-service "known ..." readers (union of everything the
// engagement learned across every enum path). The tab is opt-in — surfaced
// from the ⋮ menu in TabBar for the operator who wants the raw asset views.
import { useEffect, useMemo, useState } from "react";
import {
  getKnownUsers, getKnownHashes, getKnownDomains, getKnownHostnames,
  getKnownHostkeys, getKnownMailAccounts, getKnownOtAssets, getKnownDevices,
  getRelayTargets, getHashlootCategories,
  KnownUsers, KnownHashes, KnownDomains, KnownHostnames, KnownHostkeys,
  KnownMailAccounts, KnownOtAssets, KnownDevices, RelayTargets,
  HashlootCategories,
} from "../api";

type SubTab =
  | "users" | "hashes" | "domains" | "hostnames" | "hostkeys"
  | "mail" | "ot" | "devices" | "relay" | "hashloot";

const SUB_LABEL: Record<SubTab, string> = {
  users: "Users",
  hashes: "Hashes",
  domains: "Domains",
  hostnames: "Hostnames",
  hostkeys: "Host keys",
  mail: "Mail",
  ot: "OT assets",
  devices: "Devices",
  relay: "Relay",
  hashloot: "Hashloot",
};

const SUB_HINT: Record<SubTab, string> = {
  users: "union of user accounts learned across LDAP / SMB / BloodHound / SNMP",
  hashes: "crackable secrets — NT hashes + loot/*.hash files (values truncated)",
  domains: "AD / Kerberos domains (DNS ↔ NetBIOS) with primary selection",
  hostnames: "every DNS / short name learned engagement-wide",
  hostkeys: "SHA256 host-key fingerprints — reused = same key on ≥2 IPs",
  mail: "SMTP / IMAP / POP3 identities — one namespace across all three (RFC 8314)",
  ot: "OT / ICS asset dictionary (vendor / model / serial / firmware)",
  devices: "non-OT device registry — routers, switches, NAS, printers",
  relay: "ntlmrelayx -tf target lines (SMB signing not required, not a DC)",
  hashloot: "hashcat category reference — filename ↔ -m mode ↔ description",
};

const SUB_TABS: SubTab[] = [
  "users", "hashes", "domains", "hostnames", "hostkeys",
  "mail", "ot", "devices", "relay", "hashloot",
];

function useFetch<T>(loader: () => Promise<T>, dep: unknown): {
  data: T | null; err: string | null; loading: boolean;
} {
  const [data, setData] = useState<T | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    let cancelled = false;
    setLoading(true); setErr(null);
    loader()
      .then((d) => { if (!cancelled) { setData(d); setLoading(false); } })
      .catch((e) => { if (!cancelled) { setErr(String(e)); setLoading(false); } });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dep]);
  return { data, err, loading };
}

function useSearch<T>(items: T[], search: string, pick: (t: T) => string): T[] {
  return useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return items;
    return items.filter((it) => pick(it).toLowerCase().includes(q));
  }, [items, search, pick]);
}

function TableWrap({ children }: { children: React.ReactNode }) {
  return <div className="tablewrap">{children}</div>;
}

function Empty({ what }: { what: string }) {
  return <div className="empty">Nothing recorded yet for {what}. Runs an enumeration
    path that produces it (see the sub-tab hint) and it lands here.</div>;
}

function StatusBar({ total, matched, hint, extra }:
  { total: number; matched: number; hint: string; extra?: React.ReactNode }) {
  return (
    <div className="panel-h">
      <h3>{matched === total ? `${total}` : `${matched} / ${total}`} row{total === 1 ? "" : "s"}</h3>
      <span className="muted">{hint}</span>
      {extra}
    </div>
  );
}

// --- sub-views ---------------------------------------------------------------

function UsersView({ search }: { search: string }) {
  const { data, err, loading } = useFetch<KnownUsers>(getKnownUsers, "users");
  if (loading) return <div className="loading">Loading…</div>;
  if (err) return <div className="err">{err}</div>;
  if (!data || data.total === 0) return <Empty what="users" />;
  const rows = useSearch(data.items, search, (u) => u.name);
  return (
    <section className="panel">
      <StatusBar total={data.total} matched={rows.length} hint={SUB_HINT.users}
        extra={data.sources.length > 0 ? (
          <span className="muted">sources: {data.sources.join(", ")}</span>
        ) : null} />
      <TableWrap>
        <table className="loottable">
          <thead><tr><th>User</th></tr></thead>
          <tbody>
            {rows.map((u, i) => (<tr key={i}><td className="mono">{u.name}</td></tr>))}
          </tbody>
        </table>
      </TableWrap>
    </section>
  );
}

function HashesView({ search }: { search: string }) {
  const { data, err, loading } = useFetch<KnownHashes>(getKnownHashes, "hashes");
  if (loading) return <div className="loading">Loading…</div>;
  if (err) return <div className="err">{err}</div>;
  if (!data || data.total === 0) return <Empty what="hashes" />;
  const rows = useSearch(data.items, search, (h) => `${h.user} ${h.domain} ${h.kind} ${h.source}`);
  return (
    <section className="panel">
      <StatusBar total={data.total} matched={rows.length} hint={SUB_HINT.hashes} />
      <TableWrap>
        <table className="loottable">
          <thead><tr>
            <th>User</th><th>Domain</th><th>Kind</th><th>-m</th>
            <th>Source</th><th>Preview</th>
          </tr></thead>
          <tbody>
            {rows.map((h, i) => (
              <tr key={i}>
                <td className="mono">{h.user}</td>
                <td className="mono">{h.domain}</td>
                <td><span className="tag">{h.kind}</span></td>
                <td className="mono">{h.hashcat_mode || ""}</td>
                <td className="mono">{h.source}</td>
                <td className="mono secret">{h.value_preview}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </section>
  );
}

function DomainsView({ search }: { search: string }) {
  const { data, err, loading } = useFetch<KnownDomains>(getKnownDomains, "domains");
  if (loading) return <div className="loading">Loading…</div>;
  if (err) return <div className="err">{err}</div>;
  if (!data || data.total === 0) return <Empty what="domains" />;
  const rows = useSearch(data.items, search, (d) => `${d.dns} ${d.netbios} ${d.sources.join(" ")}`);
  return (
    <section className="panel">
      <StatusBar total={data.total} matched={rows.length} hint={SUB_HINT.domains}
        extra={data.primary_dns || data.primary_netbios ? (
          <span className="muted">primary: {data.primary_dns || data.primary_netbios}</span>
        ) : null} />
      <TableWrap>
        <table className="loottable">
          <thead><tr>
            <th>DNS</th><th>NetBIOS</th><th>Hosts</th><th>Creds</th>
            <th>Sources</th><th></th>
          </tr></thead>
          <tbody>
            {rows.map((d, i) => (
              <tr key={i}>
                <td className="mono">{d.dns || "—"}</td>
                <td className="mono">{d.netbios || "—"}</td>
                <td className="mono">{d.host_count}</td>
                <td className="mono">{d.cred_count}</td>
                <td className="mono">{d.sources.join(", ")}</td>
                <td>{d.is_primary && <span className="tag">primary</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </section>
  );
}

function HostnamesView({ search }: { search: string }) {
  const { data, err, loading } = useFetch<KnownHostnames>(getKnownHostnames, "hostnames");
  if (loading) return <div className="loading">Loading…</div>;
  if (err) return <div className="err">{err}</div>;
  if (!data || data.total === 0) return <Empty what="hostnames" />;
  const rows = useSearch(data.items, search, (n) => n.name);
  // Reverse-index: name -> [ip, ...]
  const nameToIps = useMemo(() => {
    const idx: Record<string, string[]> = {};
    Object.entries(data.by_host).forEach(([ip, names]) => {
      (names || []).forEach((n) => {
        const key = n.toLowerCase();
        (idx[key] = idx[key] || []).push(ip);
      });
    });
    return idx;
  }, [data.by_host]);
  return (
    <section className="panel">
      <StatusBar total={data.total} matched={rows.length} hint={SUB_HINT.hostnames}
        extra={data.capped ? <span className="tag warn">capped @ 500</span> : null} />
      <TableWrap>
        <table className="loottable">
          <thead><tr><th>Name</th><th>Seen on</th></tr></thead>
          <tbody>
            {rows.map((n, i) => {
              const ips = nameToIps[n.name.toLowerCase()] || [];
              return (<tr key={i}>
                <td className="mono">{n.name}</td>
                <td className="mono muted">{ips.join(", ") || "—"}</td>
              </tr>);
            })}
          </tbody>
        </table>
      </TableWrap>
    </section>
  );
}

function HostkeysView({ search }: { search: string }) {
  const { data, err, loading } = useFetch<KnownHostkeys>(getKnownHostkeys, "hostkeys");
  if (loading) return <div className="loading">Loading…</div>;
  if (err) return <div className="err">{err}</div>;
  if (!data || data.total === 0) return <Empty what="host keys" />;
  const rows = useSearch(data.items, search,
    (h) => `${h.fingerprint} ${h.key_type} ${h.endpoints.join(" ")}`);
  return (
    <section className="panel">
      <StatusBar total={data.total} matched={rows.length} hint={SUB_HINT.hostkeys}
        extra={data.reused.length > 0 ? (
          <span className="tag warn">{data.reused.length} reused</span>
        ) : null} />
      <TableWrap>
        <table className="loottable">
          <thead><tr>
            <th>Fingerprint (SHA256)</th><th>Key type</th>
            <th>Endpoints</th><th></th>
          </tr></thead>
          <tbody>
            {rows.map((h, i) => (
              <tr key={i}>
                <td className="mono secret">{h.fingerprint}</td>
                <td className="mono">{h.key_type || "—"}</td>
                <td className="mono">{h.endpoints.join(", ")}</td>
                <td>{h.reused && <span className="tag warn">reused</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </section>
  );
}

function MailView({ search }: { search: string }) {
  const { data, err, loading } = useFetch<KnownMailAccounts>(
    getKnownMailAccounts, "mail");
  if (loading) return <div className="loading">Loading…</div>;
  if (err) return <div className="err">{err}</div>;
  if (!data || data.total === 0) return <Empty what="mail accounts" />;
  const rows = useSearch(data.items, search,
    (a) => `${a.user} ${a.domain} ${a.sources.join(" ")} ${a.hosts.join(" ")}`);
  return (
    <section className="panel">
      <StatusBar total={data.total} matched={rows.length} hint={SUB_HINT.mail} />
      <TableWrap>
        <table className="loottable">
          <thead><tr>
            <th>User</th><th>Domain</th><th>Sources</th><th>Seen on</th>
          </tr></thead>
          <tbody>
            {rows.map((a, i) => (
              <tr key={i}>
                <td className="mono">{a.user}</td>
                <td className="mono">{a.domain || "—"}</td>
                <td className="mono">{a.sources.join(", ")}</td>
                <td className="mono muted">{a.hosts.join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </section>
  );
}

function OtAssetsView({ search }: { search: string }) {
  const { data, err, loading } = useFetch<KnownOtAssets>(getKnownOtAssets, "ot");
  if (loading) return <div className="loading">Loading…</div>;
  if (err) return <div className="err">{err}</div>;
  if (!data || data.total === 0) return <Empty what="OT assets" />;
  const rows = useSearch(data.items, search,
    (a) => `${a.vendor || ""} ${a.model || ""} ${a.serial || ""} ${a.firmware || ""} ${a.protocol || ""}`);
  return (
    <section className="panel">
      <StatusBar total={data.total} matched={rows.length} hint={SUB_HINT.ot} />
      <TableWrap>
        <table className="loottable">
          <thead><tr>
            <th>Vendor</th><th>Model</th><th>Serial</th><th>Firmware</th>
            <th>Protocol</th><th>Sources</th>
          </tr></thead>
          <tbody>
            {rows.map((a, i) => (
              <tr key={i}>
                <td className="mono">{a.vendor || ""}</td>
                <td className="mono">{a.model || ""}</td>
                <td className="mono">{a.serial || ""}</td>
                <td className="mono">{a.firmware || ""}</td>
                <td className="mono">{a.protocol || ""}</td>
                <td className="mono muted">{(a.sources || []).join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </section>
  );
}

function DevicesView({ search }: { search: string }) {
  const { data, err, loading } = useFetch<KnownDevices>(getKnownDevices, "devices");
  if (loading) return <div className="loading">Loading…</div>;
  if (err) return <div className="err">{err}</div>;
  if (!data || data.total === 0) return <Empty what="devices" />;
  const rows = useSearch(data.items, search,
    (d) => `${d.vendor || ""} ${d.model || ""} ${d.firmware || ""} ${d.kind || ""}`);
  return (
    <section className="panel">
      <StatusBar total={data.total} matched={rows.length} hint={SUB_HINT.devices}
        extra={data.cve_candidates.length > 0 ? (
          <span className="tag warn">{data.cve_candidates.length} CVE candidate(s)</span>
        ) : null} />
      <TableWrap>
        <table className="loottable">
          <thead><tr>
            <th>Vendor</th><th>Model</th><th>Firmware</th><th>Kind</th>
            <th>CVEs</th><th>Sources</th>
          </tr></thead>
          <tbody>
            {rows.map((d, i) => (
              <tr key={i}>
                <td className="mono">{d.vendor || ""}</td>
                <td className="mono">{d.model || ""}</td>
                <td className="mono">{d.firmware || ""}</td>
                <td className="mono">{d.kind || ""}</td>
                <td className="mono">{(d.cves || []).map((c) => c.cve).join(", ")}</td>
                <td className="mono muted">{(d.sources || []).join(", ")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </section>
  );
}

function RelayView({ search }: { search: string }) {
  const { data, err, loading } = useFetch<RelayTargets>(getRelayTargets, "relay");
  if (loading) return <div className="loading">Loading…</div>;
  if (err) return <div className="err">{err}</div>;
  if (!data || data.total === 0) return <Empty what="relay targets" />;
  const items = data.items;
  const rows = useSearch(items, search, (r) => r.target);
  function copyAll() {
    const text = items.map((r) => r.target).join("\n") + "\n";
    navigator.clipboard?.writeText(text);
  }
  return (
    <section className="panel">
      <StatusBar total={data.total} matched={rows.length} hint={SUB_HINT.relay}
        extra={<button className="cred-cmd-copy" onClick={copyAll}
                       title="copy the ntlmrelayx -tf file body">📋 copy -tf</button>} />
      <TableWrap>
        <table className="loottable">
          <thead><tr><th>Target</th></tr></thead>
          <tbody>
            {rows.map((r, i) => (<tr key={i}><td className="mono">{r.target}</td></tr>))}
          </tbody>
        </table>
      </TableWrap>
    </section>
  );
}

function HashlootView({ search }: { search: string }) {
  const { data, err, loading } = useFetch<HashlootCategories>(
    getHashlootCategories, "hashloot");
  if (loading) return <div className="loading">Loading…</div>;
  if (err) return <div className="err">{err}</div>;
  if (!data) return <div className="err">no categories</div>;
  const rows = useSearch(data.items, search,
    (c) => `${c.key} ${c.filename} ${c.mode} ${c.description}`);
  return (
    <section className="panel">
      <StatusBar total={data.total} matched={rows.length} hint={SUB_HINT.hashloot} />
      <TableWrap>
        <table className="loottable">
          <thead><tr>
            <th>Key</th><th>Filename</th><th>-m</th><th>Description</th>
          </tr></thead>
          <tbody>
            {rows.map((c, i) => (
              <tr key={i}>
                <td className="mono">{c.key}</td>
                <td className="mono">{c.filename}</td>
                <td className="mono">{c.mode}</td>
                <td>{c.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </section>
  );
}

// --- main --------------------------------------------------------------------

export function KnownAssets() {
  const [sub, setSub] = useState<SubTab>(() => {
    const saved = localStorage.getItem("recce.knownassets.sub");
    return SUB_TABS.includes(saved as SubTab) ? (saved as SubTab) : "users";
  });
  const [search, setSearch] = useState("");

  useEffect(() => {
    localStorage.setItem("recce.knownassets.sub", sub);
    setSearch("");    // fresh filter per view — each surface's shape differs
  }, [sub]);

  return (
    <div className="lootview">
      <section className="panel">
        <div className="panel-h">
          <h3>Known assets</h3>
          <span className="muted">
            what recce has learned across every enumeration path, unioned per surface
          </span>
        </div>
        <div className="creds-filters">
          {SUB_TABS.map((t) => (
            <button
              key={t}
              className={`filter-btn ${sub === t ? "active" : ""}`}
              onClick={() => setSub(t)}
              title={SUB_HINT[t]}
            >
              {SUB_LABEL[t]}
            </button>
          ))}
        </div>
        <div className="creds-search">
          <input
            type="text"
            placeholder="filter rows…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="creds-input"
          />
        </div>
      </section>

      {sub === "users" && <UsersView search={search} />}
      {sub === "hashes" && <HashesView search={search} />}
      {sub === "domains" && <DomainsView search={search} />}
      {sub === "hostnames" && <HostnamesView search={search} />}
      {sub === "hostkeys" && <HostkeysView search={search} />}
      {sub === "mail" && <MailView search={search} />}
      {sub === "ot" && <OtAssetsView search={search} />}
      {sub === "devices" && <DevicesView search={search} />}
      {sub === "relay" && <RelayView search={search} />}
      {sub === "hashloot" && <HashlootView search={search} />}
    </div>
  );
}
