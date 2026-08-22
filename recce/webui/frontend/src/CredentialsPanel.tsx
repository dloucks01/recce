import { useState, useEffect } from "react";

interface Credential {
  username?: string;
  password?: string;
  hash?: string;
  domain?: string;
  source?: string;
  looted_by?: string;
}

export function CredentialsPanel() {
  const [creds, setCreds] = useState<Credential[]>([]);
  const [filter, setFilter] = useState<"all" | "cleartext" | "hashes">("all");
  const [search, setSearch] = useState("");

  useEffect(() => {
    // Fetch credentials from API
    async function loadCreds() {
      try {
        const res = await fetch("/api/creds");
        const data = await res.json();
        setCreds(data || []);
      } catch {
        setCreds([]);
      }
    }
    loadCreds();
  }, []);

  let filtered = creds;
  if (filter === "cleartext") filtered = creds.filter((c) => c.password);
  else if (filter === "hashes") filtered = creds.filter((c) => c.hash);

  if (search.trim()) {
    const q = search.toLowerCase();
    filtered = filtered.filter(
      (c) =>
        c.username?.toLowerCase().includes(q) ||
        c.domain?.toLowerCase().includes(q) ||
        c.source?.toLowerCase().includes(q)
    );
  }

  const cleartextCount = creds.filter((c) => c.password).length;
  const hashCount = creds.filter((c) => c.hash).length;

  return (
    <div className="creds-panel">
      <div className="creds-search">
        <input
          type="text"
          placeholder="Search username, domain, source..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="creds-input"
        />
      </div>

      <div className="creds-filters">
        <button className={`filter-btn ${filter === "all" ? "active" : ""}`} onClick={() => setFilter("all")}>
          All ({creds.length})
        </button>
        <button
          className={`filter-btn ${filter === "cleartext" ? "active" : ""}`}
          onClick={() => setFilter("cleartext")}
        >
          Cleartext ({cleartextCount})
        </button>
        <button
          className={`filter-btn ${filter === "hashes" ? "active" : ""}`}
          onClick={() => setFilter("hashes")}
        >
          Hashes ({hashCount})
        </button>
      </div>

      <div className="creds-list">
        {filtered.length === 0 ? (
          <div className="empty-state">No credentials found</div>
        ) : (
          filtered.map((c, i) => (
            <div key={i} className={`cred-item ${c.password ? "cleartext" : "hash"}`}>
              <div className="cred-header">
                <span className="cred-username">{c.username || "(no username)"}</span>
                {c.domain && <span className="cred-domain">@{c.domain}</span>}
              </div>
              <div className="cred-body">
                {c.password && (
                  <div className="cred-secret">
                    <span className="cred-label">Password:</span>
                    <code className="cred-value">{c.password}</code>
                  </div>
                )}
                {c.hash && (
                  <div className="cred-secret">
                    <span className="cred-label">Hash:</span>
                    <code className="cred-value cred-hash">{c.hash.slice(0, 40)}…</code>
                  </div>
                )}
              </div>
              <div className="cred-footer">
                {c.source && <span className="cred-source">from {c.source}</span>}
                {c.looted_by && <span className="cred-by">looted by {c.looted_by}</span>}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
