import { useState, useEffect } from "react";
import { deleteCredential as apiDeleteCredential } from "./api";
import { toast } from "./toast";

interface Credential {
  username: string;
  secret: string;
  kind: string;
  domain: string;
  source: string;
  origin_ip: string;
  notes: string;
  label: string;
}

export function CredentialsPanel() {
  const [creds, setCreds] = useState<Credential[]>([]);
  const [filter, setFilter] = useState<"all" | "cleartext" | "hashes">("all");
  const [search, setSearch] = useState("");

  useEffect(() => {
    async function loadCreds() {
      try {
        const res = await fetch("/api/credentials");
        const data = await res.json();
        setCreds(data?.items || []);
      } catch {
        setCreds([]);
      }
    }
    loadCreds();
  }, []);

  let filtered = creds;
  if (filter === "cleartext") filtered = creds.filter((c) => c.kind === "password");
  else if (filter === "hashes") filtered = creds.filter((c) => c.kind === "nthash" || c.kind === "hash");

  if (search.trim()) {
    const q = search.toLowerCase();
    filtered = filtered.filter(
      (c) =>
        c.username?.toLowerCase().includes(q) ||
        c.domain?.toLowerCase().includes(q) ||
        c.source?.toLowerCase().includes(q) ||
        c.label?.toLowerCase().includes(q)
    );
  }

  const cleartextCount = creds.filter((c) => c.kind === "password").length;
  const hashCount = creds.filter((c) => c.kind === "nthash" || c.kind === "hash").length;

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
            <div key={i} className={`cred-item ${c.kind === "password" ? "cleartext" : "hash"}`}>
              <div className="cred-header">
                <span className="cred-username">{c.label || c.username || "(no username)"}</span>
                {c.domain && <span className="cred-domain">@{c.domain}</span>}
              </div>
              <div className="cred-body">
                <div className="cred-secret">
                  <span className="cred-label">{c.kind === "password" ? "Password:" : c.kind === "nthash" ? "NT Hash:" : "Hash:"}</span>
                  <code className="cred-value">{c.kind !== "password" ? (c.secret || "").slice(0, 40) + (c.secret?.length > 40 ? "..." : "") : c.secret || "—"}</code>
                </div>
              </div>
              <div className="cred-footer">
                {c.source && <span className="cred-source">from {c.source}</span>}
                {c.origin_ip && <span className="cred-by">on {c.origin_ip}</span>}
                <button className="btn danger sm cred-delete"
                        title="Permanently delete this credential from the store"
                        onClick={async () => {
                          const label = c.label || c.username || "(unlabeled)";
                          if (!confirm(`Delete credential "${label}"? This is permanent.`)) return;
                          try {
                            await apiDeleteCredential({
                              username: c.username || "",
                              secret: c.secret || "",
                              kind: c.kind || "password",
                              domain: c.domain || "",
                            });
                            setCreds((prev) => prev.filter((_, j) => j !== i));
                            toast.show("Credential deleted");
                          } catch (e) {
                            toast.show(`Delete failed: ${(e as Error).message}`);
                          }
                        }}>
                  Delete
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
