import { useState, useCallback } from "react";
import { useCollab } from "./collab";

interface Host {
  ip: string;
  hostname?: string;
  reviewed: boolean;
}

export function AssignmentsPanel({ hosts }: { hosts: Host[] }) {
  const { c, me, assign } = useCollab();
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<"mine" | "unclaimed" | "all">("mine");

  const myHosts = hosts.filter((h) => c.assignments[h.ip] === me);
  const unclaimedHosts = hosts.filter((h) => !c.assignments[h.ip]);
  const allAssigned = hosts.filter((h) => c.assignments[h.ip]);

  let displayed: Host[] = [];
  if (filter === "mine") displayed = myHosts;
  else if (filter === "unclaimed") displayed = unclaimedHosts;
  else displayed = allAssigned;

  if (search.trim()) {
    const q = search.toLowerCase();
    displayed = displayed.filter((h) => h.ip.includes(q) || h.hostname?.toLowerCase().includes(q));
  }

  const handleClaim = useCallback(
    (ip: string) => {
      assign(ip, me);
    },
    [assign, me]
  );

  const handleRelease = useCallback(
    (ip: string) => {
      assign(ip, "");
    },
    [assign]
  );

  return (
    <div className="assignments-panel">
      <div className="assign-search">
        <input
          type="text"
          placeholder="Search hosts..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="assign-input"
        />
      </div>

      <div className="assign-filters">
        <button
          className={`filter-btn ${filter === "mine" ? "active" : ""}`}
          onClick={() => setFilter("mine")}
        >
          My hosts ({myHosts.length})
        </button>
        <button
          className={`filter-btn ${filter === "unclaimed" ? "active" : ""}`}
          onClick={() => setFilter("unclaimed")}
        >
          Unclaimed ({unclaimedHosts.length})
        </button>
        <button
          className={`filter-btn ${filter === "all" ? "active" : ""}`}
          onClick={() => setFilter("all")}
        >
          All ({allAssigned.length})
        </button>
      </div>

      <div className="assign-list">
        {displayed.length === 0 ? (
          <div className="empty-state">No hosts</div>
        ) : (
          displayed.map((h) => {
            const owner = c.assignments[h.ip];
            const isMine = owner === me;
            const status = h.reviewed ? "✓" : "○";

            return (
              <div key={h.ip} className={`assign-item ${isMine ? "mine" : ""}`}>
                <div className="item-header">
                  <span className="item-status">{status}</span>
                  <span className="item-ip">{h.ip}</span>
                  {h.hostname && <span className="item-name">{h.hostname}</span>}
                </div>
                <div className="item-footer">
                  {owner ? (
                    <>
                      <span className="item-owner">
                        Claimed by <strong>{owner === me ? "you" : owner}</strong>
                      </span>
                      {isMine && (
                        <button className="release-btn" onClick={() => handleRelease(h.ip)}>
                          Release
                        </button>
                      )}
                    </>
                  ) : (
                    <button className="claim-btn" onClick={() => handleClaim(h.ip)}>
                      Claim
                    </button>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
