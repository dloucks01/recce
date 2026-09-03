# Proxy & Pivot Support

recce is **proxy-safe** and **proxy-honest**: never scan from the real IP (OPSEC), never report clean results for traffic that couldn't traverse the proxy (false negatives).

## Already handled

- **proxychains** hooks `connect()` — all stdlib TCP/HTTP probes route through SOCKS/CONNECT transparently
- **Transparent tunnels** (ligolo-ng TUN, sshuttle, msf autoroute) make subnets OS-routable; recce just works

## What only recce can fix

1. **OPSEC failure** — SYN/masscan raw packets bypass proxychains, hit targets from real IP
2. **Silent UDP misses** — SNMP/SQL-Browser can't traverse TCP proxies, fails silently → false "0 findings"

## Network surface

| Path | Primitive | proxychains? | recce's job |
|---|---|---|---|
| TCP probes | `socket.create_connection` (19 sites) | Yes | nothing |
| HTTP/S probes | `http.client.HTTP(S)Connection` (12 sites) | Yes | nothing |
| UDP probes | `socket.socket(SOCK_DGRAM)` (3 sites) | No | flag honestly |
| nmap | `subprocess` | Connect-scan only; SYN/masscan/ICMP/UDP bypass | force safe profile |
| Other tools | `subprocess` | Yes (children inherit hook) | nothing |

## Design (v1 — shipped)

**`--proxy` guarantees proxied execution.** If not already under proxychains, recce re-execs itself under `proxychains4` with a generated conf. Sentinel env var prevents loops. Auto-detects existing wrap via `LD_PRELOAD`.

**Proxy-safe nmap profile.** When proxied, `scanner` forces `-sT` (connect, not raw SYN), `-Pn` (skip ICMP/UDP discovery), no masscan, no `-sU`.

**Honesty layer.** UDP probes skipped with logged scan issue. Persistent `PROXY: socks5h://… (connect-scan mode, UDP disabled)` banner on commands and reports. `proxy.scaled()` latency multiplier prevents slow hops being misread as down.

**CLI:**
```
--proxy socks5h://[user:pass@]HOST:PORT
--proxy socks4a://HOST:PORT
--proxy http://[user:pass@]HOST:PORT
```
Startup: parse -> write proxychains conf -> re-exec if needed -> probe reachability -> print banner. `doctor` gates `proxychains4` availability.

## Status

- **P1 — awareness + safety + honesty**: Shipped. `--proxy` re-exec, safe nmap profile, UDP skip-and-warn, proxy banner in MD/HTML/XLSX, `proxy.scaled()`, 35 tests.
- **P2 — native `recce/net.py`**: Optional stdlib SOCKS5/CONNECT client so `--proxy` works without proxychains. Only if P1's dependency proves annoying.

## Open items

- Per-target / multi-hop proxy (v1 is single proxy per run)
- ligolo-ng docs ("no `--proxy` needed with ligolo")
