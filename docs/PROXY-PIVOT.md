# Proxy & Pivot Support — design + implementation plan

> **North star:** recce is for the *tester in the field*. Proxy/pivot support exists so an
> operator can reach an internal segment **through a compromised host** and still get the
> same trustworthy enumeration. It must honor the top principle: **a false negative is worse
> than a false positive.** Some traffic *cannot* traverse a SOCKS proxy (UDP, raw-packet
> SYN/masscan scans, ICMP host-discovery). When that happens recce must **say so loudly** —
> never silently skip a probe (a missed finding) and never silently fall back to a direct
> connection (which both misses the internal target *and* leaks the operator's real source
> IP past the pivot). Read `docs/ARCHITECTURE.md` first.

---

## 1. Goal & scope

**Use case.** The operator has a foothold on host `A` inside the target network and stands up
a SOCKS proxy that exits through `A` — via Metasploit (`socks_proxy` + `route`), `chisel`,
`ligolo-ng`, `sshuttle`, or a plain `ssh -D`. They then point recce at that SOCKS port so
every scan and probe reaches the internal `10.x` segment as if recce were running on `A`.

**recce is SOCKS-*aware*, it does not build tunnels.** Establishing the pivot (msf route,
chisel server/client, ligolo) is the operator's job and is tool-specific; recce's
responsibility is simply to send all its outbound traffic through a SOCKS endpoint the
operator supplies. This keeps the feature small, stdlib-only, and airgap-friendly — no new
dependency, no tunnel-management surface.

**In scope:** SOCKS5 (+ SOCKS4a) for every stdlib socket/HTTP probe; `proxychains`-style
prefixing for the external tools recce shells out to; honest handling + surfacing of the
traffic that can't be proxied.

**Out of scope (v1):** building the tunnel; HTTP CONNECT proxies (add later if needed);
per-target proxy chains (one proxy for the whole run to start).

---

## 2. The network surface recce has to cover

Grounded inventory of every place recce currently touches the network (this is what a proxy
layer must intercept — nothing more, nothing less):

| Path | Primitive | Sites | Modules |
|------|-----------|-------|---------|
| **TCP probes** | `socket.create_connection` | 19 | ftp, nfs, ldap, mongodb, kerberos, redis, rsync, smb, mssql, svcdetect, probes |
| **HTTP/S probes** | `http.client.HTTP(S)Connection` | 12 | web, probes, docker, elasticsearch, kubernetes |
| **UDP probes** | `socket.socket(SOCK_DGRAM)` | 3 | snmp (161), mssql (SQL Browser 1434), stager |
| **Tool shell-outs** | `subprocess.run` | ~6 | scanner (nmap), util.run_tool (netexec/impacket/bloodhound), ad, deploy, mssql, exploits |
| **Local render (EXCLUDE)** | `subprocess.run` | 3 | screenshot (wkhtmltoimage/chromium — never proxy this) |

Two happy facts fall out of the earlier de-bloat work:

- The TCP probes almost all go through **one primitive** (`socket.create_connection`), so a
  single wrapper covers 19 sites.
- The tool shell-outs already funnel through **two chokepoints** (`scanner._run` for nmap and
  `util.run_tool` for everything else) — the exact seams the de-bloat consolidated. Proxy
  prefixing hooks there once, not in six commands.

---

## 3. Design

### 3.1 A single `net` module (the one home for outbound connections)

Create `recce/net.py`. Every module stops calling `socket.create_connection` /
`http.client.*` directly and calls `net` instead. `net` decides direct-vs-proxied from a
process-global config.

```python
# recce/net.py  (stdlib only)
_PROXY = None   # set once at startup; None => everything behaves exactly as today

def configure(proxy: str | None) -> None:
    """Parse & store the proxy for the whole run, e.g. 'socks5://127.0.0.1:1080'.
    socks5h:// = remote DNS (default & recommended); socks4a:// supported."""

def create_connection(address, timeout=None, source_address=None):
    """Drop-in for socket.create_connection. Direct when no proxy; else opens a TCP
    socket to the SOCKS server and performs the CONNECT handshake to `address`."""

def http_connection(host, port, *, tls=False, timeout=None, context=None):
    """Return an http.client.HTTP(S)Connection whose .connect() tunnels via the proxy
    (set conn.sock to the SOCKS-tunneled socket; wrap in ssl for tls=True)."""

def udp_socket():
    """Raise ProxyUnsupported when a proxy is configured (SOCKS TCP can't carry UDP),
    so callers surface it honestly instead of leaking a direct packet."""
```

**Config propagation.** Deep probes (`probes`, `svcdetect`, the service modules) are called
without `args`, so the proxy is a **module-global set once at startup** — the same idiom
`cli._DEFER_REPORTS` already uses. `cmd_*` entry points (or `main`) call `net.configure(args.proxy)`
before any probing. No threading a `proxy=` kwarg through dozens of call signatures.

### 3.2 Hand-rolled SOCKS (stdlib, ~80 lines)

No third-party `PySocks` (airgap + stdlib-only constraint). Implement the minimal client:

- **SOCKS5**: version/method greeting (`0x05` + no-auth `0x00`, plus username/password `0x02`
  when the URL carries creds) → `CONNECT` (0x01) with either an IPv4 (0x01) or a **domain
  name** (0x03) address → parse the bind reply / error code.
- **SOCKS4a**: `CONNECT` with `0.0.0.1` sentinel + trailing hostname for remote DNS.
- **Remote DNS by default** (`socks5h`): pass the *hostname* to the proxy, never pre-resolve
  locally. This avoids DNS leaks and — more importantly — resolves internal names
  (`dc.corp.local`, Kerberos realms, `ldap://…`) that only the pivot can see. recce mostly
  targets IPs, but AD/LDAP/Kerberos paths use names, so this matters.

Map SOCKS reply codes to clear errors (`host unreachable`, `connection refused`, `TTL
expired`) so a failed internal probe reads as a real result, not a mystery.

### 3.3 Tool shell-outs → proxychains

nmap, netexec, impacket, bloodhound-python, etc. have no native SOCKS; the standard field
answer is `proxychains4`. Prefix at the two chokepoints only:

- `scanner._run(cmd)` and `util.run_tool(cmd)` prepend `proxychains4 -f <generated.conf>`
  (or `-q` for quiet) when a proxy is set. recce writes a throwaway proxychains conf from
  `--proxy` into the engagement dir.
- **`screenshot.py` is explicitly excluded** — it renders proof images locally; proxying it
  would break rendering and pointlessly route local traffic.

### 3.4 nmap over a proxy — the profile MUST change (correctness, not preference)

proxychains only intercepts libc `connect()` calls. Anything using raw packets or non-TCP
silently bypasses it — which, unhandled, means scanning from the operator's real IP. So when
a proxy is active, `scanner` must force a proxy-safe nmap profile and **refuse the unsafe
bits**:

- **Force `-sT`** (TCP connect). A SYN scan (`-sS`) uses raw packets → bypasses proxychains.
- **Force `-Pn`** (already used for port scans) and **skip ICMP/UDP host-discovery**
  (`-sn -PE -PP` / `-PU`) — ICMP and UDP don't traverse SOCKS. Discovery becomes TCP-connect
  based, through the proxy.
- **Disable masscan** — raw-packet engine, cannot be proxied at all; fall back to nmap `-sT`
  (recce already has a masscan→nmap fallback path to reuse).
- **Drop `-sU`** UDP scans while proxied (see §4).
- Keep `-n` (proxy does remote DNS).

This is a documented, operator-visible shift ("proxy mode → connect scan, no masscan, no UDP"),
not a silent downgrade.

---

## 4. Honesty & limitations (the north-star part)

Everything that **cannot** go through the proxy is surfaced, never hidden:

- **UDP probes** (SNMP 161, SQL Browser 1434, UDP host-discovery, `-sU`): SOCKS TCP can't
  carry them. `net.udp_socket()` raises `ProxyUnsupported`; each caller logs a **scan issue**
  ("SNMP skipped — UDP can't traverse the SOCKS proxy; run it from the pivot host directly")
  rather than returning "no finding". A clean "0 SNMP" while proxied would be a false
  negative; the warning prevents that misread.
- **Raw-packet scans** (SYN, masscan): auto-swapped to `-sT` with a one-line notice.
- **ICMP discovery**: replaced by `-Pn` + TCP discovery, noted.
- **No silent direct fallback, ever.** If the proxy is set and a connection can't be
  tunneled, it **fails loudly** — recce must never quietly connect direct (that leaks the
  operator's real source IP past the pivot and is an OPSEC failure, not just a bug).
- **A persistent "PROXY: socks5://… (connect-scan mode, UDP disabled)" banner** on every
  command and in the report header, so results are always read in the right context.
- **Timeouts scale** — proxied + multi-hop connections are slower; apply a proxy latency
  multiplier to probe timeouts so slow-but-alive internal hosts aren't misread as down.

---

## 5. CLI surface

A single global option (added to the shared arg groups, like `_add_common`):

```
--proxy socks5h://[user:pass@]HOST:PORT   route all probes + tools through this SOCKS proxy
--proxy socks4a://HOST:PORT               (SOCKS4a also supported)
```

- Accepts `socks5` / `socks5h` (remote DNS) / `socks4a`. `socks5h` is the recommended/default
  resolution behavior.
- On startup: parse → `net.configure()` → write proxychains conf → print the proxy banner →
  probe the SOCKS port once and **fail fast with a clear message if it's unreachable** (don't
  start a whole engagement against a dead tunnel).
- Optional `--proxy-check` doctor sub-check: verify the SOCKS endpoint answers and that
  `proxychains4` is installed (gate the tool half of the feature honestly).

---

## 6. Staged rollout (each stage ships independently, tool usable throughout)

- **P1 — `net` module + TCP probes.** Build `recce/net.py` (config + SOCKS5/4a + proxy-aware
  `create_connection`), migrate the 19 `create_connection` sites, add `--proxy`, banner,
  startup reachability check. Ships: every raw-socket service probe (ftp/smb/ldap/mongodb/
  redis/rsync/nfs/mssql/kerberos + svcdetect/probes banner grabs) works through a pivot.
  Test with a stdlib SOCKS server.
- **P2 — HTTP/S probes.** `net.http_connection`; migrate the 12 `HTTP(S)Connection` sites
  (web/api/docker/elasticsearch/kubernetes/probes). Ships: web + API enum through the pivot.
- **P3 — tool shell-outs + nmap profile.** proxychains prefixing at `scanner._run` /
  `util.run_tool`; the forced `-sT -Pn`, no-masscan, no-`-sU` proxy profile; exclude
  screenshot. Ships: the full scan + credentialed tooling through the pivot.
- **P4 — UDP honesty + polish.** `ProxyUnsupported` + scan-issue surfacing for SNMP/SQL-
  Browser/UDP-discovery, report-header banner, timeout scaling, `--proxy-check` doctor.

Order rationale: P1 covers the largest, cleanest chunk (one primitive, 19 sites) and proves
the SOCKS core end-to-end; P4 (the honesty layer) lands last because it depends on the earlier
paths knowing they're proxied.

---

## 7. Testing (offline, deterministic)

- **SOCKS handshake unit tests** — encode/parse SOCKS5 greeting/CONNECT/reply and SOCKS4a,
  including error codes, against hand-built byte vectors (mirrors the existing
  `wire_vectors.py` style).
- **A tiny stdlib SOCKS5 server in-test** (thread + loopback, like the HTTPS-probe test) to
  prove `net.create_connection` and `net.http_connection` actually tunnel: point recce probes
  at a loopback service *via* the test proxy and assert the same result as direct.
- **UDP-while-proxied** asserts `ProxyUnsupported` is raised and the caller logs a scan issue
  (not a clean zero).
- **No-proxy regression**: with `--proxy` unset, `net.create_connection` must be a
  byte-for-byte behavioral no-op over today's direct path (the whole existing suite is the
  guard).

---

## 8. Open questions / decisions to confirm

1. **HTTP CONNECT proxies** (corporate/Burp-style) in addition to SOCKS — needed, or SOCKS-
   only for v1? (Pivots are almost always SOCKS; leaning SOCKS-only first.)
2. **proxychains dependency** — assume `proxychains4` present on the Kali box (doctor-gated),
   or also offer nmap-native `--proxies socks4://…` where nmap supports it (nmap's SOCKS
   support is partial/`-sT`-only)?
3. **Per-target vs whole-run proxy** — v1 is one proxy for the run. Worth a `--proxy-scope`
   later for multi-segment engagements?
4. **ligolo-ng note** — ligolo uses a TUN, not SOCKS, so recce needs no special support there
   (traffic is transparently routed by the OS). Document as "no proxy flag needed with
   ligolo" so operators don't double-configure.
