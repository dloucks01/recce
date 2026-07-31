# Proxy & Pivot Support — design + implementation plan

> **North star:** recce is for the *tester in the field*. When they pivot through a
> compromised host into an internal segment, recce's job is **not** to be a networking
> library — the operator's proxychains/tunnel already moves the packets. recce's job is to
> make itself **proxy-safe** and **proxy-honest**: never scan from the operator's real IP by
> accident (an OPSEC failure), and never report a misleading clean result for traffic that
> silently couldn't traverse the proxy (a false negative — the top principle). Read
> `docs/ARCHITECTURE.md` first.

---

## 1. The real question: what does recce actually add?

Before writing any networking code, be honest about what's *already handled*:

- **proxychains already proxies recce's own probes, transparently.** proxychains `LD_PRELOAD`-
  hooks libc `connect()`, and every one of recce's stdlib probes (`socket.create_connection`,
  `http.client`) bottoms out in that call. So `proxychains4 recce scan 10.x` routes all of
  recce's TCP/HTTP enumeration through a SOCKS/CONNECT pivot **today, with zero code changes.**
- **Transparent tunnels need recce to do nothing at all.** ligolo-ng (TUN), `sshuttle`, msf
  `autoroute` + a local redirect — these make the internal subnet OS-routable, so
  `recce scan 10.x` just works. This covers a large and growing share of real pivoting.

So the transport problem — "get recce's packets to the internal segment" — is **already solved
for the operator.** Building a from-scratch SOCKS stack would mostly re-implement proxychains.

**What is NOT solved, and only recce can fix, are two failures that bare `proxychains4 recce`
walks straight into:**

1. **OPSEC failure — scanning from the real IP.** recce doesn't know it's proxied, so it runs
   a SYN scan / masscan. Those use raw packets, **bypass proxychains entirely**, and hit the
   target from the operator's actual source IP — the exact thing the pivot exists to avoid.
2. **False negative — silent UDP misses.** SNMP / SQL-Browser / UDP host-discovery go over
   UDP, which can't traverse a TCP proxy. Under bare proxychains they just fail silently → a
   clean, misleading "0 findings."

**recce's value is closing those two gaps — proxy *awareness*, *safety*, and *honesty* — not
transport.** That reframes the whole feature from "a networking library" to "a thin safety
layer over the transport the operator already has."

---

## 2. Scope

**In scope (v1) — the awareness/safety/honesty layer:**

- A `--proxy` flag that makes recce **guarantee** it's proxied (§4.1), flip nmap into a
  **proxy-safe profile** (§4.2), and turn on the **honesty layer** for traffic that can't
  tunnel (§4.3), plus a persistent PROXY banner.
- Transport is delegated to **proxychains4** (which speaks SOCKS4/5 *and* HTTP CONNECT), so no
  new networking code and both proxy kinds are covered for free.

**Optional / later (only if the proxychains dependency proves annoying):**

- A native stdlib `recce/net.py` (SOCKS5/4a + HTTP CONNECT) so `recce --proxy` self-contains
  transport with no proxychains and gives per-probe UDP honesty (§5). Deliberately *not* the
  headline.

**Out of scope (v1):** building the tunnel itself; per-target / multi-hop proxy chains.

---

## 3. The network surface — what proxychains covers vs. what needs recce's help

Grounded inventory of every place recce touches the network, split by whether the operator's
proxychains wrapper already handles it or recce must intervene:

| Path | Primitive | Sites | proxychains handles it? | recce's job |
|------|-----------|-------|------------------------|-------------|
| **TCP probes** | `socket.create_connection` | 19 | ✅ transparent (`connect()` hook) | nothing (v1) |
| **HTTP/S probes** | `http.client.HTTP(S)Connection` | 12 | ✅ transparent | nothing (v1) |
| **UDP probes** | `socket.socket(SOCK_DGRAM)` | 3 | ❌ can't tunnel UDP | **flag honestly** |
| **nmap** | `subprocess` (scanner._run) | 1 | ⚠️ connect-scan only; SYN/masscan/ICMP/UDP **bypass** | **force `-sT -Pn`, no masscan/`-sU`** |
| **Other tools** | `subprocess` (util.run_tool) | ~5 | ✅ children inherit the hook | nothing (v1) |
| **Local render** | `subprocess` (screenshot) | 3 | n/a — local | **never proxy** |

The two subprocess chokepoints (`scanner._run`, `util.run_tool`) that the earlier de-bloat
consolidated are also where any re-exec / prefixing logic hooks — one place each.

---

## 4. Design — the awareness / safety / honesty layer (v1)

### 4.1 `--proxy` guarantees recce is proxied (via proxychains)

`recce scan 10.x --proxy socks5h://127.0.0.1:1080` must guarantee that **every** byte recce
sends — its Python probes *and* its tool children — goes through the proxy. The clean way to
do that without any transport code:

- On startup, if `--proxy` is set and recce is **not already running under proxychains**
  (detected via `LD_PRELOAD` / an env sentinel), recce **re-executes itself under
  proxychains4**: it writes a throwaway proxychains conf from the `--proxy` URL into the
  engagement dir and `os.execvp("proxychains4", ["proxychains4", "-f", conf, "recce", …same
  argv…])`, with a sentinel env var to prevent a re-exec loop.
- After the re-exec, the whole process tree (recce's `connect()` probes + every nmap/netexec/
  impacket child) is transparently tunneled. recce then runs in proxy-safe + honest mode.
- If recce is *already* wrapped (`proxychains4 recce --proxy …`), it skips the re-exec and just
  enables safe/honest mode — no double-wrapping.
- **Nice-to-have:** auto-detect the proxychains `LD_PRELOAD` even without `--proxy` and enable
  safe mode with a "recce noticed it's under proxychains" notice, so a wrapped run can't
  accidentally SYN-scan from the real IP.

This gives full SOCKS + HTTP CONNECT transport (proxychains does both) for **zero** networking
code in recce. proxychains is gated by `doctor` / `--proxy-check` with a clear message if
missing.

### 4.2 Proxy-safe nmap profile (the core safety win)

proxychains only intercepts `connect()`. Anything raw-packet or non-TCP silently bypasses it
and goes out the real interface. So when proxied, `scanner` **forces** a safe profile and
**refuses** the unsafe engines — this is correctness, not preference:

- **Force `-sT`** (TCP connect). SYN (`-sS`) uses raw packets → bypasses the proxy.
- **Force `-Pn`** (already used for port scans) and **skip ICMP/UDP host-discovery**
  (`-sn -PE -PP` / `-PU`) — neither traverses the proxy; discovery becomes TCP-connect based.
- **Disable masscan** — raw-packet engine, cannot be proxied at all → fall back to nmap `-sT`
  (recce already has that fallback path).
- **Drop `-sU`** UDP scans (see §4.3). Keep `-n` (proxy does remote DNS).

Operator-visible ("proxy mode → connect scan, no masscan, no UDP"), never a silent downgrade.

### 4.3 Honesty layer — surface what can't tunnel

- **UDP probes** (SNMP 161, SQL-Browser 1434, UDP discovery, `-sU`): each is skipped with a
  logged **scan issue** — e.g. *"SNMP skipped: UDP can't traverse the proxy; run it from the
  pivot host directly."* A clean "0 SNMP" while proxied would be a false negative; the warning
  prevents the misread.
- **Raw-packet scans** auto-swapped to `-sT` with a one-line notice; **ICMP discovery** →
  `-Pn` + TCP, noted.
- **A persistent "PROXY: socks5h://… (connect-scan mode, UDP disabled)" banner** on every
  command and in the report header, so results are always read in the right context.
- **Timeouts scale** — proxied/multi-hop is slower; apply a latency multiplier so slow-but-
  alive internal hosts aren't misread as down.

### 4.4 Config propagation

The proxy state is a **process-global set once at startup** (the same idiom `cli._DEFER_REPORTS`
already uses) — `scanner` reads it to pick the safe profile, the UDP call sites read it to
decide skip-and-warn, the report header reads it for the banner. No threading a `proxy=` kwarg
through dozens of probe signatures.

---

## 5. Optional (later): native `recce/net.py` — transport without proxychains

Only worth building if the proxychains-wrap UX proves annoying, or to run on a box without
proxychains. It would let `recce --proxy` self-contain transport and give **per-probe** UDP
honesty instead of relying on nmap-level handling.

- Stdlib `recce/net.py`: SOCKS5 (+ SOCKS4a, remote DNS via `socks5h`) **and HTTP CONNECT**,
  scheme-driven and proxy-agnostic downstream; a proxy-aware `create_connection` +
  `http_connection` factory; `udp_socket()` that raises `ProxyUnsupported` when proxied.
- Migrate the 19 `create_connection` and 12 `HTTP(S)Connection` sites onto it.
- With `--proxy` unset it is a byte-for-byte no-op over today's direct path (the whole existing
  suite is the guard).

This is the part of the *original* design that mostly duplicated proxychains — hence demoted
to optional. Ship §4 first and see whether it's even wanted.

---

## 6. CLI surface

```
--proxy socks5h://[user:pass@]HOST:PORT   pivot through this proxy (re-execs under proxychains)
--proxy socks4a://HOST:PORT               SOCKS4a
--proxy http://[user:pass@]HOST:PORT      HTTP CONNECT (Burp / corporate web proxy)
```

- Scheme selects the proxy kind; proxychains4 handles all three, so the generated conf mirrors
  whatever `--proxy` is set — probe half and tool half stay consistent.
- On startup: parse → write proxychains conf → (re-exec if not already wrapped) → **probe the
  proxy once and fail fast with a clear message if it's unreachable** (don't launch a whole
  engagement against a dead tunnel) → print the PROXY banner.
- `doctor` / `--proxy-check`: verify `proxychains4` is installed and the proxy endpoint
  answers — gate the feature honestly.

---

## 7. Staged rollout (each stage ships independently)

- **P1 — awareness + safety + honesty (the whole valuable core).** `--proxy` re-exec-under-
  proxychains + proxychains conf generation + reachability check; the forced proxy-safe nmap
  profile (§4.2); the UDP skip-and-warn + report banner + timeout scaling (§4.3); doctor check.
  Ships the complete field capability leaning on proxychains for transport. **Small — mostly
  scanner-profile + CLI + honesty wiring, little-to-no new network code.**
- **P2 — (optional) native `recce/net.py`.** Only if P1's proxychains dependency/UX warrants
  it: the stdlib SOCKS/CONNECT client + the 19+12 site migration, so `recce --proxy` works with
  no proxychains and gains per-probe UDP honesty.

Order rationale: P1 is the part only recce can do and carries the real field value (no real-IP
leak, no silent UDP miss). P2 is a transport nicety that competes with a tool the operator
already has — build it on demand, not on spec.

---

## 8. Testing (offline, deterministic)

- **Safe-profile unit tests** — with the proxy global set, assert `scanner` emits `-sT -Pn`,
  no `-sS`, no masscan, no `-sU`, and that host-discovery drops ICMP.
- **Honesty tests** — a UDP probe (SNMP) while proxied logs a scan issue rather than returning
  a clean zero; the report header carries the PROXY banner.
- **Re-exec logic** — the LD_PRELOAD/sentinel detection picks "already wrapped" vs "need
  re-exec" correctly, with the loop guard (test the decision function, not an actual exec).
- **No-proxy regression** — with `--proxy` unset, every path is byte-for-byte today's behavior
  (the whole existing suite guards this).
- **(P2 only)** stdlib SOCKS5 test server + handshake byte-vector tests (mirrors
  `wire_vectors.py`), proving `net.create_connection` tunnels to a loopback service.

---

## 9. Decisions & notes

**Decided (2026-07-30):**

1. ✅ **Value is safety + honesty, not transport.** Transport is already handled by proxychains
   (transparent `connect()` hook) and by transparent tunnels (ligolo/sshuttle need nothing). v1
   is the thin safety/honesty layer; native SOCKS is demoted to optional P2.
2. ✅ **Proxy types — SOCKS + HTTP CONNECT**, both delivered via proxychains4 (which speaks
   all three schemes), so v1 supports them with no per-kind code.
3. ✅ **Tool proxying — proxychains4**, doctor-gated. The re-exec model extends the same
   proxychains transport to recce's own probes, so one mechanism covers everything.

**Still open (don't block P1):**

4. **Per-target / multi-hop proxy** — v1 is one proxy for the run; a `--proxy-scope` for multi-
   segment engagements could come later.
5. **ligolo-ng** — TUN, not SOCKS; the OS routes transparently, so recce needs no flag. Document
   as "no `--proxy` needed with ligolo" so operators don't double-configure.
