"""LPD (515/tcp) + CUPS/IPP printer-stack extensions.

Two protocol families that share one operational surface (print servers):

  * LPD / RFC 1179 on 515/tcp - single-byte opcodes + LF-terminated ASCII
    args. Queue listings (op 03 / op 04) are unauthenticated on every stock
    BSD lpd / LPRng / cups-lpd shim and leak owner + source host + filename
    tuples. Also fingerprints LPRng / BSD lpd / HP JetDirect / cups-lpd /
    Windows LPD from the response text so LPD-family CVEs can be cited only
    when they actually apply.

  * cups-browsed on 631/udp - the ingress path of CVE-2024-47176. One
    datagram in the CUPS browse-protocol advertising a fake IPP URI; if the
    daemon dials back to Get-Printer-Attributes on the listener we open,
    the box is exposed regardless of whether 631/tcp itself is filtered.
    Detection-only: recce never delivers the foomatic payload.

  * IPP extensions layered on top of services.ipp: Get-Jobs (op 0x000A)
    for job/user/host/filename harvest, /admin log-endpoint auth check,
    URI hostname harvest into the cross-service surfaces, and a version-
    gate on the CUPS 2024-09 chain that downgrades to informational when
    the parsed cups_version is past the vendor's fixed line.

Airgap-safe: stdlib socket / http.client / struct. Detection-only across
every probe path - recce never invokes LPD op 02 (Receive job) and never
delivers the foomatic-rip payload.
"""
from __future__ import annotations

import http.client
import re
import socket
import ssl
import struct

from ..core.models import Host, Port


_LPD_PORT = 515
_IPP_PORT = 631
_PJL_PORT = 9100
_TIMEOUT = 4.0

# LPD opcodes we USE (never op 02 - that spools paper).
_LPD_OP_SHORT = 0x03      # Send queue state (short)
_LPD_OP_LONG = 0x04       # Send queue state (long)

# Queue names to probe. Small on purpose: LPD has no listing, every probe is
# a real TCP round-trip, and most stock daemons answer for "lp" or "" (empty
# name meaning "all queues") on any queue-list op.
_QUEUE_CANDIDATES = ("lp", "", "default", "raw", "PASSTHRU", "text", "LPT1")


# --- LPD wire ---------------------------------------------------------------

def is_lpd(port: Port) -> bool:
    svc = (port.service or "").lower()
    return port.portid == _LPD_PORT or "lpd" in svc or "printer" in svc


def _lpd_short(queue: str) -> bytes:
    return bytes([_LPD_OP_SHORT]) + queue.encode("ascii", "replace") + b"\n"


def _lpd_long(queue: str) -> bytes:
    return bytes([_LPD_OP_LONG]) + queue.encode("ascii", "replace") + b"\n"


def _lpd_query(ip: str, port: int, payload: bytes, timeout: float) -> bytes:
    """Send one LPD command, read the ASCII response until EOF or timeout.

    LPD daemons close the connection after emitting the queue listing, so
    a bounded recv-until-empty loop with a total-time guard is correct.
    Returns b'' on connect/read failure."""
    from ..core import proxy
    to = proxy.scaled(timeout)
    try:
        with socket.create_connection((ip, port), timeout=to) as s:
            s.settimeout(to)
            s.sendall(payload)
            buf = b""
            # Bounded: at most 16 KiB, at most `to` seconds total. A malicious
            # daemon that never closes cannot hang the sweep.
            while len(buf) < 16384:
                try:
                    chunk = s.recv(4096)
                except (socket.timeout, OSError):
                    break
                if not chunk:
                    break
                buf += chunk
            return buf
    except OSError:
        return b""


# --- LPD parsing ------------------------------------------------------------

# Short listing (RFC 1179 sec 5.3):
#   Rank   Owner     Job  Files                Total Size
#   1st    alice     42   report.pdf           12345 bytes
# Long listing (sec 5.4) puts one job across several lines:
#   alice: 1st                        [job 042 lpd-host]
#           /var/spool/lpd/df042lpd-host  1 copies of report.pdf
#           /var/spool/lpd/cfA042lpd-host

_JOB_LINE_SHORT = re.compile(
    r"^\s*(?P<rank>\d+\S*|active)\s+(?P<owner>\S+)\s+(?P<job>\d+)\s+"
    r"(?P<files>.+?)\s+(?P<size>\d+)\s+bytes?\s*$", re.I | re.M)

_JOB_HEADER_LONG = re.compile(
    r"^\s*(?P<owner>[A-Za-z0-9._-]+):\s+(?P<rank>\d+\S*|active)\s+"
    r"\[job\s+(?P<job>\d+)\s+(?P<host>\S+)\]\s*$", re.I | re.M)

_FILE_LINE_LONG = re.compile(
    r"^\s+(?P<path>\S+)\s+(?:\d+\s+cop(?:y|ies)\s+of\s+)?"
    r"(?P<name>\S+)\s*$", re.M)


def _parse_lpd_listing(text: str) -> dict:
    """Extract jobs, owners, source hosts and filenames from either format.

    Returns {jobs: [{rank, owner, job, files, size, host}], owners: [str],
    hosts: [str], filenames: [str]}.
    """
    jobs: list[dict] = []
    owners: set = set()
    hosts: set = set()
    files: set = set()

    for m in _JOB_LINE_SHORT.finditer(text):
        d = m.groupdict()
        owners.add(d["owner"])
        for name in re.split(r"[\s,]+", d["files"].strip()):
            if name and name != "-":
                files.add(name)
        jobs.append({
            "rank": d["rank"], "owner": d["owner"], "job": d["job"],
            "files": d["files"].strip(), "size": int(d["size"]), "host": "",
        })

    for m in _JOB_HEADER_LONG.finditer(text):
        d = m.groupdict()
        owners.add(d["owner"])
        hosts.add(d["host"])
        jobs.append({
            "rank": d["rank"], "owner": d["owner"], "job": d["job"],
            "files": "", "size": 0, "host": d["host"],
        })
    for m in _FILE_LINE_LONG.finditer(text):
        n = m.group("name")
        if n and "/" not in n and not n.startswith("cf") and not n.startswith("df"):
            files.add(n)

    return {"jobs": jobs, "owners": sorted(owners),
            "hosts": sorted(hosts), "filenames": sorted(files)}


# --- LPD fingerprint --------------------------------------------------------

def _fingerprint_lpd(text: str) -> tuple[str, str]:
    """Return (family, version_hint) from queue-listing text.

    Families: lprng | bsd | cups-lpd | hp-jetdirect | windows | unknown.
    version_hint is best-effort ('' when nothing concrete)."""
    if not text:
        return "unknown", ""
    lower = text.lower()
    # cups-lpd first: it also emits a "Printer:" header (borrowed from LPRng),
    # so the URI signature disambiguates from LPRng proper.
    if "cups-lpd" in lower or "ipp://" in lower:
        m = re.search(r"cups[^\d]*(\d[\w.]*)", lower)
        return "cups-lpd", m.group(1) if m else ""
    if "lprng" in lower or re.search(r"^\s*printer:\s+\S+", text, re.I | re.M):
        m = re.search(r"lprng[^\d]*(\d[\w.]*)", lower)
        return "lprng", m.group(1) if m else ""
    if "ready and printing" in lower or "jetdirect" in lower or "hp lj" in lower:
        return "hp-jetdirect", ""
    if "windows" in lower and "print" in lower:
        return "windows", ""
    if "no entries" in lower or re.search(r"^rank\s+owner\s+job", text, re.I | re.M):
        return "bsd", ""
    return "unknown", ""


# --- LPD ACL: is peer-based access control off? -----------------------------

def _acl_open(fingerprint: str, response: bytes) -> bool:
    """Best-effort 'does the daemon accept jobs from any peer?' signal.

    A stock BSD lpd with /etc/hosts.lpd unpopulated will answer queue-list
    ops from any peer, which is the pre-condition for the historical
    control-file injection family. We infer this from the fact that WE (an
    arbitrary peer) got a listing at all - not from probing op 02.
    """
    if not response:
        return False
    # LPRng and cups-lpd have their own ACLs but still commonly answer to
    # anyone on queue-list ops - the exposure signal is unchanged.
    return fingerprint in ("bsd", "lprng", "cups-lpd", "hp-jetdirect",
                           "windows", "unknown")


# --- LPD probe --------------------------------------------------------------

def probe_lpd(ip: str, port: int = _LPD_PORT, timeout: float = _TIMEOUT,
              queues=_QUEUE_CANDIDATES) -> dict:
    """Send queue-list short + long against a small queue-name candidate set.
    Returns an aggregated view of everything the daemon offered."""
    out: dict = {"reachable": False, "family": "unknown", "version_hint": "",
                 "listings": [], "owners": [], "hosts": [], "filenames": [],
                 "acl_open": False}
    owners: set = set()
    hosts: set = set()
    files: set = set()
    fam = "unknown"
    ver = ""

    for q in queues:
        for op_name, payload in (("short", _lpd_short(q)),
                                 ("long",  _lpd_long(q))):
            data = _lpd_query(ip, port, payload, timeout)
            if not data:
                continue
            out["reachable"] = True
            try:
                text = data.decode("utf-8", "replace")
            except UnicodeDecodeError:
                text = data.decode("latin-1", "replace")
            f2, v2 = _fingerprint_lpd(text)
            if fam == "unknown" and f2 != "unknown":
                fam, ver = f2, v2
            parsed = _parse_lpd_listing(text)
            owners.update(parsed["owners"])
            hosts.update(parsed["hosts"])
            files.update(parsed["filenames"])
            out["listings"].append({
                "queue": q, "op": op_name, "text": text[:2048],
                "jobs": parsed["jobs"],
            })
            # No point probing more queues on the same daemon if we already
            # got a real listing with jobs on the first hit.
            if parsed["jobs"] and q in ("lp", ""):
                break

    out["family"] = fam
    out["version_hint"] = ver
    out["owners"] = sorted(owners)
    out["hosts"] = sorted(hosts)
    out["filenames"] = sorted(files)
    # Only meaningful on a daemon that actually answered.
    if out["reachable"]:
        # `_acl_open` reads whichever raw response was non-empty; grab one.
        raw = b""
        for lst in out["listings"]:
            if lst["text"]:
                raw = lst["text"].encode("utf-8", "replace")
                break
        out["acl_open"] = _acl_open(fam, raw)
    return out


# --- IPP Get-Jobs -----------------------------------------------------------

def _ipp_get_jobs(printer_uri: str) -> bytes:
    """RFC 8011 Get-Jobs (op 0x000A) requesting the identity-leaking attrs."""
    version = struct.pack("!BB", 1, 1)
    op = struct.pack("!H", 0x000A)
    rid = struct.pack("!I", 2)
    body = b"\x01"
    body += (b"\x47" + struct.pack("!H", 18) + b"attributes-charset"
             + struct.pack("!H", 5) + b"utf-8")
    body += (b"\x48" + struct.pack("!H", 27) + b"attributes-natural-language"
             + struct.pack("!H", 5) + b"en-us")
    uri = printer_uri.encode("utf-8", "replace")
    body += (b"\x45" + struct.pack("!H", 11) + b"printer-uri"
             + struct.pack("!H", len(uri)) + uri)
    # requested-attributes: 1setOf keyword, repeated
    attrs = ("job-id", "job-name", "job-originating-user-name",
             "job-originating-host-name", "document-name-supplied",
             "document-name")
    first = True
    for a in attrs:
        name_len = len(a) if first else 0
        name = a.encode("ascii") if first else b""
        val = a.encode("ascii")
        body += (b"\x44"                                # keyword tag
                 + struct.pack("!H", name_len) + name
                 + struct.pack("!H", len(val)) + val)
        if first:
            # Actually keep the name only on the first occurrence — that is
            # how IPP encodes a 1setOf on the wire.
            first = False
    body += b"\x03"
    return version + op + rid + body


def _ipp_post(ip: str, port: int, body: bytes, timeout: float,
              tls: bool = False, path: str = "/") -> tuple[int, bytes, str]:
    from ..core import proxy
    to = proxy.scaled(timeout)
    conn = None
    try:
        if tls:
            ctx = ssl._create_unverified_context()   # noqa: S323 - self-signed printers
            conn = http.client.HTTPSConnection(ip, port, timeout=to, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=to)
        conn.request("POST", path, body=body,
                     headers={"Content-Type": "application/ipp",
                              "User-Agent": "recce-cups-lpd/1.0"})
        r = conn.getresponse()
        return r.status, r.read(65536), r.getheader("Server") or ""
    except (OSError, http.client.HTTPException, socket.timeout):
        return 0, b"", ""
    finally:
        if conn is not None:
            try: conn.close()
            except OSError: pass


def _parse_ipp_jobs(body: bytes) -> list[dict]:
    """Best-effort Get-Jobs parser. Splits into per-job groups on the
    job-attributes-tag (0x02) boundary and pulls the identity leak attrs."""
    if len(body) < 9:
        return []
    i = 8
    jobs: list[dict] = []
    cur: dict = {}
    in_job = False               # only accumulate job-attributes-tag (0x02) groups
    while i < len(body):
        tag = body[i]
        i += 1
        if tag == 0x03:                              # end-of-attributes
            if in_job and cur:
                jobs.append(cur)
            break
        if tag in (0x00, 0x01, 0x02, 0x04, 0x05, 0x06, 0x07):
            if in_job and cur:
                jobs.append(cur)
            cur = {}
            in_job = (tag == 0x02)
            continue
        if tag < 0x08 or i + 2 > len(body):
            break
        name_len = struct.unpack_from("!H", body, i)[0]
        i += 2
        name = body[i:i + name_len].decode("ascii", "replace")
        i += name_len
        if i + 2 > len(body):
            break
        val_len = struct.unpack_from("!H", body, i)[0]
        i += 2
        val = body[i:i + val_len]
        i += val_len
        try:
            text = val.decode("utf-8", "replace")
        except UnicodeDecodeError:
            text = val.hex()
        if name and in_job:
            cur[name] = text
        elif in_job and cur:
            # 1setOf continuation: append into a same-name list under a
            # neutral key when we don't know the current attr name.
            cur.setdefault("_setof", []).append(text)
    if in_job and cur and cur not in jobs:
        jobs.append(cur)
    return jobs


def ipp_get_jobs(ip: str, printer_uri: str, port: int = _IPP_PORT,
                 timeout: float = _TIMEOUT, tls: bool = False) -> dict:
    """Fetch a printer's queued jobs. Cap the harvest at 10 jobs per printer
    (per the implementation note in the punch list) so a real spooler is not
    spammed."""
    body = _ipp_get_jobs(printer_uri)
    status, resp, server = _ipp_post(ip, port, body, timeout, tls=tls)
    out = {"reachable": bool(status), "http_status": status, "server": server,
           "jobs": [], "users": [], "hosts": [], "filenames": []}
    if not status:
        return out
    jobs = _parse_ipp_jobs(resp)[:10]
    out["jobs"] = jobs
    users = {j.get("job-originating-user-name") for j in jobs
             if j.get("job-originating-user-name")}
    hosts = {j.get("job-originating-host-name") for j in jobs
             if j.get("job-originating-host-name")}
    files = set()
    for j in jobs:
        for k in ("document-name", "document-name-supplied", "job-name"):
            if j.get(k):
                files.add(j[k])
    out["users"] = sorted(u for u in users if u)
    out["hosts"] = sorted(h for h in hosts if h)
    out["filenames"] = sorted(files)
    return out


# --- IPP URI harvest --------------------------------------------------------

_URI_RE = re.compile(r"(?:ipp|ipps|http|https|socket|lpd)://"
                     r"(?P<host>[A-Za-z0-9._-]+|\[[0-9a-fA-F:]+\])"
                     r"(?::\d+)?(?:/[^\s\"']*)?", re.I)


def harvest_uris(attr_dicts: list[dict]) -> dict:
    """Walk printer-uri-supported / device-uri / notify-recipient-uri values
    already parsed by ipp._walk_ipp_attributes; extract hosts + DNS suffixes.

    Returns {hostnames: [...], domains: [...]}. Feeds known_hostnames /
    known_domains at the analyze() layer.
    """
    hosts: set = set()
    domains: set = set()
    keys = ("printer-uri-supported", "device-uri", "notify-recipient-uri",
            "printer-more-info", "printer-more-info-manufacturer",
            "printer-icons")
    for d in attr_dicts or []:
        for k, v in (d or {}).items():
            if not v or not any(sub in k for sub in ("uri", "info", "icons")):
                continue
            if k not in keys and not k.endswith("uri"):
                continue
            for m in _URI_RE.finditer(str(v)):
                h = m.group("host").strip("[]")
                if not h or h.replace(".", "").isdigit():
                    hosts.add(h)
                    continue
                hosts.add(h)
                if "." in h:
                    domains.add(h.split(".", 1)[1].lower())
    return {"hostnames": sorted(hosts), "domains": sorted(domains)}


# --- cups-browsed 631/udp ---------------------------------------------------

def probe_cups_browsed(ip: str, port: int = _IPP_PORT,
                       listen_timeout: float = 3.0,
                       timeout: float = _TIMEOUT) -> dict:
    """Send one CUPS browse-protocol datagram advertising a fake IPP URI back
    at us; watch a short-lived TCP listener for the daemon to reach back.

    Return {sent, replied, remote_port} - `replied=True` is the exposure signal
    for CVE-2024-47176 regardless of whether 631/tcp is filtered.

    Detection-only: recce accepts and immediately closes the TCP connection.
    Never sends any IPP payload, never delivers the foomatic-rip stager.
    """
    from ..core import proxy
    out = {"sent": False, "replied": False, "remote_port": 0, "listen_port": 0}

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind(("0.0.0.0", 0))
    except OSError:
        return out
    listener.listen(1)
    listener.settimeout(proxy.scaled(listen_timeout))
    listen_port = listener.getsockname()[1]
    out["listen_port"] = listen_port

    fake_uri = f"ipp://127.0.0.1:{listen_port}/printers/recce-probe"
    # Browse datagram (cups-browsed accepts the classic CUPS browse-protocol
    # form): type(hex) state(hex) uri "location" "info" "make-and-model"
    # lease-duration. Type 0x1 = printer, state 3 = idle.
    packet = (f"0x00000001 3 {fake_uri} "
              f"\"recce\" \"recce probe\" \"recce\" 0\n").encode("ascii")
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(proxy.scaled(timeout))
    try:
        udp.sendto(packet, (ip, port))
        out["sent"] = True
    except OSError:
        udp.close(); listener.close()
        return out
    udp.close()

    try:
        conn, addr = listener.accept()
        out["replied"] = True
        out["remote_port"] = addr[1]
        try: conn.close()
        except OSError: pass
    except (socket.timeout, OSError):
        pass
    finally:
        try: listener.close()
        except OSError: pass
    return out


# --- CUPS /admin log-endpoint auth check ------------------------------------

_ADMIN_PATHS = ("/admin", "/admin/conf",
                "/admin/log/error_log", "/admin/log/access_log")


def probe_admin_endpoints(ip: str, port: int = _IPP_PORT,
                          timeout: float = _TIMEOUT,
                          tls: bool = False) -> dict:
    """GET /admin* and record what each endpoint's status was."""
    from ..core import proxy
    to = proxy.scaled(timeout)
    out: dict = {"probed": list(_ADMIN_PATHS), "results": [], "readable": [],
                 "auth_required": []}
    for path in _ADMIN_PATHS:
        conn = None
        try:
            if tls:
                ctx = ssl._create_unverified_context()   # noqa: S323
                conn = http.client.HTTPSConnection(ip, port, timeout=to, context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=to)
            conn.request("GET", path,
                         headers={"User-Agent": "recce-cups-lpd/1.0"})
            r = conn.getresponse()
            status = r.status
            body_sample = r.read(2048)
            www_auth = r.getheader("WWW-Authenticate") or ""
        except (OSError, http.client.HTTPException, socket.timeout):
            status, body_sample, www_auth = 0, b"", ""
        finally:
            if conn is not None:
                try: conn.close()
                except OSError: pass
        entry = {"path": path, "status": status,
                 "www_authenticate": www_auth,
                 "sample": body_sample[:200].decode("latin-1", "replace")}
        out["results"].append(entry)
        if status == 200:
            out["readable"].append(path)
        elif status in (401, 403) and www_auth:
            out["auth_required"].append(path)
    return out


# --- CUPS version gate for CVE-2024-47176 chain -----------------------------

# Distro-repackaged CUPS lines that are FIXED even though the upstream
# version is < 2.4.9. Keys are exact upstream-version prefixes; the value is
# a callable that returns True when the OS-supplied distro suffix indicates
# the security update was applied. Used as a downgrade gate on the finding.
_DISTRO_FIXED_SUFFIX_RE = re.compile(
    r"(ubuntu[\d.]+\.\d+|op\d+-\d+|deb\d+u\d+|el\d+|~bpo\d+)", re.I)


def cups_vulnerable(version: str, server_header: str = "") -> tuple[bool, str]:
    """Decide vulnerability against the 2024-09 chain. Returns (vulnerable, why).

    Rules:
      * upstream >= 2.4.9  -> not vulnerable
      * upstream <  2.4.9  -> vulnerable, UNLESS the server header carries a
        distro-repackaged suffix (Ubuntu SRU, RHEL op-suffix, Debian security
        update) - then treat as "downgraded, ops must confirm patch".
    """
    if not version:
        return True, "no version parsed - default to vulnerable"
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", version)
    if not m:
        return True, f"unparseable version {version!r}"
    major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if (major, minor, patch) >= (2, 4, 9):
        return False, f"upstream {version} >= 2.4.9 (fixed)"
    if _DISTRO_FIXED_SUFFIX_RE.search(server_header or version):
        return False, f"distro-backported ({server_header or version})"
    return True, f"upstream {version} < 2.4.9 and no distro-fix marker"


# --- T2 promotion probes ----------------------------------------------------

# PJL banner on 9100/tcp. This is the version-gate for CVE-2010-4107: the LPD
# fingerprint tells us "HP JetDirect", the PJL INFO ID reply gives model +
# firmware date so the operator can correlate against HP's patch matrix. UEL
# wrapping (\x1B%-12345X) guarantees we exit any residual print job state
# rather than adding data to a queue.
_PJL_INFO_PAYLOAD = (b"\x1B%-12345X@PJL INFO ID\r\n@PJL INFO CONFIG\r\n"
                     b"\x1B%-12345X\r\n")

_PJL_MODEL_RE = re.compile(
    r'@PJL\s+INFO\s+ID\s*\r?\n\s*"?(?P<model>[^\r\n"]+?)"?\s*\r?\n', re.I)
_PJL_FIRMWARE_RE = re.compile(
    r"(?:FIRMWARE(?:\s+DATECODE)?|FW\s+VERSION)\s*[:=]?\s*(?P<fw>\S+)", re.I)


def probe_pjl_info(ip: str, port: int = _PJL_PORT,
                   timeout: float = _TIMEOUT) -> dict:
    """Send @PJL INFO ID on JetDirect 9100/tcp — read-only firmware fingerprint.

    Returns {reachable, raw, model, firmware}. This is a T2-safe probe: PJL
    INFO is a query op, never a job submission, and we bracket with UEL so a
    partially-parsed reply cannot end up spooled as text on the device.
    """
    from ..core import proxy
    to = proxy.scaled(timeout)
    out: dict = {"reachable": False, "raw": "", "model": "", "firmware": ""}
    try:
        with socket.create_connection((ip, port), timeout=to) as s:
            s.settimeout(to)
            s.sendall(_PJL_INFO_PAYLOAD)
            buf = b""
            while len(buf) < 8192:
                try:
                    chunk = s.recv(4096)
                except (socket.timeout, OSError):
                    break
                if not chunk:
                    break
                buf += chunk
    except OSError:
        return out
    if not buf:
        return out
    try:
        text = buf.decode("utf-8", "replace")
    except UnicodeDecodeError:
        text = buf.decode("latin-1", "replace")
    out["reachable"] = True
    out["raw"] = text[:2048]
    m = _PJL_MODEL_RE.search(text)
    if m:
        out["model"] = m.group("model").strip()
    m = _PJL_FIRMWARE_RE.search(text)
    if m:
        out["firmware"] = m.group("fw").strip()
    return out


# CUPS access_log / error_log parse. This is what upgrades cups_admin_open
# from "endpoint returns 200" (T1) to "we pulled real user + IP + printer
# tuples out of the log body" (T2). Read-only.
_ACCESS_LOG_RE = re.compile(
    r"^(?P<host>\S+)\s+-\s+(?P<user>\S+)\s+\[(?P<date>[^\]]+)\]\s+"
    r"\"(?P<method>\S+)\s+(?P<path>\S+)\s+HTTP/\S+\"\s+(?P<status>\d+)",
    re.M)
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_ERRORLOG_IP_RE = re.compile(r"from\s+((?:\d{1,3}\.){3}\d{1,3})")


def parse_cups_log(text: str) -> dict:
    """Extract users / source IPs / printer paths from CUPS log body.

    Covers both access_log (combined-style rows) and error_log (`from IP`
    trailers). Returns {users, ips, printers, entries}.
    """
    users: set = set()
    ips: set = set()
    printers: set = set()
    entries = 0
    for m in _ACCESS_LOG_RE.finditer(text):
        entries += 1
        u = m.group("user")
        if u and u != "-":
            users.add(u)
        host = m.group("host")
        if _IPV4_RE.match(host):
            ips.add(host)
        path = m.group("path")
        if path.startswith(("/printers/", "/classes/")):
            printers.add(path.split("?", 1)[0])
    for m in _ERRORLOG_IP_RE.finditer(text):
        ips.add(m.group(1))
    return {"users": sorted(users), "ips": sorted(ips),
            "printers": sorted(printers), "entries": entries}


def fetch_admin_log(ip: str, port: int, path: str,
                    timeout: float = _TIMEOUT, tls: bool = False,
                    max_bytes: int = 65536) -> bytes:
    """Read-only fetch of an unauth CUPS /admin/log/* body, size-capped."""
    from ..core import proxy
    to = proxy.scaled(timeout)
    conn = None
    try:
        if tls:
            ctx = ssl._create_unverified_context()   # noqa: S323
            conn = http.client.HTTPSConnection(ip, port, timeout=to, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=to)
        conn.request("GET", path,
                     headers={"User-Agent": "recce-cups-lpd/1.0"})
        r = conn.getresponse()
        if r.status != 200:
            return b""
        return r.read(max_bytes)
    except (OSError, http.client.HTTPException, socket.timeout):
        return b""
    finally:
        if conn is not None:
            try: conn.close()
            except OSError: pass


# --- targets / findings emission -------------------------------------------

def lpd_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_lpd(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


# Canonical alias for /api/scan/context's `<cmd>_targets` lookup.
cups_lpd_targets = lpd_targets


def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier="", output=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": tool, "command": cmd, "remediation": rem,
            "cwes": list(cwes), "kind": kind,
            "exploit_note": exploit_note, "depth_tier": depth_tier,
            "output": output}


_LPRNG_CVES = ["CVE-2000-0917", "CVE-2001-0670"]
_HP_LPD_CVES = ["CVE-2010-4107"]


def findings(hosts: list[Host], lpd_probes: dict | None = None,
             jobs_probes: dict | None = None,
             browsed_probes: dict | None = None,
             admin_probes: dict | None = None,
             version_gate: dict | None = None,
             uri_harvest: dict | None = None,
             pjl_probes: dict | None = None) -> list[dict]:
    lpd_probes = lpd_probes or {}
    jobs_probes = jobs_probes or {}
    browsed_probes = browsed_probes or {}
    admin_probes = admin_probes or {}
    version_gate = version_gate or {}
    uri_harvest = uri_harvest or {}
    pjl_probes = pjl_probes or {}
    out: list[dict] = []

    printer_ports = {}                # ip -> set(portid) for correlation
    for h in hosts:
        printer_ports[h.ip] = {p.portid for p in h.open_ports
                               if p.portid in (515, 631, 9100)}

    for h in hosts:
        for p in h.open_ports:
            tgt = f"{h.ip}:{p.portid}"

            # --- LPD --------------------------------------------------------
            if is_lpd(p):
                pr = lpd_probes.get((h.ip, p.portid))
                if not pr or not pr.get("reachable"):
                    continue
                fam = pr.get("family", "unknown")
                jobs_total = sum(len(l["jobs"]) for l in pr.get("listings") or [])
                owners = pr.get("owners") or []
                hosts_l = pr.get("hosts") or []
                files_l = pr.get("filenames") or []

                if owners or hosts_l or files_l:
                    # T2: real user + hostname + filename tuples are the loot
                    # — an unauth query returned identity fields that the
                    # spray / lateral layers directly consume.
                    leak_output = (
                        f"RFC 1179 op 03/04 -> {jobs_total} job(s); "
                        f"owners={owners[:8]} hosts={hosts_l[:8]} "
                        f"files={files_l[:8]}")
                    out.append(_finding(
                        "high",
                        "LPD queue leaks usernames, source hostnames and print job filenames",
                        tgt,
                        f"RFC 1179 queue-list op(s) returned {jobs_total} job(s). "
                        f"Owners: {', '.join(owners[:8]) or '-'}. "
                        f"Source hosts: {', '.join(hosts_l[:8]) or '-'}. "
                        f"Filenames: {', '.join(files_l[:8]) or '-'}. "
                        f"Feed the owners into known_users, the hosts into "
                        f"known_hostnames, and treat the filenames as "
                        f"recon-grade artifact disclosures. T2 proof: those "
                        f"tuples were returned by a single unauthenticated "
                        f"query — no writes, no job submission.",
                        "lpq",
                        f"lpq -P lp -h {h.ip}   # or: echo -e '\\x04lp\\n' "
                        f"| nc {h.ip} {p.portid}",
                        "Restrict 515/tcp to trusted print sources; require "
                        "authenticated printing; move to IPP/HTTPS with client "
                        "certificates where possible.",
                        ["CWE-200", "CWE-306"], kind="lpd_queue_leak",
                        exploit_note=(
                            f"lpq -P lp -h {h.ip} ; then feed owners into "
                            "known_users, hosts into known_hostnames"),
                        depth_tier="t2", output=leak_output))
                else:
                    out.append(_finding(
                        "medium",
                        "LPD queue listing readable unauthenticated (RFC 1179)",
                        tgt,
                        f"LPD daemon answered queue-list op 03/04 without "
                        f"authentication (family={fam}). Queue was empty at "
                        f"probe time; any future job leaks owner, source host "
                        f"and filename to any peer.",
                        "lpq",
                        f"lpq -P lp -h {h.ip}",
                        "Restrict 515/tcp to trusted print sources; enforce a "
                        "peer allow-list (/etc/hosts.lpd on BSD lpd).",
                        ["CWE-200", "CWE-306"], kind="lpd_queue_open",
                        exploit_note=(
                            f"lpq -P lp -h {h.ip}  "
                            "# empty now, but leaks on the next job"),
                        depth_tier="t1"))

                # Fingerprint + CVE cross-reference. Only cite CVEs when the
                # fingerprint actually matches; unsure -> CWE only.
                if fam == "lprng":
                    ver = pr.get("version_hint") or "unknown"
                    out.append(_finding(
                        "critical",
                        "LPRng detected - CVE-2000-0917 / CVE-2001-0670 unauth RCE class",
                        tgt,
                        f"Queue-listing text matches LPRng (version hint: {ver}). "
                        f"LPRng carries a documented unauthenticated RCE class: "
                        f"CVE-2000-0917 (syslog(3) format-string) and "
                        f"CVE-2001-0670 (SITE EXEC family). Verify the running "
                        f"version against the vendor's patched line before "
                        f"citing exploitability.",
                        "review",
                        f"echo -ne '\\x04\\n' | nc {h.ip} {p.portid}   # confirm "
                        f"the LPRng-style Printer: header",
                        "Upgrade LPRng past the vendor-patched line, or migrate "
                        "to CUPS with the LPD compat layer disabled.",
                        ["CWE-134", "CWE-77"], kind="lpd_lprng_cve",
                        exploit_note=(
                            "review LPRng version and vendor patch date; "
                            "Metasploit modules exist (aux/scanner/printer/"
                            "lprng_format_string) but destructive."),
                        depth_tier="t1"))
                elif fam == "hp-jetdirect":
                    pj = pjl_probes.get(h.ip) or {}
                    has_pjl = bool(pj.get("reachable"))
                    model = pj.get("model", "")
                    firmware = pj.get("firmware", "")
                    # T2 when the version-gate probe (PJL INFO ID on 9100/tcp)
                    # actually returned a model / firmware string. Detection
                    # alone stays T1; the CVE citation is unchanged either
                    # way (still gated on firmware date, still not exploit).
                    if has_pjl:
                        tier = "t2"
                        jd_output = (f"@PJL INFO ID {h.ip}:9100 -> "
                                     f"model={model!r} firmware={firmware!r}")
                        proof = (
                            f" T2 proof: PJL INFO ID on {h.ip}:{_PJL_PORT} "
                            f"returned model={model!r} firmware={firmware!r} "
                            f"— that is the version-gate for CVE-2010-4107. "
                            f"Correlate the firmware datecode against HP's "
                            f"patch matrix before citing exploitability. No "
                            f"job was submitted; PJL INFO is a read-only "
                            f"query and the request was UEL-bracketed.")
                    else:
                        tier = "t1"
                        jd_output = ""
                        proof = ""
                    out.append(_finding(
                        "high",
                        "HP JetDirect LPD/PJL command injection (CVE-2010-4107) - vendor firmware review",
                        tgt,
                        "HP JetDirect fingerprint on LPD. Older firmware "
                        "accepts PJL commands injected through the LPD "
                        "control-file path (CVE-2010-4107). Detection is a "
                        "flag, not a confirmation - the CVE gate is the "
                        "device's firmware date, which recce cannot read "
                        "over 515." + proof,
                        "review",
                        f"nmap -p9100 --script pjl-ready-message {h.ip}   # "
                        f"read the PJL banner for a firmware date",
                        "Update JetDirect firmware; block 515/tcp and "
                        "9100/tcp at the perimeter; enforce PJL access "
                        "controls on the printer web UI.",
                        ["CWE-77", "CWE-306"], kind="lpd_jetdirect_cve",
                        exploit_note=(
                            f"nmap -p9100 --script pjl-ready-message {h.ip} "
                            f" ; # or: printf '@PJL INFO ID\\r\\n' | nc "
                            f"{h.ip} 9100"),
                        depth_tier=tier, output=jd_output))
                elif fam == "windows":
                    out.append(_finding(
                        "high",
                        "Windows Print Service on 515/tcp - correlate with PrintNightmare on 445",
                        tgt,
                        "LPD banner matches Microsoft LPD Print Service. The "
                        "same host is a candidate for MS-RPRN (PrinterBug) "
                        "and PrintNightmare on SMB - check the paired 445 "
                        "finding for signing posture and confirm the spooler "
                        "service is patched.",
                        "review",
                        f"# cross-check: recce smb {h.ip}   # PrintNightmare "
                        f"posture is in the SMB finding",
                        "Apply the PrintNightmare KBs; disable the Print "
                        "Spooler on non-print servers; restrict 515/tcp.",
                        ["CWE-284"], kind="lpd_windows_pn",
                        exploit_note=(
                            f"recce smb {h.ip}  # cross-check spooler "
                            "status; then rpcdump.py --print-services for "
                            "MS-RPRN"),
                        depth_tier="t0"))

                # Detection-only exposure flag for the classic control-file
                # injection family. NEVER invoke op 02.
                if pr.get("acl_open"):
                    out.append(_finding(
                        "medium",
                        "LPD daemon accepts queue commands from any peer (no /etc/hosts.lpd)",
                        tgt,
                        "The daemon answered queue-list operations from recce "
                        "with no peer allow-list check, which is the pre-"
                        "condition for the historical BSD lpd control-file "
                        "field injection family (multiple CVEs 1996-2003). "
                        "recce did NOT invoke op 02 (Receive job) - the "
                        "exposure is a flag, not proof of exploit.",
                        "review",
                        f"# manual review of {h.ip} /etc/hosts.lpd / "
                        f"lpd.perms; recce will not fire the injection op",
                        "Populate /etc/hosts.lpd (or the LPRng equivalent "
                        "lpd.perms) with the specific print clients; block "
                        "515/tcp at the perimeter.",
                        ["CWE-306", "CWE-77"], kind="lpd_acl_open",
                        exploit_note=(
                            "review /etc/hosts.lpd on the target manually; "
                            "do not send op 02 without ROE"),
                        depth_tier="t1"))

            # --- IPP / CUPS extensions -------------------------------------
            if p.portid == _IPP_PORT and p.protocol == "tcp":
                # Get-Jobs harvest.
                jr = jobs_probes.get((h.ip, p.portid))
                if jr and jr.get("jobs"):
                    users = jr.get("users") or []
                    files = jr.get("filenames") or []
                    hostsj = jr.get("hosts") or []
                    # T2: op 0x000A pulled real user/host/filename tuples —
                    # the same identity fields the spray + lateral layers
                    # consume. Read-only Get-Jobs, no mutation.
                    jobs_output = (
                        f"IPP op 0x000A -> {len(jr['jobs'])} job(s); "
                        f"users={users[:8]} hosts={hostsj[:8]} "
                        f"files={files[:8]}")
                    out.append(_finding(
                        "high",
                        "IPP Get-Jobs leaks originating user/host and document names",
                        tgt,
                        f"IPP Get-Jobs (op 0x000A) returned {len(jr['jobs'])} "
                        f"job(s) unauthenticated. Users: "
                        f"{', '.join(users[:8]) or '-'}. Hosts: "
                        f"{', '.join(hostsj[:8]) or '-'}. Documents: "
                        f"{', '.join(files[:8]) or '-'}. These are exactly "
                        f"the identity fields the password-spray and lateral-"
                        f"movement layers consume. T2 proof: values were "
                        f"returned by a single read-only Get-Jobs request; "
                        f"no jobs were submitted or modified.",
                        "ipptool",
                        f"ipptool -tv ipp://{h.ip}:{p.portid}/printers/lp "
                        f"get-jobs.test",
                        "Restrict IPP to trusted networks; require "
                        "authentication on IPP operations (cupsd Location / "
                        "AuthType); disable job-attribute exposure on "
                        "shared printers.",
                        ["CWE-200"], kind="ipp_get_jobs",
                        exploit_note=(
                            f"ipptool -tv ipp://{h.ip}:{p.portid}/printers/lp "
                            "get-jobs.test"),
                        depth_tier="t2", output=jobs_output))

                # cups-browsed 631/udp exposure signal.
                br = browsed_probes.get(h.ip)
                if br and br.get("replied"):
                    out.append(_finding(
                        "critical",
                        "cups-browsed (631/udp) accepts crafted printer URIs - CVE-2024-47176 ingress reachable",
                        tgt,
                        "recce sent one CUPS browse-protocol advert for a "
                        "fake IPP URI pointing back at a scanner-side "
                        "listener; the daemon reached back to Get-Printer-"
                        "Attributes on that URI. This is the ingress path of "
                        "CVE-2024-47176. Reachability is independent of "
                        "whether 631/tcp is filtered. Detection-only - recce "
                        "did NOT deliver the foomatic-rip payload.",
                        "review",
                        f"# reproduce: echo '0x1 3 ipp://YOUR-IP:631/probe "
                        f"\"\" \"\" \"\" 0' | nc -u {h.ip} 631; then watch "
                        f"nc -l 631 for the reply",
                        "Disable cups-browsed if not required (systemctl "
                        "disable --now cups-browsed); firewall 631/udp; "
                        "update CUPS past the 2024-09 chain.",
                        ["CWE-306", "CWE-940"], kind="cups_browsed_reachable",
                        exploit_note=(
                            "# ROE-required. PoC: cups-2024-47176 exploit "
                            "scripts on public repos; recce leaves the "
                            "actual payload delivery to the operator."),
                        depth_tier="t2"))

                # Version-gate the pre-existing ipp.py CVE-2024-47176 chain.
                vg = version_gate.get((h.ip, p.portid))
                if vg:
                    vulnerable = vg.get("vulnerable")
                    why = vg.get("why", "")
                    version = vg.get("version") or "unknown"
                    if vulnerable:
                        sev = "critical" if (br and br.get("replied")) else "high"
                        out.append(_finding(
                            sev,
                            "CUPS reachable at vulnerable version - CVE-2024-47076/-47175/-47176/-47177 foomatic-rip chain applies",
                            tgt,
                            f"CUPS {version} is answering IPP on {tgt} and is "
                            f"NOT past the fixed line ({why}). The 2024-09 "
                            f"chain lets a crafted Get-Printer-Attributes add "
                            f"a printer whose foomatic filter executes "
                            f"attacker commands the next time a job runs. "
                            + ("cups-browsed on 631/udp is ALSO reachable - "
                               "the ingress path is confirmed."
                               if (br and br.get("replied")) else
                               "cups-browsed on 631/udp was not confirmed "
                               "reachable in this scan."),
                            "review + vendor patch matrix",
                            "# fixed lines: upstream 2.4.9+, Ubuntu 24.04.1 "
                            "cups 2.4.7-1.2ubuntu7.1, RHEL 9 cups 2.3.3op2-"
                            "25, Debian bookworm-security.",
                            "Update CUPS to the vendor's patched build; "
                            "disable cups-browsed; firewall 631/udp.",
                            ["CWE-77", "CWE-306"], kind="cups_foomatic_vuln",
                            exploit_note=(
                                "See PoC scripts on public repos; run only "
                                "with ROE. Verify fixed line: upstream "
                                "2.4.9+, Ubuntu 24.04.1 cups 2.4.7-1.2"
                                "ubuntu7.1, RHEL 9 cups 2.3.3op2-25."),
                            depth_tier="t1"))
                    else:
                        out.append(_finding(
                            "info",
                            "CUPS reachable but past the 2024-09 fixed line",
                            tgt,
                            f"CUPS {version} on {tgt} is past the fixed line "
                            f"for the foomatic-rip chain ({why}). Still "
                            f"restrict cups-browsed and 631 exposure - the "
                            f"class of attack is unchanged; only this "
                            f"specific chain is patched.",
                            "review", "", "Keep patching cadence.",
                            [], kind="cups_foomatic_patched",
                            exploit_note="n/a - patched",
                            depth_tier="t0"))

                # /admin log-endpoint auth check.
                ar = admin_probes.get((h.ip, p.portid))
                if ar:
                    if ar.get("readable"):
                        paths = ", ".join(ar["readable"])
                        parsed = ar.get("log_parsed") or {}
                        # T2 when the log body actually parsed into rows —
                        # we HOLD the user + source-IP + printer tuples the
                        # exposure implies. Read-only; no writes.
                        if parsed.get("entries"):
                            tier = "t2"
                            u = parsed.get("users") or []
                            ips_ = parsed.get("ips") or []
                            pn = parsed.get("printers") or []
                            proof = (
                                f" T2 proof: pulled {parsed['entries']} log "
                                f"row(s) from {ar['readable'][0]}. Users: "
                                f"{', '.join(u[:8]) or '-'}. Source IPs: "
                                f"{', '.join(ips_[:8]) or '-'}. Printers: "
                                f"{', '.join(pn[:8]) or '-'}. Passive read.")
                            adm_output = (
                                f"GET {ar['readable'][0]} -> "
                                f"{parsed['entries']} entries; "
                                f"users={u[:8]} ips={ips_[:8]} "
                                f"printers={pn[:8]}")
                        else:
                            tier = "t1"
                            proof = ""
                            adm_output = ""
                        out.append(_finding(
                            "high",
                            "CUPS /admin log endpoints readable unauthenticated",
                            tgt,
                            f"GET on {paths} returned HTTP 200 without "
                            f"authentication. cupsd's /admin/log/error_log "
                            f"and access_log carry every job's user, source "
                            f"IP, and filename - a passive read of the "
                            f"tester's own history plus everyone else's."
                            + proof,
                            "curl",
                            f"curl -sS http://{h.ip}:{p.portid}"
                            f"{ar['readable'][0]}",
                            "Restrict cupsd Location /admin to localhost; "
                            "require AuthType on log endpoints; move the "
                            "listener off the public interface.",
                            ["CWE-200", "CWE-284"], kind="cups_admin_open",
                            exploit_note=(
                                f"curl -sS http://{h.ip}:{p.portid}"
                                "/admin/log/error_log | tail -200  # user "
                                "+ IP + filename history"),
                            depth_tier=tier, output=adm_output))
                    elif ar.get("auth_required"):
                        out.append(_finding(
                            "medium",
                            "CUPS /admin endpoints require authentication (default-cred spray candidate)",
                            tgt,
                            f"cupsd returned 401 on "
                            f"{', '.join(ar['auth_required'])}. Feed to the "
                            f"credential quickconnect (cups/cups, admin/"
                            f"admin) - default credentials on CUPS admin "
                            f"UIs are common on appliances.",
                            "curl",
                            f"curl -u cups:cups http://{h.ip}:{p.portid}"
                            f"{ar['auth_required'][0]}",
                            "Set strong unique credentials on the CUPS "
                            "admin group; restrict the /admin Location.",
                            ["CWE-284", "CWE-521"], kind="cups_admin_auth",
                            exploit_note=(
                                f"curl -u cups:cups http://{h.ip}:"
                                f"{p.portid}/admin ; hydra -l cups -P "
                                "/usr/share/wordlists/rockyou.txt "
                                f"http-get://{h.ip}:{p.portid}/admin"),
                            depth_tier="t0"))

                # URI hostname harvest (info-only finding; the values also
                # feed known_hostnames / known_domains via analyze()).
                uh = uri_harvest.get((h.ip, p.portid))
                if uh and (uh.get("hostnames") or uh.get("domains")):
                    out.append(_finding(
                        "medium",
                        "IPP printer-uri-supported discloses internal hostnames / DNS suffixes",
                        tgt,
                        f"IPP printer-uri-supported / device-uri values "
                        f"contain internal hostnames: "
                        f"{', '.join(uh['hostnames'][:8]) or '-'} and DNS "
                        f"suffixes: {', '.join(uh['domains'][:8]) or '-'}. "
                        f"Fed into known_hostnames + known_domains for "
                        f"downstream Kerberos/LDAP realm inference.",
                        "review",
                        f"ipptool -tv ipp://{h.ip}:{p.portid}/ "
                        f"get-printer-attributes.test",
                        "Configure cupsd BrowseLocalProtocols to none on "
                        "non-print hosts; do not advertise internal FQDNs "
                        "in printer share names.",
                        ["CWE-200"], kind="ipp_uri_harvest",
                        exploit_note=(
                            f"ipptool -tv ipp://{h.ip}:{p.portid}/ "
                            "get-printer-attributes.test"),
                        depth_tier="t0"))

            # --- Printer-stack correlation ---------------------------------
            if p.portid == 515 and printer_ports.get(h.ip, set()) >= {515, 631, 9100}:
                out.append(_finding(
                    "low",
                    "Printer stack exposed (515/tcp + 631/tcp + 9100/tcp) - treat as unmanaged appliance",
                    h.ip,
                    "All three printer-family ports are open on this host - "
                    "this is almost always an unmanaged print appliance. "
                    "Real pivot value lives on 9100 (PJL / raw print / "
                    "FSDIRLIST on old HP LaserJets); use LPD only for the "
                    "queue metadata harvest.",
                    "review",
                    f"# printer-stack pivot: recce jetdirect {h.ip}   # "
                    f"if/when a 9100 analyzer lands",
                    "Segregate print appliances onto a management VLAN; "
                    "disable unused print protocols on the device.",
                    [], kind="printer_stack_correlation",
                    exploit_note=(
                        f"printf '@PJL INFO ID\\r\\n' | nc {h.ip} 9100  "
                        "; # firmware + PJL support"),
                    depth_tier="t0"))
    return out


def runbook_lpd(ip: str, port: int = _LPD_PORT) -> list[dict]:
    return [
        {"phase": "enumerate", "tool": "lpq",
         "command": f"lpq -P lp -h {ip}",
         "why": "unauth short queue listing - owners/jobs"},
        {"phase": "enumerate", "tool": "nc",
         "command": f"printf '\\x04lp\\n' | nc -w3 {ip} {port}",
         "why": "long queue listing (RFC 1179 op 04) - filenames + hosts"},
        {"phase": "chain", "tool": "review",
         "command": f"# LPRng->CVE-2000-0917; HP->CVE-2010-4107; Windows->"
                    f"PrintNightmare on 445 of {ip}",
         "why": "gate CVE citation on the queue-listing fingerprint"},
    ]


def runbook_cups(ip: str, port: int = _IPP_PORT) -> list[dict]:
    return [
        {"phase": "enumerate", "tool": "ipptool",
         "command": f"ipptool -tv ipp://{ip}:{port}/printers/lp get-jobs.test",
         "why": "Get-Jobs identity leak (users/hosts/filenames)"},
        {"phase": "enumerate", "tool": "curl",
         "command": f"curl -sS http://{ip}:{port}/admin/log/error_log",
         "why": "log endpoints often unauth on misconfigured cupsd"},
        {"phase": "chain", "tool": "review",
         "command": f"# cups-browsed 631/udp advert -> reachability signal "
                    f"for CVE-2024-47176 on {ip}",
         "why": "the actual ingress vector; detection-only in recce"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from . import svccommon
    return svccommon.findings_to_vulns(fs, "cups-lpd", _LPD_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Sweep LPD + CUPS/IPP printer-stack targets.

    LPD is the primary driver here (own module). CUPS extensions are
    layered on top of any 631/tcp port already discovered - they do not
    re-run services.ipp's probe(), just its follow-up harvests.
    """
    from . import svcprobe
    targets_lpd = lpd_targets(hosts)
    ipp_hosts: list[tuple[str, int]] = []
    for h in hosts:
        for p in h.open_ports:
            if p.portid == _IPP_PORT and p.protocol == "tcp":
                ipp_hosts.append((h.ip, p.portid))

    lpd_probes: dict = {}
    jobs_probes: dict = {}
    browsed_probes: dict = {}
    admin_probes: dict = {}
    version_gate: dict = {}
    uri_harvest: dict = {}
    pjl_probes: dict = {}
    state: dict = {}

    # Set of hosts with 9100/tcp open — needed for the JetDirect T2 probe.
    port9100_hosts: set = set()
    for h in hosts:
        for p in h.open_ports:
            if p.portid == _PJL_PORT and p.protocol == "tcp":
                port9100_hosts.add(h.ip)

    known_hostnames: set = set()
    known_domains: set = set()
    known_users: set = set()

    if active:
        for t, pr in svcprobe.iter_probe(
                targets_lpd, lambda t: probe_lpd(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                lpd_probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["family"] = pr.get("family")
                known_users.update(pr.get("owners") or [])
                known_hostnames.update(pr.get("hosts") or [])
                for hn in pr.get("hosts") or []:
                    if "." in hn:
                        known_domains.add(hn.split(".", 1)[1].lower())

        # T2 PJL fingerprint on 9100/tcp for hosts whose LPD banner said
        # "hp-jetdirect" AND that also expose 9100/tcp. Version-gate for
        # CVE-2010-4107; strictly read-only.
        for (ip, _), pr in lpd_probes.items():
            if pr.get("family") == "hp-jetdirect" and ip in port9100_hosts \
                    and ip not in pjl_probes:
                try:
                    pj = probe_pjl_info(ip)
                except OSError:
                    pj = {}
                pjl_probes[ip] = pj

        # cups-browsed probe: at most once per unique host.
        for ip in {ip for ip, _ in ipp_hosts}:
            try:
                br = probe_cups_browsed(ip)
            except OSError:
                br = {"sent": False, "replied": False}
            browsed_probes[ip] = br

        # /admin + Get-Jobs + version-gate + URI harvest per IPP port.
        for ip, prt in ipp_hosts:
            try:
                ar = probe_admin_endpoints(ip, prt)
            except OSError:
                ar = {}
            # T2 body-pull for the first readable log endpoint. Bounded to
            # 64 KiB — one GET, no auth attempt, no state change. Feeds
            # known_users from any usernames that appear in access_log rows.
            if ar and ar.get("readable"):
                log_path = ar["readable"][0]
                try:
                    body = fetch_admin_log(ip, prt, log_path)
                except OSError:
                    body = b""
                if body:
                    parsed = parse_cups_log(
                        body.decode("latin-1", "replace"))
                    ar["log_body_sample"] = body[:2048].decode(
                        "latin-1", "replace")
                    ar["log_parsed"] = parsed
                    known_users.update(parsed.get("users") or [])
            admin_probes[(ip, prt)] = ar

            # Reuse services.ipp for Get-Printers and its version parse.
            try:
                from . import ipp as _ipp
                ipp_pr = _ipp.probe(ip, prt)
            except OSError:
                ipp_pr = {}
            # URI harvest from what ipp.probe() already walked.
            uh = harvest_uris(ipp_pr.get("printers") or [])
            uri_harvest[(ip, prt)] = uh
            known_hostnames.update(uh.get("hostnames") or [])
            known_domains.update(uh.get("domains") or [])

            # Version gate on ipp.probe's cups_version + Server header.
            version = ipp_pr.get("cups_version") or ""
            server = ipp_pr.get("server") or ""
            if ipp_pr.get("is_cups"):
                vuln, why = cups_vulnerable(version, server)
                version_gate[(ip, prt)] = {"version": version,
                                           "vulnerable": vuln, "why": why}

            # Get-Jobs per printer URI, capped to protect a live spooler.
            for printer in (ipp_pr.get("printers") or [])[:5]:
                uri = printer.get("printer-uri-supported")
                if not uri:
                    continue
                try:
                    jr = ipp_get_jobs(ip, uri, port=prt)
                except OSError:
                    jr = {}
                if jr and jr.get("jobs"):
                    jobs_probes[(ip, prt)] = jr
                    known_users.update(jr.get("users") or [])
                    known_hostnames.update(jr.get("hosts") or [])
                    for hn in jr.get("hosts") or []:
                        if "." in hn:
                            known_domains.add(hn.split(".", 1)[1].lower())
                    break

    fs = findings(hosts, lpd_probes=lpd_probes, jobs_probes=jobs_probes,
                  browsed_probes=browsed_probes, admin_probes=admin_probes,
                  version_gate=version_gate, uri_harvest=uri_harvest,
                  pjl_probes=pjl_probes)

    runbooks = []
    for t in targets_lpd:
        runbooks.append({"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                         "credfree": runbook_lpd(t["ip"], t["port"]),
                         "credentialed": []})
    for ip, prt in ipp_hosts:
        runbooks.append({"target": f"{ip}:{prt}", "ip": ip,
                         "credfree": runbook_cups(ip, prt),
                         "credentialed": []})

    return {
        "targets": targets_lpd
        + [{"ip": ip, "port": prt, "version": ""} for ip, prt in ipp_hosts],
        "findings": fs, "runbooks": runbooks,
        "probes": {
            "lpd": {f"{k[0]}:{k[1]}": v for k, v in lpd_probes.items()},
            "ipp_jobs": {f"{k[0]}:{k[1]}": v for k, v in jobs_probes.items()},
            "cups_browsed": browsed_probes,
            "cups_admin": {f"{k[0]}:{k[1]}": v for k, v in admin_probes.items()},
            "cups_version_gate": {f"{k[0]}:{k[1]}": v for k, v in version_gate.items()},
            "ipp_uri_harvest": {f"{k[0]}:{k[1]}": v for k, v in uri_harvest.items()},
            "pjl_9100": pjl_probes,
        },
        "known": {
            "users": sorted(known_users),
            "hostnames": sorted(known_hostnames),
            "domains": sorted(known_domains),
        },
        "stats": {
            "lpd_targets": len(targets_lpd),
            "ipp_targets": len(ipp_hosts),
            "findings": len(fs),
            "stopped": state.get("stopped"),
        },
    }
