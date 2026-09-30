"""Service-detection enrichment - fill the gaps nmap's -sV leaves behind.

nmap is the primary identifier; when it returns a concrete name we keep it. But
plenty of ports come back `unknown`/`tcpwrapped` or blank - especially Windows
RPC/ephemeral services (5040 CDPSvc, 5357 wsdapi, 47001 winrm-http, dynamic
MSRPC) and anything nmap ships no signature for. This module recovers those in
three escalating, airgapped-safe layers:

  1. servicefp mining   - nmap already collected the service's raw response but
     couldn't match it; we keyword-match those bytes ourselves. Zero new traffic.
  2. curated port map    - a well-known port with no name gets an *inferred* label
     from the port number (how nmap-services / IANA lists work). Zero new traffic.
  3. active banner grab  - a stdlib connect-and-read (plus a few protocol nudges:
     HTTP HEAD, Redis PING, RDP X.224) fingerprints ports the first two missed.
     Only touches the target, no external deps - runs on a stock airgapped Kali.

Every label we set records its provenance in Port.detect_source (nmap / inferred
/ banner) so the sheet can show *how confident* an ID is, and an unmatched port
becomes an actionable to-do (suggest_id_command) instead of a dead "unknown".
"""

from __future__ import annotations

import re
import socket
import ssl

from ..core.models import Host, Port

# --- layer 2: curated port -> (service, human description) ----------------------
# Deliberately scoped to the gaps nmap habitually leaves blank/unknown - mostly
# Windows RPC/ephemeral and a few app ports. NOT a full nmap-services clone; it
# only fills a label when nmap gave us nothing usable.
PORT_NAMES: dict[int, tuple[str, str]] = {
    135: ("msrpc", "Microsoft RPC Endpoint Mapper"),
    593: ("ncacn_http", "MS RPC over HTTP (ncacn_http)"),
    2179: ("vmrdp", "Hyper-V VMConnect (RDP over VMBus)"),
    3389: ("ms-wbt-server", "Remote Desktop (RDP)"),
    5040: ("cdpsvc", "Windows Connected Devices Platform Service (CDPSvc)"),
    5353: ("mdns", "Multicast DNS / Bonjour"),
    5355: ("llmnr", "Link-Local Multicast Name Resolution"),
    5357: ("wsdapi", "Microsoft Web Services on Devices (WSDAPI)"),
    5985: ("wsman", "WinRM / WS-Management (HTTP)"),
    5986: ("wsmans", "WinRM / WS-Management (HTTPS)"),
    47001: ("winrm-http", "WinRM listener (HTTP.sys)"),
    9389: ("adws", "Active Directory Web Services"),
    5722: ("dfsr", "DFS Replication RPC"),
    464: ("kpasswd", "Kerberos password change"),
    49152: ("msrpc", "Dynamic MSRPC (ephemeral)"),
    102: ("iso-tsap", "Siemens S7 / ISO-TSAP"),
    623: ("ipmi", "IPMI / BMC (out-of-band mgmt)"),
    123: ("ntp", "Network Time Protocol"),
    137: ("nbns", "NetBIOS Name Service"),
    69:  ("tftp", "Trivial FTP"),
    631: ("ipp",  "Internet Printing / CUPS"),
    6000: ("x11", "X11 display :0"),
    6001: ("x11", "X11 display :1"),
    5060: ("sip", "Session Initiation Protocol"),
    512: ("exec", "rexec (legacy Berkeley r-service)"),
    513: ("login", "rlogin (legacy Berkeley r-service)"),
    514: ("shell", "rsh (legacy Berkeley r-service)"),
    1900: ("upnp", "UPnP SSDP"),
    2049: ("nfs", "Network File System"),
    111: ("rpcbind", "ONC RPC portmapper"),
    873: ("rsync", "rsync daemon"),
    2375: ("docker", "Docker API (plaintext)"),
    2376: ("docker-s", "Docker API (TLS)"),
    6443: ("kube-apiserver", "Kubernetes API server"),
    9100: ("jetdirect", "Printer / HP JetDirect (raw)"),
    11211: ("memcached", "Memcached"),
    27017: ("mongodb", "MongoDB"),
    6379: ("redis", "Redis"),
    9200: ("elasticsearch", "Elasticsearch (HTTP API)"),
    9300: ("elasticsearch", "Elasticsearch (transport)"),
    5432: ("postgresql", "PostgreSQL"),
    1521: ("oracle-tns", "Oracle TNS listener"),
    # Storage / block / backup:
    3260: ("iscsi", "iSCSI target portal (RFC 7143)"),
    10809: ("nbd", "Network Block Device"),
    10000: ("ndmp", "Network Data Management Protocol (backup)"),
    # OT / ICS:
    47808: ("bacnet", "BACnet/IP building automation (ASHRAE 135)"),
    4840: ("opcua", "OPC UA Binary"),
    4843: ("opcua-tls", "OPC UA over TLS (opc.tcps)"),
    20000: ("dnp3", "DNP3 SCADA outstation (IEEE 1815)"),
    2404: ("iec-104", "IEC 60870-5-104 SCADA"),
    44818: ("ethernetip", "ODVA EtherNet/IP / CIP"),
    2221: ("cip-security", "CIP Security (DTLS/TLS)"),
    # IoT / messaging:
    1883: ("mqtt", "MQTT broker (plaintext, OASIS 3.1.1/v5)"),
    8883: ("secure-mqtt", "MQTT broker (TLS)"),
    1884: ("mqtt", "MQTT broker (Mosquitto WSS convention)"),
    5683: ("coap", "CoAP endpoint (RFC 7252, plaintext UDP)"),
    5684: ("coaps", "CoAP over DTLS (RFC 7252 §9)"),
    # Media / streaming:
    554: ("rtsp", "Real-Time Streaming Protocol"),
    8554: ("rtsp-alt", "RTSP (alt)"),
    322: ("rtsps", "RTSP over TLS (legacy)"),
    # Monitoring / management:
    5666: ("nrpe", "Nagios NRPE agent"),
    10050: ("zabbix-agent", "Zabbix agent — passive-check listener (ZBXD)"),
    10051: ("zabbix-trapper", "Zabbix server/proxy trapper — active checks & auto-registration"),
    8200: ("vault", "HashiCorp Vault API"),
    8201: ("vault-cluster", "Vault cluster/replication"),
    # Virtualization / vSphere:
    902: ("vmware-auth", "VMware host agent (hostd / NFC)"),
    5480: ("vmware-vami", "vCenter Server Appliance VAMI"),
    9443: ("vsphere-client", "vSphere Client / Analytics Service"),
    # Printing:
    515: ("lpd", "Line Printer Daemon (RFC 1179)"),
    # Routing:
    179: ("bgp", "Border Gateway Protocol (RFC 4271)"),
    # Service discovery / SIP-adjacent:
    427: ("slp", "Service Location Protocol"),
    3478: ("stun", "STUN / TURN (unencrypted)"),
    5349: ("turns", "STUN/TURN over TLS"),
    5350: ("nat-pmp-alt", "NAT-PMP / STUN alt"),
    # Remote access / display proxies:
    4822: ("guacd", "Apache Guacamole proxy daemon"),
    # Chat / directory-adjacent:
    5222: ("xmpp-client", "XMPP client-to-server"),
    5223: ("xmpps", "XMPP legacy implicit TLS"),
    5269: ("xmpp-server", "XMPP server-to-server"),
    # Games / SLP:
    25565: ("minecraft", "Minecraft Java Edition server (SLP)"),
    25575: ("minecraft-rcon", "Minecraft Source-RCON (default)"),
    # Legacy directory:
    714: ("ypserv", "NIS ypserv (Sun Yellow Pages)"),
    715: ("ypbind", "NIS ypbind"),
    717: ("ypserv", "NIS ypserv (Sun Yellow Pages, TCP)"),
    834: ("ypserv", "NIS ypserv (Sun)"),
}

# Dynamic MSRPC range (Windows ephemeral high ports) - anything here with no name
# is almost always an RPC endpoint the mapper (135) hands out.
_MSRPC_DYNAMIC = range(49152, 65536)


# --- layers 1 & 3: byte-signature matching --------------------------------------
# (compiled pattern, service name, description). Matched against the servicefp
# nmap kept AND against any banner we grab ourselves. Bytes are decoded latin-1
# so a text regex can scan them without choking on non-UTF-8.
_SIGNATURES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"^SSH-\d"), "ssh", "SSH"),
    (re.compile(r"^RFB \d{3}\."), "vnc", "VNC (RFB)"),
    (re.compile(r"^\+PONG"), "redis", "Redis"),
    (re.compile(r"-ERR .*unknown command|NOAUTH .*Authentication"), "redis", "Redis"),
    (re.compile(r"^220.*\b(FTP|FileZilla|vsFTPd|ProFTPD|Pure-FTPd)\b", re.I), "ftp", "FTP"),
    (re.compile(r"^220.*\b(SMTP|ESMTP|Postfix|Exim|Sendmail)\b", re.I), "smtp", "SMTP"),
    (re.compile(r"^\+OK"), "pop3", "POP3"),
    (re.compile(r"^\* OK.*IMAP", re.I), "imap", "IMAP"),
    (re.compile(r"^HTTP/\d"), "http", "HTTP"),
    (re.compile(r"^\x16\x03[\x00-\x04]"), "ssl", "TLS/SSL"),
    (re.compile(r"^\x03\x00\x00"), "ms-wbt-server", "RDP (X.224)"),
    (re.compile(r"mysql_native_password|^.\x00\x00\x00\x0a\d"), "mysql", "MySQL"),
    (re.compile(r"^\*\x03|MongoDB", re.I), "mongodb", "MongoDB"),
    (re.compile(r"^RTSP/\d"), "rtsp", "RTSP"),
    (re.compile(r"^AMQP\x00"), "amqp", "AMQP / RabbitMQ"),
    (re.compile(r"^\x00\x00\x00.\xffSMB|\xfeSMB"), "smb", "SMB"),
    # Telnet negotiation (IAC WILL/WONT/DO/DONT/SB) — matches any telnetd greeting.
    (re.compile(r"^\xff[\xfa\xfb\xfc\xfd\xfe]"), "telnet", "Telnet (IAC negotiation)"),
    # iSCSI Login Response opcode 0x23.
    (re.compile(r"^\x23[\x00-\xff]\x00[\x00-\xff]"), "iscsi", "iSCSI target portal"),
    # OPC UA Binary uacp headers.
    (re.compile(r"^ACKF"), "opcua", "OPC UA Binary (uacp ACK)"),
    (re.compile(r"^ERRF"), "opcua", "OPC UA Binary (uacp ERR)"),
    # DNP3 sync bytes.
    (re.compile(r"^\x05\x64"), "dnp3", "DNP3 SCADA (IEEE 1815)"),
    # IEC 60870-5-104 U-format start sequence.
    (re.compile(r"^\x68\x04[\x07\x0b\x13\x23\x43\x83]\x00\x00\x00"), "iec-104",
     "IEC 60870-5-104 SCADA"),
    # ODVA EtherNet/IP encapsulation replies.
    (re.compile(r"^\x63\x00.{2}", re.DOTALL), "ethernetip",
     "ODVA EtherNet/IP (List Identity reply)"),
    (re.compile(r"^\x65\x00\x04\x00", re.DOTALL), "ethernetip",
     "ODVA EtherNet/IP (RegisterSession reply)"),
    # MQTT CONNACK (0x20 rl=0x02 flags rc); PUBLISH signature deliberately omitted
    # since 0x30 is ASCII '0' and would match too many text banners.
    (re.compile(r"^\x20\x02[\x00\x01][\x00-\x05]"), "mqtt", "MQTT (CONNACK)"),
    # NRPE v2 response header (packet_version=2, packet_type=response=2).
    (re.compile(r"^\x00\x02\x00\x02"), "nrpe", "Nagios NRPE"),
    # Zabbix ZBXD (v1 plaintext / v3 compressed).
    (re.compile(r"^ZBXD[\x01\x03]"), "zabbix", "Zabbix agent/server (ZBXD)"),
    # Jenkins JNLP agent listener greeting.
    (re.compile(r"^Unknown protocol: PROTOCOL_|^Protocol:.*not understood|"
                r"Supported protocols:.*PROTOCOL_JNLP|Jenkins-Agent-Protocols", re.I),
     "jnlp-agent", "Jenkins JNLP agent listener"),
    # LPD ASCII responses.
    (re.compile(r"^\x00$|^no entries\b|^Printer:\s|^Rank\s+Owner\s+Job\b",
                re.I | re.M), "lpd", "Line Printer Daemon (RFC 1179)"),
    # NBD magic (fixed-newstyle and oldstyle).
    (re.compile(r"^NBDMAGICIHAVEOPT"), "nbd", "NBD (fixed-newstyle)"),
    (re.compile(r"^NBDMAGIC\x00\x00\x42\x02\x81\x86\x12\x53"), "nbd", "NBD (oldstyle)"),
    # BGP marker (16 bytes of 0xFF, length, type in 1..5).
    (re.compile(r"^\xff{16}..[\x01-\x05]"), "bgp", "BGP (marker)"),
    # Apache Guacamole guacd args frame (VERSION_x_y_z).
    (re.compile(r"^\d+\.args,\d+\.VERSION_\d+_\d+_\d+,"), "guacamole",
     "Apache Guacamole proxy daemon"),
    # XMPP stream open.
    (re.compile(r"<stream:stream[^>]*xmlns(?::stream)?=[\"']http://etherx\.jabber\.org/streams[\"']"
                r"|xmlns=[\"']jabber:(?:client|server)[\"']", re.I),
     "xmpp", "XMPP stream"),
    # Minecraft Java Edition SLP status response JSON prelude.
    (re.compile(r'\{"version"\s*:\s*\{[^}]*"protocol"'), "minecraft",
     "Minecraft Java Edition SLP"),
    # VMware vSphere SDK banner cues.
    (re.compile(r"Server:\s*VMware/", re.I), "vsphere-sdk", "VMware vSphere SDK"),
    (re.compile(r"ID_VC_Welcome|ID_EESX_Welcome"), "vsphere-sdk",
     "VMware vSphere SDK"),
]


def _match_signature(data: str) -> tuple[str, str] | None:
    for pat, name, desc in _SIGNATURES:
        if pat.search(data):
            return name, desc
    return None


# --- product/version extraction (feeds CVE mapping) -----------------------------
# nmap -sV names the *service* but frequently leaves product/version blank on the
# ports it half-identified (and always on the ones we banner-grabbed ourselves).
# A concrete "OpenSSH 8.9p1" / "Exim 4.94" / "vsFTPd 3.0.3" is what the CVE mapper
# keys on, so we mine it out of the banner ourselves - no new traffic beyond the
# banner we already hold. Each pattern captures named groups `prod` and `ver`.
_PRODUCT_RE: list[re.Pattern] = [
    # SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu" / "SSH-2.0-dropbear_2020.81"
    re.compile(r"SSH-2\.0-(?P<prod>OpenSSH|dropbear|libssh|ROSSSH)[_-]"
               r"(?P<ver>\d[\w.]*)", re.I),
    # FTP: "220 (vsFTPd 3.0.3)", "220 ProFTPD 1.3.5 Server", "FileZilla Server 0.9.60"
    re.compile(r"(?P<prod>vsFTPd|ProFTPD|Pure-FTPd|FileZilla Server|CrushFTP|"
               r"wu-ftpd|Serv-U)\)?\s*v?(?P<ver>\d[\w.]*)", re.I),
    # SMTP: "220 x ESMTP Postfix (Ubuntu)" / "Exim 4.94" / "Sendmail 8.15.2"
    re.compile(r"(?P<prod>Postfix|Exim|Sendmail|OpenSMTPD|Haraka|Microsoft ESMTP)"
               r"[\s/v]*(?P<ver>\d[\w.]*)", re.I),
    # MySQL/MariaDB handshake carries the version first: "5.5.5-10.3.34-MariaDB"
    re.compile(r"(?P<ver>\d+\.\d+\.\d+)-(?P<prod>MariaDB|MySQL)", re.I),
    re.compile(r"(?P<prod>MySQL|MariaDB|Percona)[\s/v]*(?P<ver>\d+\.\d+\.\d+)", re.I),
    # POP3/IMAP/mail greeters (broader vendor set feeds the CVE mapper).
    re.compile(r"(?P<prod>Dovecot|Courier|Cyrus IMAP|Cyrus|qpopper|MDaemon|Zimbra|"
               r"Microsoft Exchange|IMail|hMailServer)"
               r"(?:[\s/v]+(?P<ver>\d[\w.]*))?", re.I),
    # XMPP servers (stream errors + XEP-0092 replies).
    re.compile(r"(?P<prod>Prosody|ejabberd|Openfire|OpenFire|Tigase)"
               r"[\s/v]*(?P<ver>\d[\w.]*)", re.I),
    # Apache Guacamole guacd — product tag on its own; version normalisation for
    # the VERSION_x_y_z token is left to callers holding the full args frame.
    re.compile(r"(?P<prod>Apache Guacamole|guacd)(?:[\s/v_]+(?P<ver>\d[\w.]*))?", re.I),
    # HTTP Server header (non-web-classified ports still get product for CVEs)
    re.compile(r"Server:\s*(?P<prod>Apache|nginx|Microsoft-IIS|lighttpd|Jetty|"
               r"Caddy|openresty|Tomcat|Werkzeug|gunicorn|Boa|GoAhead|mini_httpd)"
               r"/(?P<ver>\d[\w.]*)", re.I),
    # SMTP/other generic "Product/1.2.3" fallback (bounded to word-ish products)
]


def parse_product_version(text: str) -> tuple[str, str] | None:
    """Best-effort (product, version) from a banner/servicefp string. Returns None
    when nothing concrete matches. Version may be '' if only a product is sure."""
    if not text:
        return None
    for pat in _PRODUCT_RE:
        m = pat.search(text)
        if m:
            prod = (m.groupdict().get("prod") or "").strip()
            ver = (m.groupdict().get("ver") or "").strip()
            if prod:
                return prod, ver
    return None


# --- active banner grab (layer 3) -----------------------------------------------

_BANNER_TIMEOUT = 4.0
_READ = 512

# Ports where the service stays silent until spoken to - send a tiny, protocol-
# appropriate nudge so we actually get bytes back. Everything else we just read
# (FTP/SMTP/SSH/POP/IMAP/VNC announce themselves on connect).
_HTTP_NUDGE = b"HEAD / HTTP/1.0\r\n\r\n"
# Telnet IAC AYT — many telnetds respond with '[Yes]' or a fresh IAC stream.
_TELNET_AYT = b"\xff\xf6"
# MQTT v3.1.1 minimal CONNECT (client-id blank, keepalive 30s).
_MQTT_CONNECT_NUDGE = (bytes([0x10, 0x0c, 0x00, 0x04]) + b"MQTT"
                       + bytes([0x04, 0x02, 0x00, 0x1e, 0x00, 0x00]))
_NUDGE = {
    80: _HTTP_NUDGE, 8080: _HTTP_NUDGE, 8000: _HTTP_NUDGE, 8888: _HTTP_NUDGE,
    5000: _HTTP_NUDGE, 3000: _HTTP_NUDGE,
    6379: b"PING\r\n", 11211: b"version\r\n",
    23: _TELNET_AYT, 2323: _TELNET_AYT, 5555: _TELNET_AYT,
    1883: _MQTT_CONNECT_NUDGE, 8883: _MQTT_CONNECT_NUDGE, 1884: _MQTT_CONNECT_NUDGE,
}
# RDP: an X.224 Connection Request. Cheap, and the response starts 0x03 0x00.
_RDP_CR = bytes.fromhex("0300000b06e00000000000")


def grab_banner(ip: str, port: Port, timeout: float | None = None) -> str:
    """Connect, (optionally nudge), read up to 512 bytes. Returns the raw bytes
    decoded latin-1 (lossless), or "" on any failure. Never raises."""
    from ..core import proxy
    if timeout is None:
        timeout = proxy.scaled(_BANNER_TIMEOUT)     # slower through a pivot
    pid = port.portid
    nudge = _NUDGE.get(pid)
    if pid == 3389:
        nudge = _RDP_CR
    try:
        with socket.create_connection((ip, pid), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(_READ)          # many services greet on connect
            except (socket.timeout, OSError):
                data = b""
            if not data and nudge:
                try:
                    s.sendall(nudge)
                    data = s.recv(_READ)
                except OSError:
                    data = b""
            # Last-resort HTTP probe: a web app on a non-standard port (custom API,
            # qdrant, an internal tool) stays mute until spoken to and has no nudge
            # of its own, so it used to come back "unknown" and get ZERO web/api
            # enum - a real finding silently dropped. HTTP is by far the commonest
            # thing to find on an arbitrary high port; one HEAD confirms it. A non-
            # HTTP service just won't answer with "HTTP/", so _match_signature stays
            # silent and no wrong label is set.
            if not data and nudge is None:
                try:
                    s.sendall(_HTTP_NUDGE)
                    data = s.recv(_READ)
                except OSError:
                    data = b""
            return data.decode("latin-1", "replace") if data else ""
    except OSError:
        return ""


def tls_http_probe(ip: str, port: Port, timeout: float | None = None) -> str:
    """Complete a TLS handshake then send one HTTP request over it. Returns the
    HTTP response banner if the port speaks HTTPS, else "".

    The plaintext grab_banner can't see a TLS service - an HTTPS server on a non-
    standard port answers a plaintext HEAD with a TLS alert (or nothing), so it
    stayed "unknown" and got no web/api enum, exactly the false negative the
    plaintext fallback fixed for cleartext HTTP. This is the TLS twin: handshake
    first, then HEAD. Certs are not verified (we're fingerprinting, not trusting).
    Never raises - any handshake/socket failure just means "not HTTPS here"."""
    from ..core import proxy
    if timeout is None:
        timeout = proxy.scaled(_BANNER_TIMEOUT)     # slower through a pivot
    ctx = ssl._create_unverified_context()
    ctx.check_hostname = False
    try:
        with socket.create_connection((ip, port.portid), timeout=timeout) as raw:
            raw.settimeout(timeout)
            try:
                # server_hostname must be set for SNI; an IP literal is fine with
                # verification off (no hostname matching happens).
                with ctx.wrap_socket(raw, server_hostname=ip) as tls:
                    tls.sendall(_HTTP_NUDGE)
                    data = tls.recv(_READ)
            except (ssl.SSLError, socket.timeout, OSError, ValueError):
                return ""
    except OSError:
        return ""
    return data.decode("latin-1", "replace") if data else ""


# --- orchestration --------------------------------------------------------------

def _needs_id(port: Port) -> bool:
    """True when nmap left this port without a real service name."""
    return (not port.service) or port.service in ("unknown", "tcpwrapped")


def infer_port_name(port: Port) -> tuple[str, str] | None:
    """Layers 1+2 (no network): mine nmap's kept servicefp, else the curated port
    map. Returns (service, description) or None."""
    if port.servicefp:
        hit = _match_signature(port.servicefp)
        if hit:
            return hit
    if port.portid in PORT_NAMES:
        return PORT_NAMES[port.portid]
    if port.portid in _MSRPC_DYNAMIC:
        return ("msrpc", "Dynamic MSRPC endpoint (ephemeral)")
    return None


def enrich_port(ip: str, port: Port, active: bool = True) -> bool:
    """Fill a missing service label for one port. Passive layers first (free),
    then an active banner grab if `active`. Returns True if a label was set or
    upgraded. nmap-sourced names are never overwritten."""
    if port.detect_source == "nmap":
        return False
    changed = False
    hit = infer_port_name(port)
    if hit and _needs_id(port):
        port.service = hit[0]
        port.extrainfo = port.extrainfo or hit[1]
        port.detect_source = "inferred"        # a good guess; a banner confirms it
        changed = True
    if not active:
        return changed
    banner = grab_banner(ip, port)
    if banner:
        port.banner = banner[:200]
        sig = _match_signature(banner)
        if sig:
            port.service = sig[0]
            port.extrainfo = port.extrainfo or sig[1]
            port.detect_source = "banner"      # strongest of our own evidence
            changed = True
        if _fill_product(port, banner):        # concrete product+version -> CVEs
            changed = True
    # Silent-HTTPS recovery: if a plaintext probe couldn't name it, the service may
    # be TLS-wrapped (a custom HTTPS app on an odd port). One handshake + HEAD tells
    # us. Label it "https" explicitly so _is_tls AND _is_http both fire (scheme https
    # + web/api enum). Only runs when still unidentified, so it costs nothing on the
    # ports the cheaper layers already resolved.
    if _needs_id(port):
        tls_banner = tls_http_probe(ip, port)
        if tls_banner:
            sig = _match_signature(tls_banner)
            if sig and sig[0] == "http":
                port.service = "https"
                port.extrainfo = port.extrainfo or "HTTP over TLS"
                port.banner = tls_banner[:200]
                port.detect_source = "banner"
                _fill_product(port, tls_banner)
                changed = True
    return changed


def _fill_product(port: Port, text: str) -> bool:
    """Set port.product/version from a banner when nmap left them blank. Never
    overwrites a product nmap already gave us. Returns True if it filled one."""
    if port.product:                           # nmap's product wins; don't clobber
        return False
    pv = parse_product_version(text)
    if not pv:
        return False
    port.product, ver = pv
    if ver and not port.version:
        port.version = ver
    return True


def enrich_versions(host: Host) -> int:
    """No-traffic pass: recover product/version from evidence we ALREADY hold
    (nmap's kept servicefp + any banner we captured) for ports that have a service
    name but no product - so the CVE mapper gets a version to key on. Runs even on
    nmap-named ports; only ever *fills* a blank product, never overwrites. Returns
    the number of ports enriched."""
    n = 0
    for port in host.open_ports:
        if port.product:
            continue
        for src in (port.banner, port.servicefp):
            if _fill_product(port, src):
                n += 1
                break
    return n


def enrich_host(host: Host, active: bool = True) -> int:
    """Enrich every open port on a host that nmap didn't concretely identify.
    Returns the number of ports we set/upgraded a label for."""
    n = 0
    for port in host.open_ports:
        if port.detect_source == "nmap":
            continue
        if enrich_port(host.ip, port, active=active):
            n += 1
    # No-traffic version recovery across ALL ports (incl. nmap-named ones that
    # lack a product) - fills the version the CVE mapper keys on.
    enrich_versions(host)
    return n


def still_unknown_ports(host: Host) -> list[int]:
    """Open ports we STILL couldn't name after the passive + active layers - the
    candidates for a second-opinion nmap re-probe."""
    return [p.portid for p in host.open_ports if _needs_id(p)]


def apply_reprobe(host: Host, parsed_hosts: list) -> int:
    """Fold a second-opinion nmap `-sV --version-all` re-probe back in: upgrade any
    port nmap has now concretely named (its answer is authoritative, so it wins
    over our inferred/banner guesses). Returns the number of ports upgraded."""
    idx = {(p.protocol, p.portid): p for p in host.ports}
    upgraded = 0
    for ph in parsed_hosts:
        if ph.ip != host.ip:
            continue
        for rp in ph.ports:
            cur = idx.get((rp.protocol, rp.portid))
            if cur is None:
                continue
            if rp.service and rp.service not in ("unknown", "tcpwrapped"):
                cur.service = rp.service
                cur.product = rp.product or cur.product
                cur.version = rp.version or cur.version
                cur.extrainfo = rp.extrainfo or cur.extrainfo
                if rp.cpe:
                    cur.cpe = rp.cpe
                cur.detect_source = "nmap"
                upgraded += 1
    return upgraded


def suggest_id_command(ip: str, port: Port) -> str:
    """The next command a tester should run to positively ID a still-unknown port
    - so 'unknown' is an actionable to-do, not a shrug."""
    p = port.portid
    if _needs_id(port):
        return f"nmap -sV --version-all -p {p} {ip}   # or: amap -A {ip} {p}"
    return ""
