"""Deep iSCSI (3260/tcp) enumeration (stdlib only).

iSCSI (RFC 7143) tunnels SCSI over TCP so an initiator can mount raw block LUNs
on a remote target. recce speaks the iSCSI Login/Text PDUs directly (no
open-iscsi driver) to CONFIRM the exposure, read-only:

  * **Login SecurityNegotiation** - the discriminator. A Login Response with
    opcode 0x23 confirms iSCSI; the Text key/value payload names the target's
    AuthMethod list. StatusClass=0 with no CHAP round-trip = AuthMethod=None
    accepted for a Discovery session (baseline exposure).
  * **SendTargets=All (Text Request)** - drains every TargetName + TargetAddress
    the portal advertises: full storage catalogue + internal-only portal IPs.
  * **Normal-session Login** - re-Login with SessionType=Normal against a
    discovered TargetName; a successful transition to FullFeaturePhase proves
    an attacker can mount the LUN with no credential.
  * **INQUIRY + READ CAPACITY (10)** - read-only SCSI proof against LUN 0 that
    the array is actually readable; fingerprints the vendor/product/revision.

CHAP negotiation is captured (challenge + id are hashcat -m 4800 material) and
the exchange is closed - recce never sends bogus responses or SCSI WRITEs.
"""
from __future__ import annotations

import os
import re
import socket
import struct

from ..core import proxy
from ..core.models import Host, Port
from .svccommon import (finding_builder, make_findings_to_vulns_wrapper,
                        make_proof_html_wrapper)

_DEFAULT_PORT = 3260
_TIMEOUT = 6.0
_MAX_DATA_SEGMENT = 256 * 1024
_INITIATOR_NAME = "iqn.2005-03.org.open-iscsi:recce"

# iSCSI opcodes (RFC 7143 §11).
_OP_NOP_OUT = 0x00
_OP_SCSI_CMD = 0x01
_OP_LOGIN_REQ = 0x03
_OP_TEXT_REQ = 0x04
_OP_LOGOUT_REQ = 0x06
_OP_SCSI_RESP = 0x21
_OP_LOGIN_RESP = 0x23
_OP_TEXT_RESP = 0x24
_OP_SCSI_DATA_IN = 0x25

# Login stages.
_STAGE_SECURITY = 0
_STAGE_OP = 1
_STAGE_FULLFEATURE = 3

# Status classes (RFC 7143 §11.13.4).
_STATUS_SUCCESS = 0
_STATUS_REDIRECT = 1
_STATUS_INITIATOR_ERR = 2
_STATUS_TARGET_ERR = 3


def is_iscsi(port: Port) -> bool:
    if port.portid == _DEFAULT_PORT:
        return True
    blob = f"{port.service} {port.product}".lower()
    return "iscsi" in blob or "iscsi-target" in blob


def iscsi_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_iscsi(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product or "", "version": p.version or ""})
    return out


# --- BHS + framing --------------------------------------------------------------

def _pad4(n: int) -> int:
    return (4 - (n & 3)) & 3


def _build_login_bhs(t: bool, csg: int, nsg: int, isid: bytes, tsih: int,
                     itt: int, cmdsn: int, expstatsn: int,
                     data_seg: bytes, version_max: int = 0x00,
                     version_min: int = 0x00) -> bytes:
    """Assemble a 48-byte iSCSI Login Request BHS. Immediate (I) is always set on
    Login (RFC 7143 §11.12). CSG/NSG are 2 bits each; T is bit 7 of byte 1."""
    opcode = _OP_LOGIN_REQ | 0x40                          # I=1
    flags = ((0x80 if t else 0x00)
             | ((csg & 0x03) << 2)
             | (nsg & 0x03))
    dsl = len(data_seg)
    if dsl > 0xFFFFFF:
        raise ValueError("Login data segment too long")
    bhs = struct.pack(
        ">BBBB"                                            # opcode, flags, vmax, vmin
        "B3s"                                              # TotalAHSLength, DataSegmentLength (3B BE)
        "6s"                                               # ISID
        "H"                                                # TSIH
        "I"                                                # ITT
        "HH"                                               # CID, reserved
        "II"                                               # CmdSN, ExpStatSN
        "16s",                                             # reserved
        opcode, flags, version_max, version_min,
        0, dsl.to_bytes(3, "big"),
        isid, tsih & 0xFFFF, itt & 0xFFFFFFFF, 1, 0,
        cmdsn & 0xFFFFFFFF, expstatsn & 0xFFFFFFFF,
        b"\x00" * 16,
    )
    return bhs + data_seg + b"\x00" * _pad4(dsl)


def _build_text_bhs(f: bool, c: bool, itt: int, cmdsn: int, expstatsn: int,
                    ttt: int, data_seg: bytes,
                    lun: bytes = b"\x00" * 8) -> bytes:
    """Assemble a 48-byte Text Request BHS (RFC 7143 §11.10). F=Final, C=Continue.
    Immediate is set so recce's SendTargets is answered on this connection."""
    opcode = _OP_TEXT_REQ | 0x40
    flags = ((0x80 if f else 0x00) | (0x40 if c else 0x00))
    dsl = len(data_seg)
    bhs = struct.pack(
        ">BBBBB3s8sIIIIII8s",
        opcode, flags, 0, 0,
        0, dsl.to_bytes(3, "big"),
        lun,
        itt & 0xFFFFFFFF,
        ttt & 0xFFFFFFFF,
        cmdsn & 0xFFFFFFFF,
        expstatsn & 0xFFFFFFFF,
        0, 0,
        b"\x00" * 8,
    )
    return bhs + data_seg + b"\x00" * _pad4(dsl)


def _build_scsi_cmd_bhs(read: bool, itt: int, cmdsn: int, expstatsn: int,
                        cdb: bytes, expected_len: int,
                        lun: bytes = b"\x00" * 8) -> bytes:
    """Assemble a 48-byte SCSI Command PDU (RFC 7143 §11.3). F=1 always, R set for
    Data-In. CDB is padded/truncated to 16 bytes (no AHS for CDBs <= 16)."""
    opcode = _OP_SCSI_CMD | 0x40
    flags = 0x80 | (0x40 if read else 0x00)               # F | R
    cdb16 = (cdb + b"\x00" * 16)[:16]
    return struct.pack(
        ">BBBBB3s8sIIIII16s",
        opcode, flags, 0, 0,
        0, (0).to_bytes(3, "big"),
        lun,
        itt & 0xFFFFFFFF,
        expected_len & 0xFFFFFFFF,
        cmdsn & 0xFFFFFFFF,
        expstatsn & 0xFFFFFFFF,
        0,
        cdb16,
    )


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buf += chunk
    return buf


def _read_pdu(sock: socket.socket) -> tuple[bytes, bytes] | tuple[None, None]:
    """Read one iSCSI PDU. Returns (bhs, data_segment) or (None, None) on EOF."""
    bhs = _recv_exact(sock, 48)
    if len(bhs) < 48:
        return None, None
    ahs_len = bhs[4]
    dsl = int.from_bytes(bhs[5:8], "big")
    if dsl > _MAX_DATA_SEGMENT:
        raise ValueError(f"iSCSI PDU data segment {dsl} exceeds cap {_MAX_DATA_SEGMENT}")
    total = ahs_len * 4 + dsl
    if total:
        pad = _pad4(dsl)
        rest = _recv_exact(sock, total + pad)
        if len(rest) < total + pad:
            return None, None
        data = rest[ahs_len * 4:ahs_len * 4 + dsl]
    else:
        data = b""
    return bhs, data


# --- key/value payload (login + text) ------------------------------------------

def _kvpairs(kvs: dict) -> bytes:
    """Encode key=value pairs as a NUL-terminated data segment."""
    out = b""
    for k, v in kvs.items():
        out += f"{k}={v}".encode("ascii", "replace") + b"\x00"
    return out


def _parse_kvpairs(data: bytes) -> list[tuple[str, str]]:
    """Parse NUL-separated key=value pairs. Duplicate keys are preserved (iSCSI
    intentionally sends multiple TargetName entries in one SendTargets response)."""
    out: list[tuple[str, str]] = []
    for chunk in data.split(b"\x00"):
        if not chunk:
            continue
        try:
            s = chunk.decode("utf-8")
        except UnicodeDecodeError:
            s = chunk.decode("utf-8", "replace")
        if "=" not in s:
            continue
        k, _, v = s.partition("=")
        out.append((k, v))
    return out


def _make_isid() -> bytes:
    """Random-format ISID (RFC 3720 §10.12.5: first two bits = 10)."""
    return b"\x80" + os.urandom(5)


# --- Login exchanges ------------------------------------------------------------

def _parse_login_response(bhs: bytes, data: bytes) -> dict:
    """Read the fields recce keys on from a Login Response BHS."""
    if len(bhs) < 48 or bhs[0] != _OP_LOGIN_RESP:
        return {}
    tsih = struct.unpack(">H", bhs[14:16])[0]
    return {
        "opcode": bhs[0],
        "T": bool(bhs[1] & 0x80),
        "C": bool(bhs[1] & 0x40),
        "csg": (bhs[1] >> 2) & 0x03,
        "nsg": bhs[1] & 0x03,
        "version_max": bhs[2],
        "version_active": bhs[3],
        "tsih": tsih,
        "status_class": bhs[36],
        "status_detail": bhs[37],
        "kv": _parse_kvpairs(data),
    }


def _login_send_recv(sock: socket.socket, kvs: dict, isid: bytes, tsih: int,
                     itt: int, cmdsn: int, expstatsn: int,
                     t: bool, csg: int, nsg: int,
                     version_max: int = 0x00, version_min: int = 0x00) -> dict:
    pdu = _build_login_bhs(t, csg, nsg, isid, tsih, itt, cmdsn, expstatsn,
                           _kvpairs(kvs), version_max=version_max,
                           version_min=version_min)
    sock.sendall(pdu)
    bhs, data = _read_pdu(sock)
    if bhs is None:
        return {}
    return _parse_login_response(bhs, data)


# --- IQN parsing ---------------------------------------------------------------

_IQN_RE = re.compile(r"^iqn\.(\d{4}-\d{2})\.([^:]+)(?::(.+))?$")


def parse_iqn(iqn: str) -> dict:
    """Split an IQN into date / reversed-domain / host-tail; derive an FQDN hint
    and a hostname hint (e.g. `iqn.2001-04.com.example:storage.sql01` ->
    domain=example.com, host=sql01.storage)."""
    m = _IQN_RE.match(iqn.strip())
    if not m:
        return {}
    date, rev_domain, tail = m.group(1), m.group(2), m.group(3) or ""
    domain = ".".join(reversed(rev_domain.split(".")))
    host = ""
    if tail:
        host = ".".join(reversed(tail.split(".")))
    return {"date": date, "domain": domain, "host": host,
            "reversed_domain": rev_domain, "tail": tail}


def _parse_target_address(addr: str) -> tuple[str, int, str]:
    """Parse `ip:port,portalgroup` (RFC 7143 §12.6). IPv6 addresses are bracketed."""
    portal_group = ""
    if "," in addr:
        addr, _, portal_group = addr.partition(",")
    if addr.startswith("["):
        end = addr.find("]")
        if end < 0:
            return addr, _DEFAULT_PORT, portal_group
        host = addr[1:end]
        rest = addr[end + 1:]
        port = int(rest.lstrip(":") or _DEFAULT_PORT) if rest else _DEFAULT_PORT
        return host, port, portal_group
    if ":" in addr:
        host, _, p = addr.partition(":")
        try:
            return host, int(p), portal_group
        except ValueError:
            return host, _DEFAULT_PORT, portal_group
    return addr, _DEFAULT_PORT, portal_group


def _parse_sendtargets(kv: list[tuple[str, str]]) -> list[dict]:
    """Group `TargetName=iqn...` / `TargetAddress=ip:port,pg` pairs into one dict
    per target. Addresses that follow a TargetName attach to that target."""
    out: list[dict] = []
    cur: dict | None = None
    for k, v in kv:
        if k == "TargetName":
            cur = {"iqn": v, "addresses": []}
            out.append(cur)
        elif k == "TargetAddress" and cur is not None:
            host, port, pg = _parse_target_address(v)
            cur["addresses"].append({"ip": host, "port": port, "portal_group": pg})
    return out


# --- SCSI helpers --------------------------------------------------------------

def _parse_scsi_response(bhs: bytes, data: bytes) -> dict:
    """Decode SCSI Data-In (0x25) or SCSI Response (0x21) into a dict."""
    op = bhs[0] & 0x3F
    if op == _OP_SCSI_DATA_IN:
        flags = bhs[1]
        status = bhs[3] if flags & 0x01 else 0             # S bit: Status present
        return {"opcode": op, "status": status, "data": data}
    if op == _OP_SCSI_RESP:
        return {"opcode": op, "response": bhs[2], "status": bhs[3], "data": data}
    return {"opcode": op, "data": data}


def _parse_inquiry(data: bytes) -> dict:
    """Parse a Standard INQUIRY response (SPC-4 §6.6). Returns vendor/product/
    revision plus the peripheral device type."""
    if len(data) < 36:
        return {}
    return {
        "device_type": data[0] & 0x1F,
        "vendor": data[8:16].decode("ascii", "replace").strip(),
        "product": data[16:32].decode("ascii", "replace").strip(),
        "revision": data[32:36].decode("ascii", "replace").strip(),
    }


def _parse_read_capacity10(data: bytes) -> dict:
    """Parse READ CAPACITY (10) response (SBC-3 §5.15): last-LBA + block-size."""
    if len(data) < 8:
        return {}
    last_lba, block = struct.unpack(">II", data[:8])
    return {"last_lba": last_lba, "blocks": last_lba + 1, "block_size": block,
            "capacity_bytes": (last_lba + 1) * block}


# --- probe orchestrator --------------------------------------------------------

def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT,
          do_inquiry: bool = True) -> dict:
    """Drive the full discovery: Login SecNeg -> AuthMethod inspection -> optional
    LoginOp transition -> SendTargets -> optional Normal Login + INQUIRY/READ
    CAPACITY on LUN 0. Returns a dict of everything observed; findings() maps it
    to structured items."""
    out: dict = {
        "reachable": False, "is_iscsi": False,
        "auth_methods": [], "auth_selected": "",
        "discovery_no_auth": False, "operational_reached": False,
        "targets": [], "op_params": {},
        "chap": {}, "chap_one_way": False,
        "version_max": 0, "version_active": 0, "legacy_version": False,
        "normal_login": {}, "inquiry": {}, "read_capacity": {},
        "error": "",
    }
    isid = _make_isid()
    itt = 0
    cmdsn = 0
    expstatsn = 0
    try:
        with socket.create_connection((ip, port), timeout=proxy.scaled(timeout)) as sock:
            sock.settimeout(proxy.scaled(timeout))
            # 1. Login SecurityNegotiation: advertise None,CHAP as our AuthMethod choices.
            #    T=1 means we would transition to LoginOperationalNegotiation if the
            #    target accepts AuthMethod=None on this PDU.
            kvs = {
                "InitiatorName": _INITIATOR_NAME,
                "SessionType": "Discovery",
                "AuthMethod": "None,CHAP",
            }
            resp = _login_send_recv(sock, kvs, isid, 0, itt, cmdsn, expstatsn,
                                    t=True, csg=_STAGE_SECURITY, nsg=_STAGE_OP)
            if not resp:
                out["error"] = "no Login Response"
                return out
            out["reachable"] = True
            if resp.get("opcode") != _OP_LOGIN_RESP:
                out["error"] = f"unexpected opcode {resp.get('opcode'):#x}"
                return out
            out["is_iscsi"] = True
            out["version_max"] = resp.get("version_max", 0)
            out["version_active"] = resp.get("version_active", 0)
            out["legacy_version"] = out["version_active"] not in (0, 0x00)
            status_class = resp.get("status_class")
            if status_class not in (_STATUS_SUCCESS, _STATUS_REDIRECT):
                out["error"] = (f"login refused status_class={status_class} "
                                f"detail={resp.get('status_detail')}")
                return out
            # AuthMethod negotiation lives in the key/value payload. The target
            # either echoes the chosen AuthMethod (concrete decision) or replies
            # with an AuthMethod= key listing what it will accept.
            selected = ""
            offered: list[str] = []
            for k, v in resp["kv"]:
                if k == "AuthMethod":
                    selected = v
                    for m in v.split(","):
                        m = m.strip()
                        if m and m not in offered:
                            offered.append(m)
            out["auth_methods"] = offered
            out["auth_selected"] = selected
            cmdsn += 1
            expstatsn = 0
            itt += 1

            # 2. AuthMethod=None accepted for Discovery? The target either
            #    completes the transition itself (T=1, NSG=1) or echoes
            #    AuthMethod=None and expects a follow-up transition PDU.
            reached_op = (resp.get("T") and resp.get("nsg") == _STAGE_OP)
            if selected.strip() == "None":
                out["discovery_no_auth"] = True
                if not reached_op:
                    # Send an empty LoginOp transition PDU (T=1, CSG=1, NSG=3 is
                    # a common shortcut but we only need CSG=1 here).
                    op_kvs = {
                        "HeaderDigest": "None",
                        "DataDigest": "None",
                        "MaxRecvDataSegmentLength": "8192",
                        "DefaultTime2Wait": "2",
                        "DefaultTime2Retain": "0",
                    }
                    resp2 = _login_send_recv(sock, op_kvs, isid, resp.get("tsih", 0),
                                             itt, cmdsn, expstatsn,
                                             t=True, csg=_STAGE_OP,
                                             nsg=_STAGE_FULLFEATURE)
                    if resp2 and resp2.get("status_class") == _STATUS_SUCCESS:
                        reached_op = True
                        for k, v in resp2["kv"]:
                            out["op_params"][k] = v
                    cmdsn += 1
                    itt += 1
                out["operational_reached"] = reached_op

            # 3. CHAP negotiation - only when the target selected CHAP for us.
            if selected.strip() == "CHAP":
                chap_a_resp = _login_send_recv(
                    sock, {"CHAP_A": "5"}, isid, resp.get("tsih", 0),
                    itt, cmdsn, expstatsn,
                    t=False, csg=_STAGE_SECURITY, nsg=_STAGE_SECURITY)
                cmdsn += 1
                itt += 1
                if chap_a_resp:
                    cap: dict = {}
                    for k, v in chap_a_resp["kv"]:
                        if k == "CHAP_A":
                            cap["algorithm"] = v
                        elif k == "CHAP_I":
                            cap["id"] = v
                        elif k == "CHAP_C":
                            cap["challenge"] = v
                    if cap.get("id") and cap.get("challenge"):
                        cap["hashcat_mode"] = 4800
                        out["chap"] = cap
                        # One-way vs mutual: after we (would) send CHAP_R the
                        # target should return CHAP_I/CHAP_C of its own. recce
                        # does NOT send a bogus response, but the target's
                        # selected auth alone (no CHAP_N asked back from us via
                        # a mutual-CHAP hint) is enough to note that mutual
                        # CHAP was NOT demanded up-front.
                        out["chap_one_way"] = "CHAP_N" not in {
                            k for k, _ in chap_a_resp["kv"]}
                # We do not send CHAP_R - conservative capture only.
                return out

            # 4. SendTargets sweep once discovery Login succeeded.
            if out["discovery_no_auth"] and out["operational_reached"]:
                targets = _sendtargets(sock, itt, cmdsn, expstatsn)
                cmdsn += 1
                itt += 1
                out["targets"] = targets
    except (OSError, socket.timeout, ValueError, struct.error) as e:
        out["error"] = out["error"] or str(e)
        return out

    # 5. Normal Login (fresh connection) against the first discovered target -
    #    a successful FullFeaturePhase transition proves LUN mount without a
    #    credential. Best-effort: on any failure, `normal_login` stays empty.
    if do_inquiry and out["targets"]:
        first = out["targets"][0]
        addr = first["addresses"][0] if first["addresses"] else {"ip": ip, "port": port}
        try:
            n = _normal_login_and_inquiry(addr["ip"], addr["port"], first["iqn"], timeout)
            out["normal_login"] = n.get("login", {})
            out["inquiry"] = n.get("inquiry", {})
            out["read_capacity"] = n.get("read_capacity", {})
        except (OSError, socket.timeout, ValueError, struct.error):
            pass
    return out


def _sendtargets(sock: socket.socket, itt: int, cmdsn: int,
                 expstatsn: int) -> list[dict]:
    """Issue Text Request SendTargets=All; drain C=1 continuations until F=1."""
    payload = _kvpairs({"SendTargets": "All"})
    pdu = _build_text_bhs(f=True, c=False, itt=itt, cmdsn=cmdsn,
                          expstatsn=expstatsn, ttt=0xFFFFFFFF, data_seg=payload)
    sock.sendall(pdu)
    collected: list[tuple[str, str]] = []
    while True:
        bhs, data = _read_pdu(sock)
        if bhs is None or (bhs[0] & 0x3F) != _OP_TEXT_RESP:
            break
        collected.extend(_parse_kvpairs(data))
        f = bool(bhs[1] & 0x80)
        c = bool(bhs[1] & 0x40)
        ttt = struct.unpack(">I", bhs[20:24])[0]
        if f:
            break
        if c:
            # Ack the continuation with an empty Text Request carrying the TTT.
            cmdsn += 1
            itt += 1
            ack = _build_text_bhs(f=False, c=False, itt=itt, cmdsn=cmdsn,
                                  expstatsn=expstatsn, ttt=ttt, data_seg=b"")
            sock.sendall(ack)
            continue
        break
    return _parse_sendtargets(collected)


def _normal_login_and_inquiry(ip: str, port: int, target_name: str,
                              timeout: float) -> dict:
    """Fresh connection: Login SessionType=Normal against `target_name` with
    AuthMethod=None. On FullFeaturePhase, issue INQUIRY + READ CAPACITY (10) on
    LUN 0. Read-only. Returns {login, inquiry, read_capacity}."""
    out: dict = {"login": {}, "inquiry": {}, "read_capacity": {}}
    isid = _make_isid()
    itt = 0
    cmdsn = 0
    with socket.create_connection((ip, port), timeout=proxy.scaled(timeout)) as sock:
        sock.settimeout(proxy.scaled(timeout))
        kvs = {
            "InitiatorName": _INITIATOR_NAME,
            "SessionType": "Normal",
            "TargetName": target_name,
            "AuthMethod": "None",
        }
        resp = _login_send_recv(sock, kvs, isid, 0, itt, cmdsn, 0,
                                t=True, csg=_STAGE_SECURITY, nsg=_STAGE_OP)
        if not resp or resp.get("status_class") != _STATUS_SUCCESS:
            return out
        out["login"]["security_ok"] = True
        cmdsn += 1
        itt += 1
        reached_ff = (resp.get("T") and resp.get("nsg") == _STAGE_FULLFEATURE)
        if not reached_ff:
            op_kvs = {
                "HeaderDigest": "None",
                "DataDigest": "None",
                "MaxRecvDataSegmentLength": "8192",
                "MaxBurstLength": "262144",
                "FirstBurstLength": "65536",
                "DefaultTime2Wait": "2",
                "DefaultTime2Retain": "0",
                "InitialR2T": "Yes",
                "ImmediateData": "Yes",
            }
            resp2 = _login_send_recv(sock, op_kvs, isid, resp.get("tsih", 0),
                                     itt, cmdsn, 0,
                                     t=True, csg=_STAGE_OP,
                                     nsg=_STAGE_FULLFEATURE)
            if not resp2 or resp2.get("status_class") != _STATUS_SUCCESS:
                return out
            reached_ff = (resp2.get("T") and resp2.get("nsg") == _STAGE_FULLFEATURE)
            cmdsn += 1
            itt += 1
        if not reached_ff:
            return out
        out["login"]["full_feature"] = True

        # INQUIRY - Standard, 36 bytes.
        inq_cdb = bytes([0x12, 0x00, 0x00, 0x00, 0x24, 0x00])
        sock.sendall(_build_scsi_cmd_bhs(read=True, itt=itt, cmdsn=cmdsn,
                                         expstatsn=0, cdb=inq_cdb,
                                         expected_len=36))
        cmdsn += 1
        itt += 1
        inq_data = _drain_scsi_response(sock)
        if inq_data:
            out["inquiry"] = _parse_inquiry(inq_data)

        # READ CAPACITY (10) - 8-byte response.
        rc_cdb = bytes([0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        sock.sendall(_build_scsi_cmd_bhs(read=True, itt=itt, cmdsn=cmdsn,
                                         expstatsn=0, cdb=rc_cdb,
                                         expected_len=8))
        rc_data = _drain_scsi_response(sock)
        if rc_data:
            out["read_capacity"] = _parse_read_capacity10(rc_data)
    return out


def _drain_scsi_response(sock: socket.socket, max_pdus: int = 4) -> bytes:
    """Read PDUs until a Data-In/Response with final status arrives; concatenate
    Data-In payloads. Bounded to `max_pdus` so a rogue target cannot loop us."""
    buf = b""
    for _ in range(max_pdus):
        bhs, data = _read_pdu(sock)
        if bhs is None:
            break
        op = bhs[0] & 0x3F
        if op == _OP_SCSI_DATA_IN:
            buf += data
            # F bit is 0x80 in byte 1.
            if bhs[1] & 0x80:
                break
        elif op == _OP_SCSI_RESP:
            # SCSI Response with a piggybacked sense buffer - data segment
            # contains sense data, not the SCSI payload. Return what we have.
            break
        else:
            break
    return buf


# --- narratives + findings -----------------------------------------------------

_NARRATIVE = {
    "iscsi_reachable": (
        "recce completed a Login Request/Response handshake with the iSCSI target "
        "portal. The AuthMethod list disclosed in the Login Response tells the "
        "attacker which authentication paths are available (None, CHAP, KRB5, SRP)."),
    "iscsi_auth_none_discovery": (
        "The portal accepted AuthMethod=None for a Discovery session - the baseline "
        "exposure that unlocks SendTargets and every target IQN + portal address it "
        "advertises. Enforce CHAP or KRB5 on the Discovery session."),
    "iscsi_auth_none_normal": (
        "A Normal-session Login against a discovered TargetName transitioned to "
        "FullFeaturePhase with NO credential - an attacker can mount the LUN as a "
        "raw block device (VM disk, database volume, backup share). Enforce CHAP "
        "or KRB5 and LUN masking, and firewall 3260 to the initiator subnet."),
    "iscsi_targets_disclosed": (
        "SendTargets=All drained the portal's complete catalogue of TargetNames and "
        "TargetAddresses. IQNs leak hostnames + reversed-DNS zones and TargetAddress "
        "commonly reveals internal-only storage-network IPs."),
    "iscsi_chap_challenge_captured": (
        "The CHAP challenge (CHAP_I + CHAP_C) is captured. Combined with any real "
        "initiator's CHAP_N + CHAP_R (from an on-path capture) it is hashcat -m 4800 "
        "material. Even without the response, the target's willingness to answer any "
        "peer with a challenge is a MITM/relay primitive."),
    "iscsi_chap_one_way": (
        "The target does NOT demand mutual CHAP - it never sends the initiator its "
        "own CHAP_I/CHAP_C. A MITM/relay attacker can proxy the initiator's response "
        "to the target without knowing the shared secret."),
    "iscsi_inquiry_leak": (
        "SCSI INQUIRY on LUN 0 returned the array's vendor / product / revision. "
        "This proves real block access AND identifies the storage firmware for CVE "
        "mapping (NetApp / EMC / HPE / LIO / tgt / SCST)."),
    "iscsi_lun_readable": (
        "READ CAPACITY (10) reported the LUN's block count and block size - a "
        "concrete byte count an attacker can dump. LUN masking is absent."),
    "iscsi_no_digest": (
        "HeaderDigest=None and DataDigest=None were negotiated. On a routed portal "
        "an on-path attacker can tamper with PDUs without detection."),
    "iscsi_legacy_version": (
        "The Login Response reports a Version-Active below the RFC 7143 baseline. "
        "Legacy vendor firmware often accepts junk versions and predates fixes for "
        "well-known iSCSI login bugs."),
    "iscsi_iqn_hostinfo": (
        "The IQN discloses a hostname (host-tail) and reversed-DNS domain. These "
        "feed the AD / DNS / TLS enumeration paths even when the storage array is "
        "on an isolated VLAN with no forward DNS."),
    "iscsi_pivot_portal": (
        "TargetAddress advertises a portal IP outside the current scan scope - the "
        "initiator was expected to reach it, so the current host has a route to a "
        "storage-network segment recce has not yet mapped."),
}

_finding = finding_builder("iscsi", _NARRATIVE)


def findings(hosts: list[Host], probes: dict | None = None,
             scope_ips: set[str] | None = None) -> list[dict]:
    probes = probes or {}
    scope_ips = scope_ips or {h.ip for h in hosts}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_iscsi(p):
                continue
            pr = probes.get((h.ip, p.portid)) or {}
            if not pr.get("is_iscsi"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            _emit_reachable(out, pr, tgt, h, p)
            _emit_auth_none_discovery(out, pr, tgt, h, p)
            _emit_sendtargets(out, pr, tgt, h, p)
            _emit_auth_none_normal(out, pr, tgt, h, p)
            _emit_scsi(out, pr, tgt, h, p)
            _emit_chap(out, pr, tgt, h, p)
            _emit_op_params(out, pr, tgt, h, p)
            _emit_legacy_version(out, pr, tgt, h, p)
            _emit_iqn_hints(out, pr, tgt, h, p)
            _emit_pivots(out, pr, tgt, h, p, scope_ips)
    return out


def _emit_reachable(out, pr, tgt, h, p):
    methods = pr.get("auth_methods") or []
    detail = f"Login handshake completed. AuthMethod offered: {', '.join(methods) or 'unknown'}."
    out.append(_finding(
        "info", "iSCSI portal reachable (RFC 7143 Login handshake)", tgt,
        detail, "iscsiadm",
        f"iscsiadm -m discovery -t sendtargets -p {h.ip}:{p.portid}",
        "Restrict 3260/tcp to initiator IPs; require CHAP or KRB5 on Discovery "
        "and Normal sessions.",
        ["CWE-200"], kind="iscsi_reachable"))


def _emit_auth_none_discovery(out, pr, tgt, h, p):
    if not pr.get("discovery_no_auth"):
        return
    out.append(_finding(
        "high",
        "iSCSI target - AuthMethod=None accepted for Discovery session", tgt,
        "The portal completed a Discovery Login with AuthMethod=None. Any peer "
        "on the network can now enumerate every advertised TargetName and portal "
        "address (SendTargets=All).",
        "iscsiadm",
        f"iscsiadm -m discovery -t sendtargets -p {h.ip}:{p.portid}",
        "Set node.session.auth.authmethod=CHAP (or KRB5) on Discovery; disable "
        "AuthMethod=None on the target portal.",
        ["CWE-306"], kind="iscsi_auth_none_discovery"))


def _emit_sendtargets(out, pr, tgt, h, p):
    targets = pr.get("targets") or []
    if not targets:
        return
    lines = []
    for t in targets[:10]:
        addrs = ", ".join(f"{a['ip']}:{a['port']}" for a in t.get("addresses", []))
        lines.append(f"  {t['iqn']} -> {addrs or '(no address)'}")
    more = f"\n  ... +{len(targets) - 10} more" if len(targets) > 10 else ""
    out.append(_finding(
        "high",
        "iSCSI portal - unauthenticated SendTargets discloses all IQNs and portal addresses",
        tgt,
        f"SendTargets=All returned {len(targets)} target(s):\n" + "\n".join(lines) + more,
        "iscsiadm",
        f"iscsiadm -m discovery -t sendtargets -p {h.ip}:{p.portid}",
        "Enforce CHAP/KRB5 on the Discovery portal; treat the IQN list and "
        "portal-address list as sensitive (they leak internal topology).",
        ["CWE-200"], kind="iscsi_targets_disclosed"))


def _emit_auth_none_normal(out, pr, tgt, h, p):
    nl = pr.get("normal_login") or {}
    if not nl.get("full_feature"):
        return
    out.append(_finding(
        "critical",
        "iSCSI target - AuthMethod=None accepted for Normal session (raw LUN mount, no credential)",
        tgt,
        "A Normal-session Login against the first discovered TargetName reached "
        "FullFeaturePhase with NO credential. An attacker can mount the LUN as a "
        "raw block device (VM disk, database volume, backup share).",
        "iscsiadm",
        f"iscsiadm -m node -T <iqn> -p {h.ip}:{p.portid} --login",
        "Require CHAP or KRB5 for Normal sessions; configure LUN masking on the "
        "array so unauthorized initiators cannot enumerate LUNs.",
        ["CWE-306", "CWE-284"], kind="iscsi_auth_none_normal"))


def _emit_scsi(out, pr, tgt, h, p):
    inq = pr.get("inquiry") or {}
    rc = pr.get("read_capacity") or {}
    if inq.get("vendor") or inq.get("product"):
        vendor = inq.get("vendor", "?")
        product = inq.get("product", "?")
        revision = inq.get("revision", "?")
        out.append(_finding(
            "high",
            "iSCSI target - INQUIRY leaks LUN vendor / product / revision", tgt,
            f"SCSI INQUIRY on LUN 0 returned vendor='{vendor}' product='{product}' "
            f"revision='{revision}'. Proves real block access and identifies the "
            f"array firmware for CVE mapping.",
            "sg3_utils",
            f"sg_inq /dev/disk/by-path/ip-{h.ip}:{p.portid}-iscsi-<iqn>-lun-0",
            "Enforce authentication and LUN masking so LUN 0 is not visible to "
            "arbitrary initiators.",
            ["CWE-306"], kind="iscsi_inquiry_leak"))
    if rc.get("blocks"):
        cap = rc.get("capacity_bytes", 0)
        out.append(_finding(
            "high",
            "iSCSI target - READ CAPACITY (10) succeeded on LUN 0 (LUN masking absent)",
            tgt,
            f"READ CAPACITY (10) reported blocks={rc['blocks']} block_size="
            f"{rc.get('block_size')} (~{cap} bytes readable). A read-only proof; "
            "recce did NOT issue any WRITE opcodes.",
            "sg3_utils",
            f"sg_readcap /dev/disk/by-path/ip-{h.ip}:{p.portid}-iscsi-<iqn>-lun-0",
            "Configure LUN masking so an unauthenticated initiator cannot see "
            "LUN 0; enforce CHAP/KRB5 on Normal sessions.",
            ["CWE-306"], kind="iscsi_lun_readable"))


def _emit_chap(out, pr, tgt, h, p):
    chap = pr.get("chap") or {}
    if chap.get("id") and chap.get("challenge"):
        out.append(_finding(
            "high",
            "iSCSI CHAP - challenge captured for offline cracking (hashcat -m 4800)",
            tgt,
            f"Target returned CHAP_A={chap.get('algorithm', '5')} CHAP_I={chap['id']} "
            f"CHAP_C={chap['challenge']}. A captured initiator response (CHAP_N + "
            "CHAP_R) combines with this into hashcat -m 4800 material "
            "(response:challenge:id).",
            "hashcat",
            "# format: <CHAP_R>:<CHAP_C>:<CHAP_I>\nhashcat -m 4800 iscsi.chap wordlist.txt",
            "Enforce a high-entropy CHAP secret (16+ chars); scope 3260/tcp to "
            "the initiator subnet.",
            ["CWE-916", "CWE-287"], kind="iscsi_chap_challenge_captured"))
    if pr.get("chap_one_way"):
        out.append(_finding(
            "medium",
            "iSCSI CHAP - one-way authentication only (initiator does not verify target)",
            tgt,
            "The target selected CHAP but never returned its own CHAP_I/CHAP_C to "
            "the initiator - mutual (bidirectional) CHAP is not required. A "
            "MITM/relay attacker can proxy the initiator's CHAP_R to the real "
            "target without knowing the secret.",
            "iscsiadm",
            f"iscsiadm -m node -T <iqn> -p {h.ip}:{p.portid} -o show | grep -i chap",
            "Configure mutual CHAP (node.session.auth.username_in / password_in "
            "on the initiator AND per-initiator credentials on the target).",
            ["CWE-287", "CWE-300"], kind="iscsi_chap_one_way"))


def _emit_op_params(out, pr, tgt, h, p):
    op = pr.get("op_params") or {}
    hd = (op.get("HeaderDigest") or "").lower()
    dd = (op.get("DataDigest") or "").lower()
    if hd == "none" and dd == "none":
        out.append(_finding(
            "low",
            "iSCSI portal - HeaderDigest=None and DataDigest=None (on-path tampering)",
            tgt,
            "The portal negotiated no header or data CRC. An on-path attacker "
            "can silently corrupt PDUs.",
            "iscsiadm",
            f"iscsiadm -m node -T <iqn> -p {h.ip}:{p.portid} -o show | grep -i digest",
            "Set node.conn[0].iscsi.HeaderDigest=CRC32C and "
            "DataDigest=CRC32C on both ends.",
            ["CWE-353"], kind="iscsi_no_digest"))


def _emit_legacy_version(out, pr, tgt, h, p):
    if not pr.get("legacy_version"):
        return
    out.append(_finding(
        "low",
        "iSCSI portal - legacy Version-Active accepted (pre-RFC 7143)", tgt,
        f"Login Response reports Version-Active={pr.get('version_active')} (baseline "
        f"is 0x00). Legacy vendor firmware often predates fixes for well-known "
        f"iSCSI login-parser bugs.",
        "iscsiadm",
        f"iscsiadm -m discovery -t sendtargets -p {h.ip}:{p.portid} -d 8",
        "Upgrade the target firmware to a vendor build that pins Version-Active=0.",
        ["CWE-1104"], kind="iscsi_legacy_version"))


def _emit_iqn_hints(out, pr, tgt, h, p):
    hints = []
    for t in pr.get("targets") or []:
        info = parse_iqn(t.get("iqn", ""))
        if not info:
            continue
        hints.append((t["iqn"], info))
    if not hints:
        return
    lines = []
    for iqn, info in hints[:10]:
        lines.append(f"  {iqn} -> host='{info.get('host')}' domain='{info.get('domain')}'")
    more = f"\n  ... +{len(hints) - 10} more" if len(hints) > 10 else ""
    out.append(_finding(
        "info",
        "iSCSI IQN discloses hostname / reversed-DNS domain", tgt,
        "IQNs of the form iqn.<yyyy-mm>.<reversed.domain>:<host> leak the "
        "storage node's shortname and the customer's reversed-DNS zone:\n"
        + "\n".join(lines) + more,
        "iscsiadm",
        f"iscsiadm -m discovery -t sendtargets -p {h.ip}:{p.portid}",
        "Consider generic IQNs that do not embed a hostname or reversed FQDN.",
        ["CWE-200"], kind="iscsi_iqn_hostinfo"))


def _emit_pivots(out, pr, tgt, h, p, scope_ips):
    pivots: list[dict] = []
    for t in pr.get("targets") or []:
        for a in t.get("addresses", []):
            ip = a.get("ip", "")
            if ip and ip not in scope_ips and ip != h.ip:
                pivots.append({"iqn": t["iqn"], "ip": ip,
                               "port": a.get("port", _DEFAULT_PORT)})
    if not pivots:
        return
    lines = [f"  {pv['ip']}:{pv['port']} ({pv['iqn']})" for pv in pivots[:10]]
    more = f"\n  ... +{len(pivots) - 10} more" if len(pivots) > 10 else ""
    out.append(_finding(
        "medium",
        "iSCSI SendTargets discloses internal-only storage-network portal IPs", tgt,
        "TargetAddress lists portal IPs outside the current scan scope - the "
        "current host has a route to a storage segment recce has not yet mapped:\n"
        + "\n".join(lines) + more,
        "nmap",
        "nmap -Pn -p 3260 " + " ".join(sorted({pv['ip'] for pv in pivots[:10]})),
        "Segment the storage network so a compromised host in the initiator "
        "VLAN cannot reach the storage-array management plane.",
        ["CWE-200"], kind="iscsi_pivot_portal"))


# --- runbook + proof + analyze -------------------------------------------------

TESTING_NARRATIVE = [
    ("1. Login SecurityNegotiation",
     "recce sends an iSCSI Login Request (opcode 0x43) with SessionType=Discovery "
     "and AuthMethod=None,CHAP. The Login Response (opcode 0x23) confirms the port "
     "speaks iSCSI and names the target's AuthMethod list."),
    ("2. AuthMethod=None discriminator",
     "A Login Response that echoes AuthMethod=None with StatusClass=0 and no CHAP "
     "round-trip = the baseline exposure that unlocks SendTargets."),
    ("3. SendTargets sweep",
     "One Text Request (opcode 0x44) with SendTargets=All drains the portal's "
     "complete TargetName + TargetAddress catalogue; continuations (C=1) are "
     "reissued until F=1."),
    ("4. Normal-session Login (read-only proof)",
     "recce re-Logs in on a fresh connection with SessionType=Normal against the "
     "first discovered TargetName. FullFeaturePhase + INQUIRY + READ CAPACITY (10) "
     "on LUN 0 proves real block access. NO SCSI WRITEs are ever issued."),
]


def runbook(ip: str, port: int) -> list[dict]:
    steps = [
        ("recon", "nmap NSE", f"nmap -p{port} --script iscsi-info {ip}",
         "iSCSI target information and unauth discovery check."),
        ("enumerate", "iscsiadm",
         f"iscsiadm -m discovery -t sendtargets -p {ip}:{port}",
         "Drain every TargetName + TargetAddress the portal advertises."),
        ("loot", "iscsiadm + sg3_utils",
         f"iscsiadm -m node -T <iqn> -p {ip}:{port} --login && "
         "sg_inq /dev/disk/by-path/ip-<...>-lun-0 && sg_readcap /dev/disk/by-path/...",
         "Mount the LUN read-only; INQUIRY + READ CAPACITY prove access without "
         "issuing any WRITE opcodes."),
        ("escalate", "dd / partclone",
         "# read-only pull of the raw LUN contents (block device on the initiator)\n"
         "dd if=/dev/disk/by-path/ip-<...>-lun-0 of=lun0.img bs=1M count=64",
         "Dump the VM disk / database volume / backup share the LUN backs."),
    ]
    return [{"phase": ph, "tool": t, "command": c, "why": w}
            for ph, t, c, w in steps]


proof_html = make_proof_html_wrapper("iscsi> ")
findings_to_vulns = make_findings_to_vulns_wrapper("iscsi", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None,
            do_inquiry: bool = True) -> dict:
    """Full iSCSI analysis. Returns {targets, findings, runbooks, probes, stats}."""
    from . import svcprobe
    targets = iscsi_targets(hosts)
    probes: dict = {}
    state: dict = {}
    scope_ips = {h.ip for h in hosts}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets,
                lambda t: probe(t["ip"], t["port"], do_inquiry=do_inquiry),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["unauth_discovery"] = pr.get("discovery_no_auth", False)
                t["unauth_normal"] = bool(pr.get("normal_login", {}).get("full_feature"))
                t["target_count"] = len(pr.get("targets", []))
    fs = findings(hosts, probes, scope_ips=scope_ips)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
