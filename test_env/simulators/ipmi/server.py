"""IPMI-over-LAN target sim for recce's ipmi probe (LAB ONLY).

Implements the minimum wire surface needed to exercise every finding
recce.services.ipmi emits from a fingerprint scan:

  * IPMI 1.5 session-less requests: 0x38 (Get Channel Auth Cap), 0x01
    (Get Device ID), 0x54 (Get Channel Cipher Suites).
  * IPMI 2.0 RMCP+ Open Session Request (payload type 0x10) — accepts
    the cipher-suite-0 negotiation so recce's T2 SAFE proof lands.

No real BMC state, no RAKP1/RAKP3 continuation. The point is response
shape, not a working KVM — a BMC that stops after Open Session
Response would look identical over the wire during a recce probe.

Wire references: IPMI 2.0 spec §13 (RMCP+), §22 (App netfn commands),
Table 20-2 (Get Device ID data), Table 22-19 (cipher-suite records).
"""
import socket
import struct
import sys

_PORT = 623

# Get Device ID reports vendor Dell (IANA 674) + firmware 1.20 + IPMI 2.0.
_DEV_VENDOR_ID = 674
_DEV_PRODUCT_ID = 0x0100
_DEV_FW_MAJOR = 0x01
_DEV_FW_MINOR = 0x20        # BCD-ish minor as tools print it
_DEV_IPMI_VER = 0x02        # spec: 2.0 encoded as 0x02 (low nib) | 0x00 << 4
_DEV_DEVICE_ID = 0x20
_DEV_DEVICE_REV = 0x81      # bit 7 = "provides Device SDRs"


def _csum(data: bytes) -> int:
    """IPMI 2's-complement checksum over `data`."""
    return (-sum(data)) & 0xff


def _ipmi15_reply(cmd: int, data: bytes = b"") -> bytes:
    """Build a session-less IPMI 1.5 response. Layout mirrors the request
    format in recce.services.ipmi._ipmi15_request. rqAddr / rsAddr are
    swapped vs. the request (RFC-style)."""
    # In a response, the netFn is the request's netFn | 1 (0x06<<2 = 0x18,
    # response = 0x1c). rqAddr becomes the console (0x81), rsAddr the BMC
    # (0x20). recce's parser doesn't check any of that — it keys on the
    # cmd byte at msg[5] and compCode at msg[6] — but we do it correctly
    # so a real ipmitool client also sees a well-formed packet.
    rq_addr = 0x81
    netfn = (0x06 << 2) | 0x04            # APP response netFn = 0x1c
    csum1 = _csum(bytes([rq_addr, netfn]))
    rs_addr = 0x20
    rq_seq = 0x00
    compcode = 0x00
    body = bytes([rs_addr, rq_seq, cmd, compcode]) + data
    csum2 = _csum(body)
    msg = bytes([rq_addr, netfn, csum1]) + body + bytes([csum2])
    rmcp = b"\x06\x00\xff\x07"
    sess = b"\x00" + b"\x00" * 4 + b"\x00" * 4         # auth 0, seq 0, sid 0
    return rmcp + sess + bytes([len(msg)]) + msg


def _handle_gcac(_data: bytes) -> bytes:
    """Get Channel Auth Capabilities (cmd 0x38) response.
       byte 0: channel echoed (0x0e)
       byte 1: auth types bitmap
       byte 2: auth status
       byte 3: ext caps
       byte 4-6: OEM enterprise (0)
       byte 7: OEM auxiliary (0)
    Advertise every finding recce.services.ipmi can flag: none|MD2|MD5|
    password (weak_auth), anonymous + null-user logon, IPMI 2.0."""
    auth_types = 0x01 | 0x02 | 0x04 | 0x10          # none|MD2|MD5|password
    auth_status = 0x01 | 0x02                        # anonymous + null_user
    ext_caps = 0x02 | 0x01                           # IPMI 1.5 + 2.0 support
    data = bytes([0x0e, auth_types, auth_status, ext_caps,
                  0x00, 0x00, 0x00, 0x00])
    return _ipmi15_reply(0x38, data)


def _handle_device_id(_data: bytes) -> bytes:
    """Get Device ID (cmd 0x01) — Table 20-2 layout:
       0: Device ID
       1: Device Revision
       2: Firmware Major (bit7 = available)
       3: Firmware Minor (BCD)
       4: IPMI Version (BCD, low-nib MAJOR — spec §20.1)
       5: Aux Device Support
       6-8: Manufacturer ID (LE, 3 bytes)
       9-10: Product ID (LE, 2 bytes)"""
    aux_support = 0x00
    mfg = _DEV_VENDOR_ID
    prod = _DEV_PRODUCT_ID
    data = bytes([_DEV_DEVICE_ID, _DEV_DEVICE_REV,
                  _DEV_FW_MAJOR, _DEV_FW_MINOR,
                  _DEV_IPMI_VER, aux_support,
                  mfg & 0xff, (mfg >> 8) & 0xff, (mfg >> 16) & 0xff,
                  prod & 0xff, (prod >> 8) & 0xff])
    return _ipmi15_reply(0x01, data)


def _handle_cipher_suites(data_field: bytes) -> bytes:
    """Get Channel Cipher Suites (cmd 0x54). Request carries:
         byte 0: channel (bits 3:0)
         byte 1: list index (0..63)
    Response payload:
         byte 0: channel echo
         bytes 1+: cipher-suite records (Table 22-19)

    Serve one record for suite id 0 with auth_alg=0 on index 0, empty
    payload after — recce's iterator stops when a page comes back with
    < 16 record bytes (`if len(record_data) < 16: break`)."""
    if len(data_field) < 2:
        return _ipmi15_reply(0x54, b"")
    channel = data_field[0] & 0x0f
    index = data_field[1] & 0x3f
    if index != 0:
        # No more records — send just the channel echo (short reply
        # signals end of stream to the iterator).
        return _ipmi15_reply(0x54, bytes([channel]))
    # One 0xC0 record: standard suite id 0, one auth-alg tag (top bits
    # 00 → auth alg), one integrity-alg tag (top bits 01), one conf
    # tag (top bits 10). auth_alg=0 = RAKP-none = CVE-2013-4786.
    #   0xC0 <suite_id=0> <auth=00> <integ=41 (=integ alg 1)> <conf=80 (=conf 0)>
    # Padded to keep the reply < 16 record bytes so the iterator stops.
    record = bytes([0xC0, 0x00, 0x00, 0x41, 0x80])
    return _ipmi15_reply(0x54, bytes([channel]) + record)


def _rmcpplus(session_id: int, payload_type: int, payload: bytes) -> bytes:
    """RMCP + IPMI 2.0 session header + payload, no auth/integrity/
    confidentiality (mirror of the client-side helper in recce)."""
    rmcp = b"\x06\x00\xff\x07"
    session = (b"\x06" + bytes([payload_type & 0x3F])
               + struct.pack("<I", session_id)
               + struct.pack("<I", 0)                # session seq
               + struct.pack("<H", len(payload)))
    return rmcp + session + payload


def _handle_open_session_request(pkt: bytes) -> bytes:
    """RMCP+ Open Session Request (payload type 0x10) → Open Session
    Response (payload type 0x11).

    Request payload (IPMI 2.0 §13.17): tag, max_priv, rsvd(2),
    remote_sid(4), auth_alg_payload(8), integ_alg_payload(8),
    conf_alg_payload(8).

    Response payload (§13.19): tag, status, max_priv, rsvd(1),
    remote_sid(4 echo), managed_sid(4), auth_alg_payload(8),
    integ_alg_payload(8), conf_alg_payload(8) — 36 bytes.

    Echo the requested algs so recce's cipher_zero_session_proof sees
    accepted_auth_alg = 0."""
    if len(pkt) < 16 + 32:
        return b""
    payload = pkt[16:]
    tag = payload[0]
    max_priv = payload[1]
    remote_sid = struct.unpack("<I", payload[4:8])[0]
    auth_alg = payload[12] if len(payload) > 12 else 0
    integ_alg = payload[20] if len(payload) > 20 else 0
    conf_alg = payload[28] if len(payload) > 28 else 0
    managed_sid = 0x00000001
    resp = (
        bytes([tag, 0x00, max_priv, 0x00])            # tag / status=ok / priv / rsvd
        + struct.pack("<I", remote_sid)
        + struct.pack("<I", managed_sid)
        + bytes([0x00, 0x00, 0x00, 0x08,              # authentication payload
                 auth_alg, 0x00, 0x00, 0x00])
        + bytes([0x01, 0x00, 0x00, 0x08,              # integrity payload
                 integ_alg, 0x00, 0x00, 0x00])
        + bytes([0x02, 0x00, 0x00, 0x08,              # confidentiality payload
                 conf_alg, 0x00, 0x00, 0x00])
    )
    return _rmcpplus(0, 0x11, resp)


def _dispatch(pkt: bytes) -> bytes | None:
    """Route by wire shape. Session-less IPMI 1.5 packets have auth_type=0
    at pkt[4]; RMCP+ packets carry auth_type=6."""
    if len(pkt) < 5:
        return None
    if pkt[0] != 0x06 or pkt[3] != 0x07:                # not RMCP/IPMI
        return None
    auth_type = pkt[4]
    if auth_type == 0x06:                                # IPMI 2.0 RMCP+
        # Payload type is pkt[5] & 0x3f. We only implement Open Session Req.
        if len(pkt) < 6:
            return None
        payload_type = pkt[5] & 0x3f
        if payload_type == 0x10:
            return _handle_open_session_request(pkt)
        return None
    # IPMI 1.5 session-less. Message body starts at offset 14.
    if len(pkt) < 14 + 7:
        return None
    msg = pkt[14:]
    if len(msg) < 7:
        return None
    cmd = msg[5]
    data_field = msg[6:-1]                               # trim trailing csum
    if cmd == 0x38:
        return _handle_gcac(data_field)
    if cmd == 0x01:
        return _handle_device_id(data_field)
    if cmd == 0x54:
        return _handle_cipher_suites(data_field)
    return None


def main() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", _PORT))
        print(f"[recce-lab ipmi-sim] listening on 0.0.0.0:{_PORT}/udp",
              flush=True)
        while True:
            try:
                pkt, addr = sock.recvfrom(2048)
            except OSError:
                continue
            reply = _dispatch(pkt)
            if reply is None:
                continue
            try:
                sock.sendto(reply, addr)
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
