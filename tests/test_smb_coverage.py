"""SMB enumeration coverage: null -> guest -> credentialed session selection.

Closes the gap where a locked-down standalone/workgroup host that denies null and
guest sessions but has valid credentials was never enumerated with those creds.
"""
from __future__ import annotations

import struct


def test_enum_session_uses_local_auth_for_workgroup_and_d_for_domain(monkeypatch):
    from recce.services import smb
    monkeypatch.setattr(smb, "smb_tool", lambda: "nxc")
    seen: dict = {}
    monkeypatch.setattr(smb, "_run", lambda cmd: (seen.__setitem__("cmd", cmd), ("", ""))[1])

    smb.enum_session("10.0.0.5", "localadmin", "pw")            # no domain -> local account
    assert "--local-auth" in seen["cmd"] and "-d" not in seen["cmd"]

    smb.enum_session("10.0.0.5", "svc", "pw", domain="CORP")    # domain account -> -d
    assert "-d" in seen["cmd"] and "CORP" in seen["cmd"] and "--local-auth" not in seen["cmd"]

    smb.enum_session("10.0.0.5", "", "")                        # null session -> neither
    assert "--local-auth" not in seen["cmd"]

    smb.enum_session("10.0.0.5", "guest", "")                   # guest -> neither
    assert "--local-auth" not in seen["cmd"]


def _fake_sessions(monkeypatch, *, null=None, guest=None, creds=None):
    from recce.services import smb
    calls = []

    def fake(ip, user="", password="", port=445, domain=""):
        calls.append({"user": user, "password": password, "domain": domain})
        if user == "" :
            return null or {"shares": [], "users": [], "auth": False}
        if user.lower() == "guest":
            return guest or {"shares": [], "users": [], "auth": False}
        return creds or {"shares": [], "users": [], "auth": False}

    monkeypatch.setattr(smb, "enum_session", fake)
    return smb, calls


def test_prefers_null_when_it_works(monkeypatch):
    smb, calls = _fake_sessions(monkeypatch, null={"shares": [{"name": "PUB"}], "users": []})
    session, level = smb.enum_best_session("10.0.0.5", 445, {"user": "svc", "secret": "p"})
    assert level == "null"
    assert len(calls) == 1                    # didn't even try guest/creds


def test_falls_back_to_guest(monkeypatch):
    smb, calls = _fake_sessions(monkeypatch, guest={"shares": [{"name": "SHARE"}], "users": []})
    session, level = smb.enum_best_session("10.0.0.5", 445, {"user": "svc", "secret": "p"})
    assert level == "guest"


def test_falls_back_to_credentials_on_locked_down_host(monkeypatch):
    # the GAP: null + guest deny everything, but valid creds enumerate shares.
    smb, calls = _fake_sessions(
        monkeypatch, creds={"auth": True, "shares": [{"name": "Finance", "perms": "READ"}], "users": []})
    creds = {"user": "svc", "secret": "pw", "domain": "CORP"}
    session, level = smb.enum_best_session("10.0.0.5", 445, creds)
    assert level == "creds"
    assert session["shares"][0]["name"] == "Finance"
    # it actually tried the operator creds (with the domain), after null + guest
    assert {"user": "svc", "password": "pw", "domain": "CORP"} in calls


def test_no_session_works(monkeypatch):
    smb, calls = _fake_sessions(monkeypatch)         # everything empty
    session, level = smb.enum_best_session("10.0.0.5", 445, {"user": "svc", "secret": "p"})
    assert level == "none"


def test_tool_missing_short_circuits(monkeypatch):
    smb, calls = _fake_sessions(
        monkeypatch, null={"error": "nxc/netexec not installed", "shares": [], "users": []})
    session, level = smb.enum_best_session("10.0.0.5", 445, None)
    assert level == "error"


# --- share spidering for secrets -------------------------------------------------

def test_flag_secret_files_matches_the_right_things():
    from recce.services import smb
    files = [
        "Public\\readme.txt",                       # ignore
        "IT\\unattend.xml",                         # answer file
        "Web\\inetpub\\web.config",                 # app config
        "Backups\\db-2023.bak",                     # backup
        "Users\\jdoe\\.ssh\\id_rsa",                # private key
        "HR\\passwords.xlsx",                       # credential store
        "Policies\\{GUID}\\Groups.xml",             # GPP cpassword
        "Media\\vacation.jpg",                      # ignore
    ]
    hits = {h["path"] for h in smb.flag_secret_files(files)}
    assert "IT\\unattend.xml" in hits
    assert "Web\\inetpub\\web.config" in hits
    assert "Backups\\db-2023.bak" in hits
    assert "Users\\jdoe\\.ssh\\id_rsa" in hits
    assert "HR\\passwords.xlsx" in hits
    assert "Policies\\{GUID}\\Groups.xml" in hits
    assert "Public\\readme.txt" not in hits
    assert "Media\\vacation.jpg" not in hits


def test_parse_smbclient_ls_extracts_files_not_dirs():
    from recce.services import smb
    out = (
        "\\\n"
        "  .                                   D        0  Mon Jan  1 00:00:00 2024\n"
        "  unattend.xml                        A     1024  Mon Jan  1 00:00:00 2024\n"
        "  logs                                D        0  Mon Jan  1 00:00:00 2024\n"
        "\\logs\n"
        "  app.log                             A      500  Mon Jan  1 00:00:00 2024\n")
    paths = smb._parse_smbclient_ls(out, "Data")
    assert "Data\\unattend.xml" in paths
    assert "Data\\logs\\app.log" in paths
    assert not any(p.endswith("logs") for p in paths)     # the directory itself isn't a file


def test_spider_shares_flags_readable_share(monkeypatch):
    from recce.services import smb
    monkeypatch.setattr(smb, "smbclient_tool", lambda: "smbclient")
    ls = ("\\\n  web.config   A   200   Mon Jan  1 00:00:00 2024\n"
          "  index.html    A   100   Mon Jan  1 00:00:00 2024\n")
    monkeypatch.setattr(smb, "_run", lambda cmd, timeout=90: (ls, ""))
    shares = [{"name": "wwwroot", "perms": "READ"},
              {"name": "IPC$", "perms": "READ"}]         # IPC$ skipped
    fs = smb.spider_shares("10.0.0.5", shares, {"user": "svc", "secret": "p"})
    assert len(fs) == 1
    assert "wwwroot" in fs[0]["title"] and fs[0]["severity"] == "high"
    assert "web.config" in fs[0]["detail"]


# --- NTLMSSP CHALLENGE harvest (MS-NLMP 2.2.1.2 / MS-SMB2 2.2.5) -----------------

def _av(av_id: int, value: bytes) -> bytes:
    return struct.pack("<HH", av_id, len(value)) + value


def _utf16(s: str) -> bytes:
    return s.encode("utf-16-le")


def _build_ntlm_type2(av_pairs: bytes, flags: int = 0x02028215,
                      version: bytes = b"\x0a\x00\x69\x4a\x00\x00\x00\x0f") -> bytes:
    """Assemble a wire-shape NTLMSSP CHALLENGE with a Version field (default = 10.0.19049,
    Windows 10 20H1) and the caller's AV_PAIR TargetInfo block."""
    ti_off = 56                                         # header includes 8-byte Version
    header = (b"NTLMSSP\x00" + struct.pack("<I", 2)
              + struct.pack("<HHI", 0, 0, 0)            # TargetName (empty)
              + struct.pack("<I", flags)
              + b"\x01" * 8                             # ServerChallenge
              + b"\x00" * 8                             # Reserved
              + struct.pack("<HHI", len(av_pairs), len(av_pairs), ti_off)
              + version)
    return header + av_pairs


def _build_smb2_session_setup_response(sec_buffer: bytes,
                                       session_flags: int = 0,
                                       status: int = 0xC0000016) -> bytes:
    """NBT-prefixed SMB2 SESSION_SETUP response (STATUS_MORE_PROCESSING_REQUIRED)
    carrying `sec_buffer` after the 8-byte fixed body."""
    hdr = (b"\xfeSMB" + struct.pack("<H", 64) + struct.pack("<H", 0)
           + struct.pack("<I", status) + struct.pack("<H", 0x0001)
           + struct.pack("<H", 1) + struct.pack("<I", 0) + struct.pack("<I", 0)
           + struct.pack("<Q", 1) + struct.pack("<I", 0) + struct.pack("<I", 0)
           + struct.pack("<Q", 0) + b"\x00" * 16)
    body = (struct.pack("<H", 9) + struct.pack("<H", session_flags)
            + struct.pack("<H", 64 + 8) + struct.pack("<H", len(sec_buffer)))
    smb = hdr + body + sec_buffer
    return struct.pack(">I", len(smb)) + smb


def test_spnego_neg_token_init_wraps_and_carries_payload():
    from recce.services import smb
    inner = b"NTLMSSP\x00\x01\x00\x00\x00"                  # arbitrary payload
    blob = smb._spnego_neg_token_init(inner)
    assert blob[0] == 0x60                                  # [APPLICATION 0]
    assert smb._SPNEGO_OID in blob                          # SPNEGO OID
    assert smb._NTLMSSP_OID in blob                         # NTLMSSP mech OID
    assert inner in blob                                    # payload survives wrapping


def test_parse_ntlm_challenge_info_extracts_avpair_intel_and_os_build():
    from recce.services import smb
    ti = (_av(0x0002, _utf16("CORP"))                       # MsvAvNbDomainName
          + _av(0x0001, _utf16("PC01"))                     # MsvAvNbComputerName
          + _av(0x0004, _utf16("corp.local"))               # MsvAvDnsDomainName
          + _av(0x0003, _utf16("pc01.corp.local"))          # MsvAvDnsComputerName
          + _av(0x0005, _utf16("corp.local"))               # MsvAvDnsTreeName
          + _av(0x0007, struct.pack("<Q", 133518912000000000))   # MsvAvTimestamp
          + _av(0x0000, b""))                               # MsvAvEOL
    version = b"\x0a\x00\x41\x4a\x00\x00\x00\x0f"           # 10.0.19009
    info = smb.parse_ntlm_challenge_info(_build_ntlm_type2(ti, version=version))
    assert info is not None
    assert info["netbios_computer"] == "PC01"
    assert info["netbios_domain"] == "CORP"
    assert info["dns_computer"] == "pc01.corp.local"
    assert info["dns_domain"] == "corp.local"
    assert info["dns_tree"] == "corp.local"
    assert info["os_version"] == "10.0.19009"
    assert info["ntlm_revision"] == 0x0F
    assert info["server_time_epoch"] > 0                    # decoded from FILETIME


def test_parse_ntlm_challenge_info_tolerates_spnego_wrapper():
    from recce.services import smb
    ti = _av(0x0001, _utf16("PC01")) + _av(0x0000, b"")
    raw = _build_ntlm_type2(ti)
    wrapped = smb._spnego_neg_token_init(raw)
    info = smb.parse_ntlm_challenge_info(wrapped)
    assert info and info["netbios_computer"] == "PC01"


def test_parse_ntlm_challenge_info_returns_none_for_non_ntlm():
    from recce.services import smb
    assert smb.parse_ntlm_challenge_info(b"") is None
    assert smb.parse_ntlm_challenge_info(b"garbage no signature") is None


def test_parse_smb2_session_setup_response_extracts_buffer_and_flags():
    from recce.services import smb
    ti = _av(0x0001, _utf16("PC01")) + _av(0x0000, b"")
    sec = _build_ntlm_type2(ti)
    wire = _build_smb2_session_setup_response(sec, session_flags=0x0001)
    r = smb.parse_smb2_session_setup_response(wire)
    assert r is not None
    assert r["session_flags"] == 0x0001
    assert r["is_guest"] is True and r["is_null"] is False
    assert r["security_buffer"] == sec
    assert r["status"] == 0xC0000016


def test_parse_smb2_session_setup_response_rejects_wrong_command_and_short_data():
    from recce.services import smb
    assert smb.parse_smb2_session_setup_response(b"") is None
    assert smb.parse_smb2_session_setup_response(b"\x00" * 80) is None
    # A NEGOTIATE reply (command 0x0000) must not be misread as a session_setup response.
    hdr = (b"\xfeSMB" + struct.pack("<H", 64) + b"\x00" * 2 + b"\x00" * 4
           + struct.pack("<H", 0x0000) + struct.pack("<H", 1) + b"\x00" * 44)
    body = struct.pack("<H", 9) + b"\x00" * 6
    smb_bytes = struct.pack(">I", len(hdr + body)) + hdr + body
    assert smb.parse_smb2_session_setup_response(smb_bytes) is None


def test_probe_ntlm_info_end_to_end_over_fake_socket(monkeypatch):
    """The full two-message flow: NEGOTIATE then SESSION_SETUP, with a scripted
    server reading the request and sending fixture bytes back."""
    from recce.services import smb
    ti = (_av(0x0002, _utf16("CORP")) + _av(0x0001, _utf16("PC01"))
          + _av(0x0004, _utf16("corp.local")) + _av(0x0000, b""))
    sec = _build_ntlm_type2(ti)

    class FakeSock:
        def __init__(self):
            neg_body = (struct.pack("<H", 65) + struct.pack("<H", 0x01)
                        + struct.pack("<H", 0x0302) + struct.pack("<H", 0)
                        + b"\x11" * 16 + struct.pack("<I", 0)
                        + b"\x00" * 16 + struct.pack("<H", 128) + struct.pack("<H", 0))
            neg = (b"\xfeSMB" + struct.pack("<H", 64) + b"\x00" * 2 + b"\x00" * 4
                   + struct.pack("<H", 0x0000) + struct.pack("<H", 1) + b"\x00" * 44
                   + neg_body)
            self._pdus = [struct.pack(">I", len(neg)) + neg,
                          _build_smb2_session_setup_response(sec)]
            self._recv = b""

        def sendall(self, _b):
            if self._pdus:
                self._recv += self._pdus.pop(0)

        def recv(self, n):
            out, self._recv = self._recv[:n], self._recv[n:]
            return out

        def settimeout(self, _t):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

    monkeypatch.setattr(smb.socket, "create_connection", lambda *a, **k: FakeSock())
    info = smb.probe_ntlm_info("10.0.0.5", 445, timeout=1.0)
    assert info is not None
    assert info["netbios_computer"] == "PC01"
    assert info["netbios_domain"] == "CORP"
    assert info["dns_domain"] == "corp.local"


def test_findings_emit_ntlm_info_disclosure_when_probe_has_ntlm_info():
    from recce.core.models import Host, Port
    from recce.services import smb
    h = Host(ip="10.0.0.5", ports=[Port(portid=445, state="open", protocol="tcp")])
    probes = {("10.0.0.5", 445): {
        "dialect": 0x0302, "dialect_name": "SMB 3.0.2",
        "signing_enabled": True, "signing_required": True, "smbv1": False,
        "ntlm_info": {"netbios_computer": "PC01", "netbios_domain": "CORP",
                      "dns_domain": "corp.local", "os_version": "10.0.19041",
                      "server_time_epoch": 1_700_000_000}}}
    fs = smb.findings([h], probes)
    kinds = [f["kind"] for f in fs]
    assert "smb_ntlm_info_disclosure" in kinds
    hit = next(f for f in fs if f["kind"] == "smb_ntlm_info_disclosure")
    assert hit["severity"] == "low"
    assert "PC01" in hit["detail"] and "corp.local" in hit["detail"]
    assert "10.0.19041" in hit["detail"]                    # OS build lands in the finding


def test_findings_no_ntlm_finding_when_probe_lacks_ntlm_info():
    from recce.core.models import Host, Port
    from recce.services import smb
    h = Host(ip="10.0.0.5", ports=[Port(portid=445, state="open", protocol="tcp")])
    probes = {("10.0.0.5", 445): {"dialect": 0x0302, "dialect_name": "SMB 3.0.2",
                                  "signing_enabled": True, "signing_required": True,
                                  "smbv1": False}}
    assert not any(f["kind"] == "smb_ntlm_info_disclosure"
                   for f in smb.findings([h], probes))
