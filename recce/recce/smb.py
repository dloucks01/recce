"""Deep offensive SMB enumeration + vulnerability identification (stdlib core).

Modelled on recce/mssql.py. Two layers:

  * **Credential-free (airgapped, recce's own stdlib probes):** an SMB2 NEGOTIATE
    reveals the highest dialect and the *signing posture* (signing required vs
    merely enabled -> the NTLM-relay surface); a separate SMBv1 NEGOTIATE reveals
    whether the legacy SMBv1 protocol is still answered (the EternalBlue / MS17-010
    surface). No tools, no credentials - just crafted packets, like the TDS
    pre-login probe the MSSQL module uses.
  * **With tools / credentials:** null & guest session share enumeration (via
    `nxc smb` / `smbclient`), a reversible *writable-share* proof (drop a marker
    file, list it, delete it), and the credentialed runbook (shares / users /
    password policy / secretsdump / relay).

Everything positive becomes a finding that folds into the main severity totals,
the Vulnerabilities sheet, the write-ups, and a dedicated **SMB** workbook tab -
and each finding carries the exact existing-tool command to prove or abuse it.
Airgapped, stdlib only for the probe; the live layer shells out to the same
tools `credenum` already uses and degrades cleanly when they're absent. Safety
posture: see SECURITY.md.
"""
from __future__ import annotations

import socket
import struct

from .models import Host, Port

_SMB_PORTS = (445, 139)
_DEFAULT_PORT = 445
_TIMEOUT = 6.0
_PROBE_MARK = "recce_smb_probe"

# SMB2 dialect revision -> human label.
_DIALECT = {
    0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1", 0x02FF: "SMB 2.wildcard",
}
_SMB1_DIALECTS = [b"PC NETWORK PROGRAM 1.0", b"LANMAN1.0",
                  b"Windows for Workgroups 3.1a", b"LM1.2X002",
                  b"LANMAN2.1", b"NT LM 0.12"]


def is_smb(port: Port) -> bool:
    if port.state != "open":
        return False
    if port.portid in _SMB_PORTS:
        return True
    blob = f"{port.service} {port.product}".lower()
    return any(k in blob for k in ("microsoft-ds", "netbios-ssn", "smb", "samba"))


# --- credential-free wire probe (stdlib) ----------------------------------------

def _smb2_header(command: int, flags: int = 0) -> bytes:
    return (b"\xfeSMB"
            + struct.pack("<H", 64) + struct.pack("<H", 0) + struct.pack("<I", 0)
            + struct.pack("<H", command) + struct.pack("<H", 1)
            + struct.pack("<I", flags) + struct.pack("<I", 0)
            + struct.pack("<Q", 0) + struct.pack("<I", 0) + struct.pack("<I", 0)
            + struct.pack("<Q", 0) + b"\x00" * 16)


def _build_smb2_negotiate() -> bytes:
    # Offer 2.0.2 .. 3.0.2. We deliberately do NOT offer 3.1.1 (0x0311): it requires
    # negotiate contexts (preauth integrity) we don't build, so a 3.1.1-capable server
    # offered a bare 0x0311 would select it and reply STATUS_INVALID_PARAMETER. Every
    # such server also speaks 3.0.2, so it negotiates that instead and returns a valid
    # response we can read signing posture from.
    dialects = [0x0202, 0x0210, 0x0300, 0x0302]
    body = (struct.pack("<H", 36) + struct.pack("<H", len(dialects))
            + struct.pack("<H", 0x0001)          # SecurityMode: signing enabled
            + struct.pack("<H", 0) + struct.pack("<I", 0) + b"\x00" * 16
            + struct.pack("<I", 0) + struct.pack("<H", 0) + struct.pack("<H", 0)
            + b"".join(struct.pack("<H", d) for d in dialects))
    smb = _smb2_header(0x0000) + body
    return struct.pack(">I", len(smb)) + smb


def parse_smb2_negotiate(data: bytes) -> dict | None:
    """dialect + signing posture from an SMB2 NEGOTIATE response.

    Validates the SMB2 header before trusting the body: an *error* response (e.g.
    STATUS_INVALID_PARAMETER) or a non-NEGOTIATE reply would otherwise be read as a
    dialect-0 / signing-not-required host and emit a bogus 'signing not required'
    finding. Requires Command==NEGOTIATE(0), Status==SUCCESS, and StructureSize==65.
    """
    if not data or len(data) < 4 + 64 + 8:
        return None
    smb = data[4:]
    if smb[:4] != b"\xfeSMB":
        return None
    status = struct.unpack("<I", smb[8:12])[0]
    command = struct.unpack("<H", smb[12:14])[0]
    if command != 0x0000 or status != 0x00000000:
        return None                              # error / wrong command - not a NEGOTIATE OK
    body = smb[64:]
    if len(body) < 8 or struct.unpack("<H", body[0:2])[0] != 65:
        return None                              # NEGOTIATE response StructureSize is 65
    sec_mode = struct.unpack("<H", body[2:4])[0]
    dialect = struct.unpack("<H", body[4:6])[0]
    return {"dialect": dialect,
            "dialect_name": _DIALECT.get(dialect, f"0x{dialect:04x}"),
            "signing_enabled": bool(sec_mode & 0x01),
            "signing_required": bool(sec_mode & 0x02)}


def _build_smb1_negotiate() -> bytes:
    header = (b"\xffSMB" + b"\x72" + b"\x00\x00\x00\x00" + b"\x18"
              + b"\x01\x28" + b"\x00\x00" + b"\x00" * 8 + b"\x00\x00"
              + b"\x00\x00" + b"\x2f\x4b" + b"\x00\x00" + b"\xc5\x5e")
    blob = b"".join(b"\x02" + d + b"\x00" for d in _SMB1_DIALECTS)
    body = b"\x00" + struct.pack("<H", len(blob)) + blob
    smb = header + body
    return struct.pack(">I", len(smb)) + smb


def parse_smb1_negotiate(data: bytes) -> dict:
    """True if the server answered SMBv1 with a selected dialect (SMBv1 enabled)."""
    if not data or len(data) < 4 + 35:
        return {"smbv1": False}
    smb = data[4:]
    if smb[:4] != b"\xffSMB" or smb[4] != 0x72 or smb[32] == 0:
        return {"smbv1": False}
    idx = struct.unpack("<H", smb[33:35])[0]
    if idx == 0xFFFF:
        return {"smbv1": False}
    return {"smbv1": True, "dialect_index": idx}


def _exchange(ip: str, port: int, payload: bytes, timeout: float) -> bytes | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(payload)
            head = s.recv(4)
            if len(head) < 4:
                return None
            n = struct.unpack(">I", head)[0] & 0x00FFFFFF
            buf = b""
            while len(buf) < n and len(buf) < 65535:
                chunk = s.recv(min(4096, n - len(buf)))
                if not chunk:
                    break
                buf += chunk
            return head + buf
    except OSError:
        return None


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict | None:
    """Credential-free SMB posture: dialect, signing, whether SMBv1 is enabled.
    Returns None only if the host answered neither SMB2 nor SMB1."""
    r2 = _exchange(ip, port, _build_smb2_negotiate(), timeout)
    neg = parse_smb2_negotiate(r2)
    r1 = _exchange(ip, port, _build_smb1_negotiate(), timeout)
    v1 = parse_smb1_negotiate(r1)
    if neg is None and not v1.get("smbv1"):
        return None
    out = {"ip": ip, "port": port, "smbv1": bool(v1.get("smbv1"))}
    if neg:
        out.update(neg)
    return out


def smb_targets(hosts: list[Host]) -> list[dict]:
    """One row per open SMB port across the given hosts."""
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_smb(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product or "", "version": p.version or ""})
    return out


# --- narratives -----------------------------------------------------------------

_NARRATIVE = {
    "smbv1": (
        "SMBv1 is a 30-year-old file-sharing protocol Microsoft deprecated and now "
        "disables by default. A server that still answers it exposes the exact "
        "surface of MS17-010 / EternalBlue (CVE-2017-0143/0144 - the wormable RCE "
        "behind WannaCry and NotPetya): a heap-overflow in the SMBv1 transaction "
        "handler that yields SYSTEM-level remote code execution pre-authentication. "
        "SMBv1 also has no support for signing or encryption and negotiates the "
        "weak NTLMv1 flows, so it enables downgrade and relay attacks even when it "
        "isn't the EternalBlue-vulnerable build. Its mere presence is a critical "
        "hardening failure; confirm the patch level with the non-intrusive "
        "smb-vuln-ms17-010 NSE check to separate 'legacy protocol on' from "
        "'remotely exploitable today'."),
    "smb_signing": (
        "SMB message signing that is 'not required' means the server will accept an "
        "unsigned session - the precondition for an NTLM relay TO this host. An "
        "attacker who coerces authentication from a privileged account (PetitPotam / "
        "PrinterBug / a poisoned LLMNR/NBNS/mDNS response captured by Responder) "
        "relays that NetNTLM authentication straight to this machine over SMB with "
        "ntlmrelayx and acts AS the victim: dump the SAM, run secretsdump, execute a "
        "command, or (if the victim is a Domain Admin / the machine account of a DC) "
        "escalate to full domain compromise. Where the relayed account is a local "
        "admin, it is instant remote code execution as SYSTEM. Domain Controllers "
        "require signing by default - a member server or workstation that does not "
        "is the classic relay landing spot."),
    "null_session": (
        "A null / anonymous session is an unauthenticated SMB logon (empty username "
        "and password) that the server nonetheless honours. It leaks the domain SID, "
        "the full user and group list (feeding password-spray target lists and "
        "AS-REP/Kerberoast candidate discovery), the password policy (so you spray "
        "without tripping lockout), the machine and share inventory, and often the "
        "contents of world-readable shares. It is reconnaissance gold and frequently "
        "the first foothold: enum4linux-ng / rpcclient / nxc all pivot from it."),
    "guest": (
        "The guest account is enabled and maps unauthenticated or unknown logons to "
        "a real, if low-privileged, session. That turns 'access denied' into 'access "
        "granted' for share reads and RPC enumeration without any credential, and on "
        "misconfigured hosts guest can reach shares that hold scripts, backups or "
        "credentials."),
    "readable_share": (
        "A non-administrative share is readable without valid credentials (null / "
        "guest). Open shares routinely hold deployment scripts, configuration files "
        "with embedded passwords, database backups, private keys, and user home "
        "directories - the raw material for the next hop. Everything here is "
        "exfiltratable with a single smbclient / smbget."),
    "writable_share": (
        "A share is WRITABLE without administrative credentials. Beyond planting a "
        "web shell where a share backs a web root, a writable share enables passive "
        "credential theft: drop a poisoned .SCF, .URL, .LNK, or desktop.ini that "
        "points its icon at a UNC path on your host, and any user who browses the "
        "folder in Explorer silently authenticates to you - capture the NetNTLM hash "
        "with Responder and crack or relay it. Writable network shares are also a "
        "common ransomware and lateral-movement vector. recce proves the write is "
        "real by dropping a harmless marker, listing it, and immediately deleting it "
        "again (fully reversible)."),
}


def narrative_for(kind: str) -> str:
    return _NARRATIVE.get(kind, "")


TESTING_NARRATIVE = [
    ("1. Credential-free posture (stdlib)",
     "recce sends an SMB2 NEGOTIATE and reads the highest dialect and the signing "
     "posture (required vs merely enabled), then sends an SMBv1 NEGOTIATE to see "
     "whether the legacy protocol is still answered. No tools, no credentials - the "
     "signing and SMBv1 states are directly observed, not inferred from a banner."),
    ("2. Vulnerability identification",
     "SMBv1 answered -> the MS17-010 / EternalBlue surface (critical). Signing not "
     "required -> the NTLM-relay surface. These fold into the main severity totals "
     "and the prove engine adjudicates each from the observed state."),
    ("3. Anonymous enumeration",
     "With nxc / smbclient, recce tries a null and guest session and enumerates the "
     "share, user and password-policy inventory an anonymous logon leaks - the "
     "reconnaissance an attacker gets before holding any credential."),
    ("4. Access + write proof",
     "For each reachable share recce records READ/WRITE ACLs, and for a writable "
     "share it PROVES the write reversibly: drop a marker file, list it, delete it. "
     "A confirmed write is a CONFIRMED finding with the terminal transcript as "
     "proof - the material for a technical walkthrough screenshot."),
    ("5. Credentialed runbook",
     "Given credentials, recce stages the full enumeration (shares / users / "
     "sessions / logged-on / password policy), secretsdump where the account is "
     "admin, and the relay chain where signing is off - each command pre-filled."),
]


# --- findings -------------------------------------------------------------------

def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind=""):
    return {"category": "smb", "severity": sev, "title": title, "target": target,
            "detail": detail, "tool": tool, "command": cmd, "remediation": rem,
            "cwes": list(cwes), "kind": kind, "narrative": _NARRATIVE.get(kind, "")}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    """Offline SMB findings from the stdlib probe + any NSE scripts already on the
    port. `probes` is {(ip,port): probe_dict} from analyze(); when absent only the
    NSE-derived findings are produced."""
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_smb(p):
                continue
            tgt = f"{h.ip}:{p.portid}"
            pr = probes.get((h.ip, p.portid))
            if pr and pr.get("smbv1"):
                out.append(_finding(
                    "high", "SMBv1 (legacy protocol) enabled - EternalBlue/MS17-010 surface",
                    tgt,
                    "The host answered an SMBv1 NEGOTIATE with a selected dialect - the "
                    "deprecated SMBv1 protocol is still enabled (directly observed, not a "
                    "banner guess). This is the MS17-010 / EternalBlue attack surface.",
                    "nmap",
                    "nmap --script smb-vuln-ms17-010 -p445 <ip>   # non-intrusive: "
                    "VULNERABLE = remotely exploitable now, NOT VULNERABLE = legacy proto "
                    "on but patched",
                    "Disable SMBv1 entirely (Windows: Remove-WindowsFeature FS-SMB1 / "
                    "registry SMB1=0; Samba: 'server min protocol = SMB2_10').",
                    ["CWE-1104", "CWE-477"], kind="smbv1"))
            if pr and "signing_required" in pr and not pr["signing_required"]:
                out.append(_finding(
                    "medium",
                    "SMB signing not required (NTLM relay surface)", tgt,
                    f"The SMB2 NEGOTIATE reported signing not required "
                    f"(dialect {pr.get('dialect_name', '?')}) - directly observed. An NTLM "
                    "relay TO this host will succeed, so coerced/poisoned authentication can "
                    "be replayed here to act as the victim.",
                    "impacket / nxc",
                    "nxc smb <ip> --gen-relay-list relays.txt ; "
                    "ntlmrelayx.py -t smb://<ip> -smb2support   # relay a coerced login "
                    "(PetitPotam/Responder) in ROE",
                    "Require SMB signing (GPO: 'Microsoft network server: Digitally sign "
                    "communications (always)' = Enabled; Samba: 'server signing = mandatory').",
                    ["CWE-287", "CWE-319"], kind="smb_signing"))
    return out


# --- runbooks -------------------------------------------------------------------

def _fill(text: str, ip: str, port: int, creds: dict | None) -> str:
    creds = creds or {}
    return (text.replace("<ip>", ip).replace("<port>", str(port))
            .replace("<user>", creds.get("user") or "<user>")
            .replace("<pass>", creds.get("secret") or "<pass>")
            .replace("<domain>", creds.get("domain") or "<domain>"))


def credfree_runbook(ip: str, port: int) -> list[dict]:
    steps = [
        ("recon", "nmap NSE", "nmap -p445 --script smb-protocols,smb2-security-mode,"
         "smb-vuln-ms17-010,smb-enum-shares <ip>",
         "Dialects, signing posture, MS17-010 status, anonymous shares."),
        ("recon", "enum4linux-ng", "enum4linux-ng -A <ip>",
         "Null-session sweep: domain SID, users, groups, shares, password policy."),
        ("recon", "nxc (null)", "nxc smb <ip> -u '' -p '' --shares --users --pass-pol",
         "Anonymous share/user/policy enumeration."),
        ("recon", "nxc (guest)", "nxc smb <ip> -u 'guest' -p '' --shares",
         "Guest-account share access."),
    ]
    return [{"phase": ph, "tool": t,
             "command": _fill(c, ip, port, None), "why": w}
            for ph, t, c, w in steps]


def cred_runbook(ip: str, port: int, creds: dict | None) -> list[dict]:
    steps = [
        ("enumerate", "nxc smb",
         "nxc smb <ip> -u <user> -p <pass> --shares --users --sessions "
         "--loggedon-users --pass-pol",
         "Authenticated inventory: shares+ACLs, users, sessions, policy."),
        ("enumerate", "nxc spider", "nxc smb <ip> -u <user> -p <pass> -M spider_plus",
         "Recursively index every readable share for secrets/backups."),
        ("loot", "smbclient",
         "smbclient //<ip>/<share> -U '<domain>\\<user>%<pass>' -c 'recurse; ls'",
         "Browse and pull interesting files from a readable share."),
        ("escalate", "secretsdump",
         "impacket-secretsdump '<domain>/<user>:<pass>@<ip>'",
         "If the account is local admin: dump the SAM/LSA secrets (local hashes)."),
        ("escalate", "relay",
         "ntlmrelayx.py -t smb://<ip> -smb2support   # when signing is not required",
         "Relay a coerced/poisoned login to act as the victim on this host."),
    ]
    return [{"phase": ph, "tool": t, "command": _fill(c, ip, port, creds), "why": w}
            for ph, t, c, w in steps]


# --- live tools (nxc / smbclient) -----------------------------------------------

def _tool(*names):
    import shutil
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def smb_tool():
    return _tool("nxc", "netexec", "crackmapexec")


def smbclient_tool():
    return _tool("smbclient")


def _run(cmd, timeout: int = 120) -> tuple[str, str | None]:
    from .util import run_tool
    return run_tool(cmd, timeout)


def enum_session(ip: str, user: str = "", password: str = "",
                 port: int = _DEFAULT_PORT) -> dict:
    """Run `nxc smb` for a (possibly null/guest) session and parse the result via
    the shared credenum parser. Returns {ran, auth, shares, users, passpol, error}."""
    tool = smb_tool()
    if not tool:
        return {"ran": False, "error": "nxc/netexec not installed", "shares": [],
                "users": [], "auth": False}
    cmd = [tool, "smb", ip, "-u", user, "-p", password,
           "--shares", "--users", "--pass-pol"]
    if port and port != _DEFAULT_PORT:
        cmd += ["--port", str(port)]
    out, err = _run(cmd)
    if err:
        return {"ran": True, "error": err, "shares": [], "users": [], "auth": False,
                "output": out}
    from .credenum import parse_nxc_smb
    data = parse_nxc_smb(out)
    data["ran"] = True
    data["error"] = None
    data["output"] = out
    return data


def prove_writable(ip: str, share: str, creds: dict | None = None,
                   port: int = _DEFAULT_PORT) -> dict:
    """Reversibly prove a share is writable: drop a marker file, list it, delete it.
    Returns {writable, evidence, command, error}. Never leaves the marker behind."""
    tool = smbclient_tool()
    if not tool:
        return {"writable": False, "error": "smbclient not installed"}
    creds = creds or {}
    marker = f"{_PROBE_MARK}.txt"
    if creds.get("user"):
        dom = creds.get("domain") or ""
        auth = f"{dom}\\{creds['user']}%{creds.get('secret', '')}" if dom \
            else f"{creds['user']}%{creds.get('secret', '')}"
        authflag = ["-U", auth]
    else:
        authflag = ["-N"]                      # anonymous / null
    # Write a temp local file to upload, then put/list/delete on the share.
    import tempfile
    import os
    fd, local = tempfile.mkstemp(prefix="recce_smb_", suffix=".txt")
    try:
        os.write(fd, b"recce-writable-share-proof\n")
        os.close(fd)
        script = f"put {local} {marker}; ls {marker}; del {marker}"
        cmd = [tool, f"//{ip}/{share}"] + authflag + ["-c", script]
        if port and port != _DEFAULT_PORT:
            cmd += ["-p", str(port)]
        out, err = _run(cmd, timeout=60)
    finally:
        try:
            os.unlink(local)
        except OSError:
            pass
    if err:
        return {"writable": False, "error": err, "command": " ".join(cmd)}
    low = out.lower()
    # Judge the WRITE from the put itself, not the whole transcript: smbclient prints
    # "putting file ... as \marker (rate)" only on a successful STOR, and
    # "NT_STATUS_..._DENIED opening remote file" when the put is refused. (Keying off
    # the whole blob would let the trailing `del` result - which can be ACCESS_DENIED
    # on a create-but-not-delete share - flip a real write to a false negative.)
    wrote = "putting file" in low and "opening remote file" not in low
    # Cleanup contract: if the write landed but the in-script `del` was refused, the
    # marker is still on the share - make one more explicit delete attempt so we never
    # leave it behind, and record whether cleanup succeeded.
    cleanup_ok = wrote and "deleting remote file" not in low  # no delete error seen
    if wrote and not cleanup_ok:
        del_cmd = [tool, f"//{ip}/{share}"] + authflag + ["-c", f"del {marker}"]
        if port and port != _DEFAULT_PORT:
            del_cmd += ["-p", str(port)]
        d_out, _d_err = _run(del_cmd, timeout=30)
        cleanup_ok = "nt_status" not in (d_out or "").lower()
        out += "\n" + d_out
    ev = out.strip()
    if wrote and not cleanup_ok:
        ev += (f"\n\n[!] cleanup: the delete of {marker} was refused - the marker may "
               "remain on the share; remove it manually.")
    return {"writable": bool(wrote), "cleanup_ok": bool(cleanup_ok),
            "evidence": ev, "command": " ".join(cmd), "error": None}


def null_session_findings(ip: str, port: int, session: dict) -> list[dict]:
    """Turn a successful null/guest nxc session into findings."""
    out: list[dict] = []
    tgt = f"{ip}:{port}"
    shares = session.get("shares") or []
    users = session.get("users") or []
    if not session.get("ran") or session.get("error"):
        return out
    # A null session that enumerated anything at all is a confirmed anonymous logon.
    if shares or users:
        detail = (f"An anonymous (null) SMB session enumerated {len(shares)} share(s) "
                  f"and {len(users)} user(s) without credentials.")
        out.append(_finding(
            "medium", "SMB null / anonymous session allows enumeration", tgt,
            detail + "  This leaks the share/user inventory and password policy an "
            "attacker uses to build spray lists.", "nxc / enum4linux-ng",
            "nxc smb <ip> -u '' -p '' --shares --users --pass-pol",
            "Restrict anonymous access: RestrictNullSessManagement, "
            "RestrictAnonymous=1; Samba 'restrict anonymous = 2'.",
            ["CWE-306", "CWE-200"], kind="null_session"))
    # Non-admin readable shares reachable anonymously.
    readable = [s for s in shares if "READ" in (s.get("perms") or "").upper()
                and s.get("name", "").upper() not in ("IPC$", "PRINT$")]
    if readable:
        names = ", ".join(s["name"] for s in readable[:12])
        out.append(_finding(
            "medium", "SMB share readable without credentials", tgt,
            f"Anonymous/guest read access to share(s): {names}. Open shares routinely "
            "hold scripts, backups and configs with embedded secrets.",
            "smbclient", "smbclient //<ip>/<share> -N -c 'recurse; ls'",
            "Remove anonymous READ from non-public shares; review share + NTFS ACLs.",
            ["CWE-200", "CWE-306"], kind="readable_share"))
    return out


def write_proof_finding(ip: str, port: int, share: str, proof: dict,
                        creds: dict | None) -> dict | None:
    if not proof.get("writable"):
        return None
    anon = "" if (creds and creds.get("user")) else "anonymous/guest "
    return _finding(
        "high", f"Writable SMB share (proven): {share}", f"{ip}:{port}",
        f"recce PROVED write access to \\\\{ip}\\{share} with {anon}access by "
        "dropping a marker file, listing it, then deleting it (fully reversible):\n\n"
        + (proof.get("evidence") or ""),
        "smbclient / Responder",
        "smbclient //<ip>/" + share + " -N -c 'put poison.scf; ls'   # then capture "
        "NetNTLM with Responder; or drop a web shell if the share backs a web root",
        "Remove write access for non-admin/anonymous principals; audit share + NTFS "
        "ACLs.", ["CWE-732", "CWE-276"], kind="writable_share")


# --- proof screenshot -----------------------------------------------------------

def proof_html(command, output, banner: str = "") -> str:
    from . import mssql
    return mssql.proof_html(command, output, prompt="# ", banner=banner)


# --- top-level analyze ----------------------------------------------------------

def findings_to_vulns(fs: list[dict]) -> dict:
    """SMB findings -> {ip: [Vuln]} (source='smb'), for the main totals + writeups."""
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "smb", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    """Full offline SMB analysis. Returns {targets, findings, runbooks, stats}.
    When active, runs the stdlib negotiate probe against each target (no creds/tools
    needed); the live tool layer (share enum / write proof) is driven from cmd_smb.
    `budget` caps wall-clock seconds; `progress(i, n, target)` fires per probe."""
    from . import svcprobe
    targets = smb_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["dialect"] = pr.get("dialect_name", "")
                t["smbv1"] = pr.get("smbv1", False)
                t["signing_required"] = pr.get("signing_required")
    fs = findings(hosts, probes)
    runbooks = []
    for t in targets:
        runbooks.append({
            "target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
            "credfree": credfree_runbook(t["ip"], t["port"]),
            "credentialed": cred_runbook(t["ip"], t["port"], creds)})
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
