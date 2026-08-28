"""SMB enumeration coverage: null -> guest -> credentialed session selection.

Closes the gap where a locked-down standalone/workgroup host that denies null and
guest sessions but has valid credentials was never enumerated with those creds.
"""
from __future__ import annotations


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
