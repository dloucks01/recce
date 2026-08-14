"""SMB enumeration coverage: null -> guest -> credentialed session selection.

Closes the gap where a locked-down standalone/workgroup host that denies null and
guest sessions but has valid credentials was never enumerated with those creds.
"""
from __future__ import annotations


def test_enum_session_uses_local_auth_for_workgroup_and_d_for_domain(monkeypatch):
    from recce import smb
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
    from recce import smb
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
