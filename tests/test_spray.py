"""The spray engine: parse netexec hits + run a lockout-safe spray (nxc mocked)."""
from __future__ import annotations

from recce import credentials as cr, credenum
from recce.models import Credential, Host, Port


def _h(ip, port, svc):
    return Host(ip=ip, ports=[Port(portid=port, service=svc, state="open")])


def test_parse_nxc_hits_extracts_logins_and_admin():
    out = (
        "SMB   10.0.0.11  445  SQL01  [*] Windows 10.0 Build 17763\n"
        "SMB   10.0.0.11  445  SQL01  [+] corp.local\\svc_sql:Summer2023! (Pwn3d!)\n"
        "SMB   10.0.0.23  445  FS01   [-] corp.local\\svc_sql:Summer2023! STATUS_LOGON_FAILURE\n"
        "SSH   10.0.0.30  22   redis  [+] root:root\n")
    hits = cr._parse_nxc_hits(out)
    assert len(hits) == 2                                  # the FAIL line is not a hit
    smb = next(h for h in hits if h["ip"] == "10.0.0.11")
    assert smb["user"] == "corp.local\\svc_sql" and smb["secret"] == "Summer2023!" and smb["admin"]
    assert not next(h for h in hits if h["ip"] == "10.0.0.30")["admin"]


def test_run_spray_needs_a_tool(monkeypatch, tmp_path):
    monkeypatch.setattr(credenum, "smb_tool", lambda: None)
    res = cr.run_spray([_h("10.0.0.5", 445, "smb")],
                       [Credential(username="u", secret="p", kind="password")], str(tmp_path))
    assert res["ok"] is False and "netexec" in res["error"]


def test_run_spray_needs_usernames(monkeypatch, tmp_path):
    monkeypatch.setattr(credenum, "smb_tool", lambda: "nxc")
    res = cr.run_spray([_h("10.0.0.5", 445, "smb")], [], str(tmp_path))
    assert res["ok"] is False and "username" in res["error"]


def test_run_spray_is_lockout_safe_by_default(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, timeout=0, **k):
        calls.append(cmd)
        return "", None

    monkeypatch.setattr(credenum, "smb_tool", lambda: "nxc")
    monkeypatch.setattr(credenum, "_run", fake_run)
    cred = [Credential(username="u", secret="p", kind="password")]
    cr.run_spray([_h("10.0.0.5", 445, "smb")], cred, str(tmp_path))
    assert calls and "--no-bruteforce" in calls[0]         # safe by default
    calls.clear()
    cr.run_spray([_h("10.0.0.5", 445, "smb")], cred, str(tmp_path), safe=False)
    assert calls and "--no-bruteforce" not in calls[0]     # full user x pass only when opted in


def test_run_spray_returns_parsed_hits(monkeypatch, tmp_path):
    monkeypatch.setattr(credenum, "smb_tool", lambda: "nxc")
    out = "SMB  10.0.0.5  445  H  [+] corp\\svc:P@ss (Pwn3d!)"
    monkeypatch.setattr(credenum, "_run", lambda cmd, timeout=0, **k: (out, None))
    res = cr.run_spray([_h("10.0.0.5", 445, "smb")],
                       [Credential(username="svc", secret="P@ss", kind="password")], str(tmp_path))
    assert res["ok"] and len(res["hits"]) == 1 and res["hits"][0]["admin"]


def test_credenum_all_creds_sprays_then_enums_with_the_working_cred(monkeypatch, tmp_path):
    # --all-creds sprays to discover the working cred per host, then enumerates each
    # host with ITS discovered cred (nxc + enrich_host mocked - no network).
    import contextlib
    import io
    from recce import cli, credenum
    from recce.cli import _open_paths
    from recce.models import Host, Port
    from recce.store import Store
    eng = str(tmp_path / "e")
    st = Store(_open_paths(eng)["db"])
    st.upsert_host(Host(ip="10.0.0.5", ports=[Port(portid=445, service="smb", state="open")]))
    st.add_credential(Credential(username="svc", secret="P@ss", kind="password", source="loot"))
    st.close()
    monkeypatch.setattr(credenum, "smb_tool", lambda: "nxc")
    monkeypatch.setattr(credenum, "_run",
                        lambda cmd, timeout=0, **k: ("SMB 10.0.0.5 445 H [+] svc:P@ss (Pwn3d!)", None))
    seen = {}

    def fake_enrich(host, creds, ssh_creds, aggressive=False, admin_creds=None):
        seen[host.ip] = creds
        return [], {"user": {"tried": True, "auth": bool(creds), "admin": False}}

    monkeypatch.setattr(credenum, "enrich_host", fake_enrich)
    with contextlib.redirect_stdout(io.StringIO()):
        rc = cli.main(["credenum", "--all-creds", "-o", eng])
    assert rc == 0
    assert seen.get("10.0.0.5", {}).get("username") == "svc"     # enumed with the discovered cred
