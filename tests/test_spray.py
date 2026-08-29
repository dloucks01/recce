"""The spray engine: parse netexec hits + run a lockout-safe spray (nxc mocked)."""
from __future__ import annotations

from recce.creds import credentials as cr, credenum
from recce.core.models import Account, Credential, Host, Port


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
    from recce import cli
    from recce.creds import credenum
    from recce.cli import _open_paths
    from recce.core.models import Host, Port
    from recce.core.store import Store
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


# --- crack -> spray: potfile import -------------------------------------------
# recce emitted hashcat-ready hashes in a dozen places and had no way back, so
# cracked passwords had to be re-keyed by hand before they could be sprayed.

_TGS = ("$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/db.corp.local:1433*"
        "$aabbccdd$eeff0011")
_ASREP = "$krb5asrep$23$noauth@CORP.LOCAL:aabbccdd$eeff0011"


def _loot(tmp_path):
    d = tmp_path / "loot"
    d.mkdir()
    (d / "kerberoast.hash").write_text(_TGS + "\n", encoding="utf-8")
    (d / "asrep.hash").write_text(_ASREP + "\n", encoding="utf-8")
    return str(d)


def test_potfile_matches_nt_hash_case_insensitively(tmp_path):
    """recce stores NT hashes uppercase; hashcat writes its potfile lowercase."""
    creds = [Credential(username="alice", secret="8846F7EAEE8FB117AD06BDD830B7586C",
                        kind="nthash", domain="CORP")]
    got = cr.parse_potfile("8846f7eaee8fb117ad06bdd830b7586c:password", creds)
    assert len(got) == 1
    assert (got[0].username, got[0].secret, got[0].kind) == ("alice", "password", "password")
    assert got[0].domain == "CORP" and got[0].source == "cracked"


def test_potfile_handles_hashes_and_passwords_containing_colons(tmp_path):
    """A krb5tgs hash is full of colons and a password may contain them too, so
    splitting the line (rsplit(":", 1)) mangles both. Matching anchors on a hash
    recce already holds instead."""
    got = cr.parse_potfile(f"{_TGS}:Summer2024!\n{_ASREP}:Pa:ss:word\n",
                           [], _loot(tmp_path))
    by_user = {c.username: c.secret for c in got}
    assert by_user["svc_sql"] == "Summer2024!"      # SPN colon did not split the hash
    assert by_user["noauth"] == "Pa:ss:word"        # colons in the PASSWORD survived
    assert all(c.domain == "CORP.LOCAL" for c in got)


def test_potfile_skips_hashes_recce_never_captured(tmp_path):
    """A shared potfile carries other engagements' hashes; guessing at them would
    invent credentials for accounts recce never saw."""
    creds = [Credential(username="alice", secret="8846F7EAEE8FB117AD06BDD830B7586C",
                        kind="nthash")]
    got = cr.parse_potfile(
        "ffffffffffffffffffffffffffffffff:notours\n"
        "8846f7eaee8fb117ad06bdd830b7586c:password\n", creds)
    assert [c.secret for c in got] == ["password"]


def test_potfile_ignores_comments_blanks_and_dedups(tmp_path):
    creds = [Credential(username="alice", secret="8846F7EAEE8FB117AD06BDD830B7586C",
                        kind="nthash")]
    got = cr.parse_potfile(
        "# hashcat potfile\n\n"
        "8846f7eaee8fb117ad06bdd830b7586c:password\n"
        "8846f7eaee8fb117ad06bdd830b7586c:password\n", creds)
    assert len(got) == 1


def test_cracked_passwords_reach_the_spray_files(tmp_path):
    """The point of the loop: a cracked plaintext must end up in passwords.txt,
    which is the file the netexec spray commands consume."""
    creds = [Credential(username="alice", secret="8846F7EAEE8FB117AD06BDD830B7586C",
                        kind="nthash", domain="CORP")]
    cracked = cr.parse_potfile(f"8846f7eaee8fb117ad06bdd830b7586c:password\n"
                               f"{_TGS}:Summer2024!\n", creds, _loot(tmp_path))
    files = cr.write_files(creds + cracked, str(tmp_path / "creds"))
    assert "passwords.txt" in files
    body = open(files["passwords.txt"], encoding="utf-8").read()
    assert "password" in body and "Summer2024!" in body
    users = open(files["users.txt"], encoding="utf-8").read()
    assert "svc_sql" in users          # the roasted account is now sprayable too


def test_potfile_without_any_known_hashes_returns_nothing(tmp_path):
    assert cr.parse_potfile("abc:def", [], "") == []


# --- users.txt now folds in the engagement's enumerated user list ---------
# Any spray consumer (netexec ssh / smb / winrm / mssql / ldap) reads
# users.txt, so folding known_users() in here means SSH spray automatically
# tries every account BloodHound / LDAP / SNMP / SAMR / netexec enum'd —
# same principle as the crack loop and the IPMI RAKP wire-up.

def test_write_files_folds_bloodhound_users_into_users_txt(tmp_path):
    """A host with BloodHound-parsed accounts + one credentialed user should
    produce a users.txt containing BOTH — recce's spray now reaches every
    account it enumerated, not just those it had a password for."""
    h = Host(ip="10.0.0.10")
    h.accounts = [
        Account(ip="10.0.0.10", source="bloodhound", kind="user", name="alice"),
        Account(ip="10.0.0.10", source="bloodhound", kind="user",
                name="svc_backup"),
    ]
    creds = [Credential(username="administrator", secret="Passw0rd!",
                        kind="password")]
    files = cr.write_files(creds, str(tmp_path), hosts=[h])
    lines = open(files["users.txt"], encoding="utf-8").read().splitlines()
    assert set(lines) == {"administrator", "alice", "svc_backup"}
    # Ordering: credential users first (recce SAW them), then enum users
    # priority-ordered — the credential one lands ahead of any enum-only.
    assert lines[0] == "administrator"


def test_write_files_without_hosts_arg_falls_back_to_creds_only(tmp_path):
    """Legacy call path (no hosts=) MUST stay working — otherwise every
    caller not yet migrated silently drops the enum-only users. And when
    hosts= is omitted the ordering / dedup logic must still work."""
    creds = [Credential(username="alice", secret="pw", kind="password"),
             Credential(username="bob", secret="nt" * 16, kind="nthash")]
    files = cr.write_files(creds, str(tmp_path))
    lines = open(files["users.txt"], encoding="utf-8").read().splitlines()
    assert lines == ["alice", "bob"]


def test_write_files_dedupes_case_insensitively_across_creds_and_enum(tmp_path):
    """BloodHound gives ADMIN, credentials store gives Admin — one account.
    Cred-side casing wins because it was seen first."""
    h = Host(ip="10.0.0.1")
    h.accounts = [
        Account(ip="10.0.0.1", source="bloodhound", kind="user", name="ADMIN"),
    ]
    creds = [Credential(username="Admin", secret="pw", kind="password")]
    files = cr.write_files(creds, str(tmp_path), hosts=[h])
    lines = open(files["users.txt"], encoding="utf-8").read().splitlines()
    assert lines == ["Admin"]


def test_build_spray_reports_the_enum_only_folded_in_users(tmp_path):
    """The CLI prints '[+] N additional username(s) from engagement enum
    folded into users.txt' — that requires build_spray() to return the
    count + source list, not just the file list."""
    h = Host(ip="10.0.0.10", ports=[Port(portid=22, service="ssh", state="open")])
    h.accounts = [
        Account(ip="10.0.0.10", source="bloodhound", kind="user", name="alice"),
        Account(ip="10.0.0.10", source="ldap", kind="user", name="bob"),
    ]
    creds = [Credential(username="administrator", secret="pw", kind="password")]
    summary = cr.build_spray(creds, [h], str(tmp_path))
    enum_only = summary["enum_only_users"]
    assert set(enum_only) == {"alice", "bob"}
    assert set(summary["enum_only_sources"]) == {"bloodhound", "ldap"}


def test_run_spray_returns_enum_only_users_for_the_cli_summary(monkeypatch, tmp_path):
    """The `--run` path prints the same "N additional username(s) from
    engagement enum" summary that `--plan` does. That summary needs the
    enum_only_users + enum_only_sources fields on run_spray's return."""
    monkeypatch.setattr(credenum, "smb_tool", lambda: "nxc")
    monkeypatch.setattr(credenum, "_run", lambda cmd, timeout=0, **k: ("", None))
    h = _h("10.0.0.5", 445, "smb")
    h.accounts = [
        Account(ip="10.0.0.5", source="bloodhound", kind="user", name="alice"),
        Account(ip="10.0.0.5", source="ldap", kind="user", name="svc_backup"),
    ]
    res = cr.run_spray([h],
                       [Credential(username="administrator", secret="pw",
                                   kind="password")],
                       str(tmp_path))
    assert res["ok"]
    # Both enum-only users surface, administrator does NOT (it had a cred)
    assert set(res["enum_only_users"]) == {"alice", "svc_backup"}
    assert set(res["enum_only_sources"]) == {"bloodhound", "ldap"}


def test_ssh_spray_line_now_targets_the_widened_users_txt(tmp_path):
    """The SSH spray command uses users.txt verbatim — extending users.txt
    means the SSH spray automatically tries every enumerated account with
    no other change to the spray path."""
    h = Host(ip="10.0.0.10",
             ports=[Port(portid=22, service="ssh", state="open")])
    h.accounts = [Account(ip="10.0.0.10", source="ldap", kind="user",
                          name="svc_backup")]
    creds = [Credential(username="alice", secret="pw", kind="password")]
    summary = cr.build_spray(creds, [h], str(tmp_path))
    files = summary["files"]
    users = open(files["users.txt"], encoding="utf-8").read().splitlines()
    assert "svc_backup" in users                              # got folded in
    ssh_lines = [line for line in summary["commands"]
                 if line.lstrip().startswith("netexec ssh")]
    assert ssh_lines and "users.txt" in ssh_lines[0]         # spray uses it
