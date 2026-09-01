"""creds.known_uploaded_shells: catalog of files recce PUT into a target
so a post-engagement cleanup consumer has a per-host DELETE list.
"""
from __future__ import annotations

from recce.core.models import Host, Port
from recce.creds.known_uploaded_shells import (cleanup_commands,
                                               known_uploaded_shells,
                                               record_uploaded_shell,
                                               uploaded_shells_for)


# --- record_uploaded_shell --------------------------------------------------

def test_record_attaches_and_reads_back():
    h = Host(ip="10.0.0.10")
    record_uploaded_shell(h, "10.0.0.10", 80, "/webdav/recce.php",
                          "DELETE", "webdav:put-webshell")
    got = uploaded_shells_for(h)
    assert len(got) == 1
    assert got[0]["path"] == "/webdav/recce.php"
    assert got[0]["cleanup_verb"] == "DELETE"
    assert got[0]["source"] == "webdav:put-webshell"
    assert got[0]["uploaded_at_iso"]  # datetime.now() stamp is set


def test_record_default_cleanup_verb_is_delete():
    h = Host(ip="10.0.0.10")
    record_uploaded_shell(h, "10.0.0.10", 80, "/dav/x.txt")
    assert uploaded_shells_for(h)[0]["cleanup_verb"] == "DELETE"


def test_record_is_idempotent_on_same_port_and_path():
    h = Host(ip="10.0.0.10")
    record_uploaded_shell(h, "10.0.0.10", 80, "/dav/x.txt")
    record_uploaded_shell(h, "10.0.0.10", 80, "/dav/x.txt")
    assert len(uploaded_shells_for(h)) == 1


def test_record_silently_drops_empty_path():
    h = Host(ip="10.0.0.10")
    record_uploaded_shell(h, "10.0.0.10", 80, "")
    record_uploaded_shell(h, "10.0.0.10", 80, "   ")
    assert uploaded_shells_for(h) == []


def test_cleanup_commands_emit_curl_delete_per_artifact():
    h = Host(ip="10.0.0.10")
    record_uploaded_shell(h, "10.0.0.10", 80, "/dav/a.php", "DELETE",
                          use_tls=False)
    record_uploaded_shell(h, "10.0.0.10", 443, "/dav/b.php", "DELETE",
                          use_tls=True)
    cmds = cleanup_commands(h)
    assert "curl -k -X DELETE http://10.0.0.10/dav/a.php" in cmds
    assert "curl -k -X DELETE https://10.0.0.10/dav/b.php" in cmds


def test_cleanup_commands_include_explicit_port_when_non_default():
    h = Host(ip="10.0.0.10")
    record_uploaded_shell(h, "10.0.0.10", 8080, "/dav/x.php", "DELETE")
    assert cleanup_commands(h) == [
        "curl -k -X DELETE http://10.0.0.10:8080/dav/x.php",
    ]


# --- engagement-wide reader -------------------------------------------------

def test_known_uploaded_shells_unions_across_hosts():
    a = Host(ip="10.0.0.10")
    b = Host(ip="10.0.0.20")
    record_uploaded_shell(a, "10.0.0.10", 80, "/dav/a.php")
    record_uploaded_shell(b, "10.0.0.20", 80, "/dav/b.php")
    got = known_uploaded_shells([a, b])
    assert got["count"] == 2
    assert {s["path"] for s in got["shells"]} == {"/dav/a.php", "/dav/b.php"}


# --- producer wire: webdav.analyze() ---------------------------------------

def test_webdav_analyze_wires_anon_put_and_rce_paths(monkeypatch):
    from recce.services import svcprobe, webdav

    h = Host(ip="10.0.0.10")
    h.ports = [Port(portid=80, protocol="tcp", state="open", service="http")]

    fake_pr = {
        "reachable": True, "mounts": [], "backend": {}, "caps": {},
        "auth_schemes": [], "hrefs": [], "users": [], "sensitive": [],
        "anon_put": {"proven": True, "path": "/webdav/recce_probe.txt"},
        "rce":      {"proven": True, "path": "/webdav/recce_probe.php",
                     "ext": "php", "nonce": "abc123"},
        "copy_bypass": {"proven": True, "path": "/webdav/recce_probe.asp",
                        "ext": "asp"},
    }

    def _fake_iter(targets, fn, budget=None, progress=None, state=None):
        for t in targets:
            yield t, fake_pr

    monkeypatch.setattr(svcprobe, "iter_probe", _fake_iter)
    webdav.analyze([h], active=True, upload_shell=True)

    got = known_uploaded_shells([h])
    paths = sorted(s["path"] for s in got["shells"])
    assert paths == ["/webdav/recce_probe.asp",
                     "/webdav/recce_probe.php",
                     "/webdav/recce_probe.txt"]
