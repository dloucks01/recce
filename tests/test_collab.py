"""Tests for recce/webui/collab.py — collaboration state helpers."""
from __future__ import annotations

import time

import pytest

from recce.store import Store
from recce.webui.collab import (
    Presence,
    add_activity,
    add_chat,
    get_activity,
    get_assignments,
    get_chat,
    get_dismissed,
    get_labels,
    get_port_status,
    image_ext,
    set_assignment,
    set_dismissed,
    set_label,
    set_port_status,
)


@pytest.fixture
def st(tmp_path):
    with Store(str(tmp_path / "test.sqlite")) as s:
        yield s


# --- assignments --------------------------------------------------------------

def test_assignments_empty_by_default(st):
    assert get_assignments(st) == {}


def test_set_assignment_adds_and_returns(st):
    result = set_assignment(st, "10.0.0.1", "alice")
    assert result == {"10.0.0.1": "alice"}
    assert get_assignments(st) == {"10.0.0.1": "alice"}


def test_set_assignment_overwrites(st):
    set_assignment(st, "10.0.0.1", "alice")
    set_assignment(st, "10.0.0.1", "bob")
    assert get_assignments(st)["10.0.0.1"] == "bob"


def test_set_assignment_empty_tester_removes(st):
    set_assignment(st, "10.0.0.1", "alice")
    result = set_assignment(st, "10.0.0.1", "")
    assert "10.0.0.1" not in result
    assert get_assignments(st) == {}


def test_multiple_assignments(st):
    set_assignment(st, "10.0.0.1", "alice")
    set_assignment(st, "10.0.0.2", "bob")
    a = get_assignments(st)
    assert a == {"10.0.0.1": "alice", "10.0.0.2": "bob"}


# --- labels -------------------------------------------------------------------

def test_labels_empty_by_default(st):
    assert get_labels(st) == {}


def test_set_label_on(st):
    result = set_label(st, "10.0.0.1", "interesting", True)
    assert result == {"10.0.0.1": ["interesting"]}
    assert get_labels(st) == {"10.0.0.1": ["interesting"]}


def test_set_label_multiple_sorted(st):
    set_label(st, "10.0.0.1", "out-of-scope", True)
    set_label(st, "10.0.0.1", "interesting", True)
    labels = get_labels(st)["10.0.0.1"]
    assert labels == ["interesting", "out-of-scope"]


def test_set_label_off_removes(st):
    set_label(st, "10.0.0.1", "interesting", True)
    set_label(st, "10.0.0.1", "needs-review", True)
    set_label(st, "10.0.0.1", "interesting", False)
    assert get_labels(st) == {"10.0.0.1": ["needs-review"]}


def test_set_label_off_last_removes_ip_key(st):
    set_label(st, "10.0.0.1", "interesting", True)
    set_label(st, "10.0.0.1", "interesting", False)
    assert get_labels(st) == {}


# --- port status --------------------------------------------------------------

def test_port_status_empty_by_default(st):
    assert get_port_status(st) == {}


def test_set_port_status_valid(st):
    for status in ("todo", "wip", "done"):
        set_port_status(st, "10.0.0.1", 445, status)
        assert get_port_status(st)["10.0.0.1:445"] == status


def test_set_port_status_empty_clears(st):
    set_port_status(st, "10.0.0.1", 445, "wip")
    set_port_status(st, "10.0.0.1", 445, "")
    assert "10.0.0.1:445" not in get_port_status(st)


def test_set_port_status_unknown_clears(st):
    set_port_status(st, "10.0.0.1", 80, "done")
    set_port_status(st, "10.0.0.1", 80, "bogus")
    assert "10.0.0.1:80" not in get_port_status(st)


# --- dismissed ----------------------------------------------------------------

def test_dismissed_empty_by_default(st):
    assert get_dismissed(st) == {}


def test_set_dismissed_on(st):
    result = set_dismissed(st, "vuln:10.0.0.1:445:ms17", "alice", True)
    assert result == {"vuln:10.0.0.1:445:ms17": "alice"}


def test_set_dismissed_off(st):
    set_dismissed(st, "vuln:10.0.0.1:445:ms17", "alice", True)
    result = set_dismissed(st, "vuln:10.0.0.1:445:ms17", "alice", False)
    assert result == {}
    assert get_dismissed(st) == {}


# --- activity -----------------------------------------------------------------

def test_add_activity_returns_entry(st):
    entry = add_activity(st, "alice", "assign", "alice claimed 10.0.0.1")
    assert entry["tester"] == "alice"
    assert entry["kind"] == "assign"
    assert entry["text"] == "alice claimed 10.0.0.1"
    assert "ts" in entry


def test_add_activity_empty_tester_defaults(st):
    entry = add_activity(st, "", "test", "something")
    assert entry["tester"] == "someone"


def test_get_activity_newest_first(st):
    add_activity(st, "alice", "a", "first")
    add_activity(st, "bob", "b", "second")
    items = get_activity(st)
    assert items[0]["text"] == "second"
    assert items[1]["text"] == "first"


def test_get_activity_limit(st):
    for i in range(10):
        add_activity(st, "alice", "x", f"entry {i}")
    assert len(get_activity(st, limit=3)) == 3


# --- chat ---------------------------------------------------------------------

def test_add_chat_returns_message(st):
    msg = add_chat(st, "alice", "hello team")
    assert msg["tester"] == "alice"
    assert msg["text"] == "hello team"
    assert msg["image"] == ""
    assert msg["file"] is None
    assert len(msg["id"]) == 12
    assert "ts" in msg


def test_add_chat_with_image(st):
    msg = add_chat(st, "bob", "screenshot", image="20260101-abc123.png")
    assert msg["image"] == "20260101-abc123.png"


def test_add_chat_with_file(st):
    f = {"stored": "20260101-def456.zip", "name": "loot.zip", "size": 1024}
    msg = add_chat(st, "carol", "here's the loot", file=f)
    assert msg["file"] == f


def test_add_chat_unique_ids(st):
    ids = {add_chat(st, "x", f"msg {i}")["id"] for i in range(20)}
    assert len(ids) == 20


def test_get_chat_oldest_first(st):
    add_chat(st, "alice", "first")
    add_chat(st, "bob", "second")
    msgs = get_chat(st)
    assert msgs[0]["text"] == "first"
    assert msgs[1]["text"] == "second"


def test_get_chat_limit(st):
    for i in range(10):
        add_chat(st, "alice", f"msg {i}")
    assert len(get_chat(st, limit=3)) == 3


# --- image_ext ----------------------------------------------------------------

def test_image_ext_png():
    assert image_ext(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100) == "png"


def test_image_ext_jpeg():
    assert image_ext(b"\xff\xd8\xff\xe0" + b"\x00" * 100) == "jpg"


def test_image_ext_gif87a():
    assert image_ext(b"GIF87a" + b"\x00" * 100) == "gif"


def test_image_ext_gif89a():
    assert image_ext(b"GIF89a" + b"\x00" * 100) == "gif"


def test_image_ext_webp():
    assert image_ext(b"RIFF\x00\x00\x00\x00WEBP" + b"\x00" * 100) == "webp"


def test_image_ext_unknown():
    assert image_ext(b"PK\x03\x04" + b"\x00" * 100) == ""
    assert image_ext(b"\x00" * 10) == ""


# --- Presence -----------------------------------------------------------------

def test_presence_empty_roster():
    p = Presence()
    assert p.roster() == []


def test_presence_ping_and_roster():
    p = Presence(ttl=10.0)
    p.ping("alice")
    p.ping("bob")
    assert p.roster() == ["alice", "bob"]


def test_presence_sorted():
    p = Presence(ttl=10.0)
    p.ping("charlie")
    p.ping("alice")
    p.ping("bob")
    assert p.roster() == ["alice", "bob", "charlie"]


def test_presence_ttl_expiry():
    p = Presence(ttl=0.1)
    p.ping("alice")
    time.sleep(0.2)
    assert p.roster() == []


def test_presence_ping_empty_ignored():
    p = Presence(ttl=10.0)
    p.ping("")
    assert p.roster() == []


def test_presence_refresh_extends_ttl():
    p = Presence(ttl=0.15)
    p.ping("alice")
    time.sleep(0.1)
    p.ping("alice")
    time.sleep(0.1)
    assert p.roster() == ["alice"]
