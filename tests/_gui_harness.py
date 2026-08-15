"""Test harness for the opt-in headless GUI walk (RECCE_GUI_IT=1).

Serves the real recce web app in a background thread and drives the real SPA in
Firefox over the Marionette protocol (Chromium is blocked in this environment; Firefox
on TCP 2828 is the supported driver). Kept out of the always-on suite - it needs a
browser and is inherently heavier - but it's the click-through that catches a dead tab
or an unwired view.
"""
from __future__ import annotations

import contextlib
import json
import socket
import subprocess
import tempfile
import threading
import time


# --------------------------- serve the app in-process ----------------------------

@contextlib.contextmanager
def serve_app(eng_dir: str):
    import uvicorn
    from recce.webui.app import create_app

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    config = uvicorn.Config(create_app(eng_dir), host="127.0.0.1", port=port,
                            log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        for _ in range(100):                       # wait for bind
            if server.started:
                break
            time.sleep(0.1)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)


# ------------------------------- Marionette driver -------------------------------

class _Marionette:
    def __init__(self, sock):
        self.s = sock
        self._id = 0
        self._read()                               # consume the server "hello" frame
        self._cmd("WebDriver:NewSession", {})

    def _read(self):
        # frames are "<len>:<json>"
        length = b""
        while not length.endswith(b":"):
            ch = self.s.recv(1)
            if not ch:
                raise RuntimeError("marionette closed")
            length += ch
        n = int(length[:-1])
        buf = b""
        while len(buf) < n:
            chunk = self.s.recv(n - len(buf))
            if not chunk:
                raise RuntimeError("marionette closed mid-frame")
            buf += chunk
        return json.loads(buf)

    def _cmd(self, method, params=None):
        self._id += 1
        payload = json.dumps([0, self._id, method, params or {}]).encode()
        self.s.sendall(f"{len(payload)}:".encode() + payload)
        resp = self._read()                        # [1, id, error, result]
        if isinstance(resp, list) and len(resp) >= 4 and resp[2]:
            raise RuntimeError(f"{method} error: {resp[2]}")
        return resp[3] if isinstance(resp, list) and len(resp) >= 4 else None

    def navigate(self, url):
        self._cmd("WebDriver:Navigate", {"url": url})
        # start collecting any runtime errors for console_errors()
        self.execute("window.__err=[];addEventListener('error',e=>__err.push(''+e.message));"
                     "addEventListener('unhandledrejection',e=>__err.push(''+e.reason));")

    def execute(self, script, args=None):
        r = self._cmd("WebDriver:ExecuteScript",
                      {"script": "return (function(){" + script + "})()", "args": args or []})
        return r.get("value") if isinstance(r, dict) else r

    def body_text(self):
        return self.execute("return document.body ? document.body.innerText : ''") or ""

    def wait_text(self, text, timeout=10.0):
        end = time.time() + timeout
        while time.time() < end:
            if text in self.body_text():
                return True
            time.sleep(0.2)
        return False

    def click_button(self, label):
        clicked = self.execute(
            "var b=[].slice.call(document.querySelectorAll('button'))"
            ".find(x=>x.textContent.trim()===arguments0);"
            "if(b){b.click();return true}return false".replace("arguments0", json.dumps(label)))
        time.sleep(0.4)
        return bool(clicked)

    def console_errors(self):
        return self.execute("return window.__err||[]") or []

    def close(self):
        with contextlib.suppress(Exception):
            self._cmd("Marionette:Quit", {})
        with contextlib.suppress(Exception):
            self.s.close()


@contextlib.contextmanager
def firefox_session():
    import shutil
    binary = shutil.which("firefox") or shutil.which("firefox-esr")
    profile = tempfile.mkdtemp()
    with open(f"{profile}/user.js", "w") as fh:
        fh.write('user_pref("marionette.port", 2828);\n')
    proc = subprocess.Popen(
        [binary, "--headless", "--marionette", "--no-remote", "--new-instance",
         "--profile", profile, "about:blank"],
        env={"MOZ_HEADLESS": "1", "PATH": "/usr/bin:/bin", "HOME": profile},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    sock = None
    try:
        for _ in range(100):                       # wait for marionette to listen
            try:
                sock = socket.create_connection(("127.0.0.1", 2828), timeout=1)
                break
            except OSError:
                time.sleep(0.2)
        if sock is None:
            raise RuntimeError("firefox marionette did not come up on :2828")
        sock.settimeout(20)
        driver = _Marionette(sock)
        yield driver
    finally:
        with contextlib.suppress(Exception):
            driver.close()  # type: ignore[possibly-undefined]
        proc.terminate()
        with contextlib.suppress(Exception):
            proc.wait(timeout=5)
        __import__("shutil").rmtree(profile, ignore_errors=True)
