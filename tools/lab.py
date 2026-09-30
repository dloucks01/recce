#!/usr/bin/env python3
"""Zero-install test lab — stdlib-only, no docker.

Stands up a handful of real-enough services on localhost so recce's discovery,
version detection, web posture checks, and a couple of service modules have
something live to run against, with nothing to install — a quick dev loop:

    python3 tools/lab.py                 # bind high ports (unprivileged)
    python3 tools/lab.py --standard      # canonical ports (21/22/80/…) — needs sudo
    # then, in another shell:
    python3 -m recce enum 127.0.0.1 -o /tmp/lab -Pn --all-ports
    python3 -m recce serve -o /tmp/lab --port 8008

Multi-host mode uses the loopback range (every 127.x.x.x is localhost on Linux)
to stand up several role-differentiated hosts so recce's cross-host attack-path
synthesis and lateral-movement summary have a real multi-host estate to chain:

    sudo python3 tools/lab.py --hosts 4 --standard   # 127.0.0.2-.5, canonical ports
    python3 -m recce enum 127.0.0.2-5 -o /tmp/lab -Pn --all-ports

(--standard is recommended with --hosts: recce's lateral-movement summary keys on
canonical ports — SSH 22, SMB 445, RDP 3389 — so high ports won't chain.)

Everything here is intentionally exposed/weakly-configured for TESTING on
localhost only — never expose it on a real network. Ctrl-C to stop.
"""
from __future__ import annotations

import argparse
import socket
import threading
import time

# (name, high-port, standard-port, handler-name)
SERVICES = [
    ("http", 8081, 80, "http"),
    ("ftp", 2121, 21, "ftp"),
    ("ssh", 2222, 22, "ssh"),
    ("smtp", 2525, 25, "smtp"),
    ("redis", 6380, 6379, "redis"),
    ("telnet", 2323, 23, "telnet"),
    ("vnc", 5901, 5900, "vnc"),
]
_SVC_BY_NAME = {s[0]: s for s in SERVICES}

# Multi-host estate (--hosts): each loopback IP 127.0.0.2, .3, … gets one role so
# recce discovers a differentiated network and can chain a cross-host attack path:
# foothold (vsftpd backdoor / web) -> credential access (.env DB creds) -> lateral
# movement (SSH across the estate) -> the DB/infra hosts the creds point at.
PROFILES = [
    ("web01", ["http", "ftp", "ssh"]),      # foothold + leaks .env DB creds -> db01
    ("db01", ["redis", "ssh"]),             # unauth redis; the creds' target, SSH-reachable
    ("app01", ["http", "smtp", "ssh"]),     # more web surface + SMTP open relay
    ("infra01", ["ssh", "telnet", "vnc"]),  # jump/infra host, extra lateral surface
]

_stop = threading.Event()


def _serve(host: str, port: int, handler, name: str) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
    except OSError as e:
        print(f"  [!] {name}: cannot bind {host}:{port} ({e}) — skipped")
        return
    srv.listen(16)
    srv.settimeout(0.5)
    print(f"  [+] {name:7s} on {host}:{port}")
    while not _stop.is_set():
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=_client, args=(conn, handler), daemon=True).start()
    srv.close()


def _client(conn: socket.socket, handler) -> None:
    conn.settimeout(5.0)
    try:
        handler(conn)
    except (OSError, ConnectionError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


# --- per-service handlers (just enough protocol to be identified/enumerated) ---

def _recv(conn, n=4096) -> bytes:
    try:
        return conn.recv(n)
    except (OSError, socket.timeout):
        return b""


def _http_reply(conn, status: str, body: bytes, ctype: str = "text/html") -> None:
    # Deliberately missing security headers (recce's web posture check flags these)
    # and a dated Server banner (version detection + CVE-lead territory).
    conn.sendall(
        b"HTTP/1.1 " + status.encode() + b"\r\n"
        b"Server: Apache/2.4.49 (Unix)\r\n"
        b"Content-Type: " + ctype.encode() + b"\r\n"
        b"X-Powered-By: PHP/5.6.40\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)


_DEFAULT_ENV = (b"DB_HOST=10.0.0.20\nDB_USER=appuser\nDB_PASS=Summer2024!\n"
                b"SECRET_KEY=devkey-do-not-ship\n")


_GIT_CONFIG = (b"[core]\n\trepositoryformatversion = 0\n"
               b"[remote \"origin\"]\n\turl = https://git.lab.local/internal/app.git\n")
_ROBOTS = b"User-agent: *\nDisallow: /admin\nDisallow: /backup\n"
_APP_HTML = (b"<!doctype html><title>Lab App</title><h1>Internal Tool</h1>"
             b'<form method=post action=/login>user <input name=u> '
             b'pass <input type=password name=p><button>sign in</button></form>'
             b"<!-- TODO: remove /.git and /.env before prod -->")


def h_http(conn, env_body: bytes = _DEFAULT_ENV) -> None:
    req = _recv(conn)
    path = b"/"
    line = req.split(b"\r\n", 1)[0].split(b" ")
    if len(line) >= 2:
        path = line[1].split(b"?", 1)[0]     # drop query string for exact matching
    # A CURATED set of genuinely-exposed artifacts (exact match). Real servers 404
    # made-up backup variants; matching every /.env* prefix made recce flag ~48
    # near-identical "exposed" findings and never exercised its 404/canary path.
    exposed = {
        b"/.git/config": (_GIT_CONFIG, "text/plain"),
        b"/.env": (env_body, "text/plain"),
        b"/.env.bak": (env_body, "text/plain"),          # one realistic backup leak
        b"/.env.production": (env_body, "text/plain"),
        b"/robots.txt": (_ROBOTS, "text/plain"),
    }
    if path in exposed:
        body, ctype = exposed[path]
        _http_reply(conn, "200 OK", body, ctype)
    elif path in (b"/", b"/index.html", b"/login"):
        _http_reply(conn, "200 OK", _APP_HTML)
    else:
        _http_reply(conn, "404 Not Found", b"<h1>404 Not Found</h1>")


def h_vnc(conn) -> None:
    # RFB protocol version banner — enough for nmap -sV to identify VNC.
    conn.sendall(b"RFB 003.008\n")
    _recv(conn)


def h_ftp(conn) -> None:
    conn.sendall(b"220 (vsFTPd 2.3.4)\r\n")     # a famously-backdoored version string
    while True:
        data = _recv(conn)
        if not data:
            return
        cmd = data.strip().upper()
        if cmd.startswith(b"USER"):
            conn.sendall(b"331 Please specify the password.\r\n")
        elif cmd.startswith(b"PASS"):
            conn.sendall(b"230 Login successful.\r\n")   # anonymous/weak login allowed
        elif cmd.startswith(b"SYST"):
            conn.sendall(b"215 UNIX Type: L8\r\n")
        elif cmd.startswith(b"QUIT"):
            conn.sendall(b"221 Goodbye.\r\n")
            return
        else:
            conn.sendall(b"200 OK\r\n")


def h_ssh(conn) -> None:
    conn.sendall(b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.1\r\n")
    _recv(conn)   # read the client's banner, then let the handshake fail (banner is enough for -sV)


def h_smtp(conn) -> None:
    conn.sendall(b"220 lab.local ESMTP Postfix (Ubuntu)\r\n")
    while True:
        data = _recv(conn)
        if not data:
            return
        cmd = data.strip().upper()
        if cmd.startswith((b"EHLO", b"HELO")):
            conn.sendall(b"250-lab.local\r\n250-STARTTLS\r\n250 HELP\r\n")
        elif cmd.startswith(b"QUIT"):
            conn.sendall(b"221 Bye\r\n")
            return
        else:
            conn.sendall(b"250 OK\r\n")


def h_redis(conn) -> None:
    # No AUTH required — recce flags an unauthenticated Redis. Answer a couple of
    # RESP commands so version detection + the redis module have something real.
    while True:
        data = _recv(conn)
        if not data:
            return
        up = data.upper()
        if b"PING" in up:
            conn.sendall(b"+PONG\r\n")
        elif b"INFO" in up:
            info = ("# Server\r\nredis_version:5.0.7\r\nos:Linux\r\n"
                    "# Clients\r\nconnected_clients:1\r\n")
            conn.sendall(b"$" + str(len(info)).encode() + b"\r\n" + info.encode() + b"\r\n")
        elif b"COMMAND" in up:
            conn.sendall(b"*0\r\n")
        else:
            conn.sendall(b"+OK\r\n")


def h_telnet(conn) -> None:
    conn.sendall(b"\r\nUbuntu 16.04.6 LTS\r\nlab login: ")
    _recv(conn)
    conn.sendall(b"Password: ")
    _recv(conn)
    conn.sendall(b"\r\nLogin incorrect\r\nlab login: ")


HANDLERS = {"http": h_http, "ftp": h_ftp, "ssh": h_ssh,
            "smtp": h_smtp, "redis": h_redis, "telnet": h_telnet, "vnc": h_vnc}


def _handler_for(name: str, ip: str, db_ip: str):
    """The handler for a service on a given host. web01's /.env leaks DB creds that
    point at the db host, so recce can chain credential-access -> lateral movement."""
    import functools
    if name == "http":
        env = (f"DB_HOST={db_ip}\nDB_USER=appuser\nDB_PASS=Summer2024!\n"
               f"REDIS_URL=redis://{db_ip}:6379/0\nSECRET_KEY=devkey-do-not-ship\n").encode()
        return functools.partial(h_http, env_body=env)
    return HANDLERS[name]


def _plan_hosts(args) -> list[tuple[str, str, list]]:
    """Return [(ip, role, [(svc, port, handler), ...]), ...] to stand up."""
    def port_of(svc):
        s = _SVC_BY_NAME[svc]
        return s[2] if args.standard else s[1]

    if args.hosts <= 1:
        # legacy single-host behaviour on --host, honouring --only.
        svcs = [s[0] for s in SERVICES if not args.only or s[0] in args.only]
        db_ip = args.host
        return [(args.host, "lab",
                 [(n, port_of(n), _handler_for(n, args.host, db_ip)) for n in svcs])]

    # multi-host: role profiles across 127.0.0.2 .. 127.0.0.(hosts+1).
    ips = [f"127.0.0.{i + 2}" for i in range(args.hosts)]
    # the db host is whichever profile is db01 (fallback: the 2nd host).
    db_ip = next((ips[i] for i, (r, _) in
                  enumerate(PROFILES[:len(ips)]) if r == "db01"),
                 ips[1] if len(ips) > 1 else ips[0])
    plan = []
    for i, ip in enumerate(ips):
        role, svcs = PROFILES[i % len(PROFILES)]
        if args.only:
            svcs = [s for s in svcs if s in args.only]
        plan.append((ip, role,
                     [(n, port_of(n), _handler_for(n, ip, db_ip)) for n in svcs]))
    return plan


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1",
                    help="bind address for single-host mode (default 127.0.0.1)")
    ap.add_argument("--hosts", type=int, default=1, metavar="N",
                    help="stand up N role-differentiated hosts on 127.0.0.2.. "
                         "(multi-host estate for attack-path/lateral testing). "
                         "Pair with --standard; binding <1024 needs sudo.")
    ap.add_argument("--standard", action="store_true",
                    help="use canonical ports (80/21/22/25/6379/23) — needs sudo")
    ap.add_argument("--only", nargs="*", metavar="SVC",
                    help="only these services (default: all)")
    ap.add_argument("--scan", action="store_true",
                    help="one-shot harness: start the lab, run `recce enum` against it, "
                         "print what was found, then stop")
    args = ap.parse_args()

    plan = _plan_hosts(args)
    if not any(svcs for _ip, _role, svcs in plan):
        print("[x] no matching services; choose from: "
              + ", ".join(s[0] for s in SERVICES))
        return 1

    mode = "standard" if args.standard else "high"
    n_hosts = len(plan)
    print(f"recce zero-install lab — {n_hosts} host(s), {mode} ports. Ctrl-C to stop.\n")
    for ip, role, svcs in plan:
        print(f"  {role} @ {ip}:")
        for name, port, handler in svcs:
            t = threading.Thread(target=_serve, args=(ip, port, handler, name),
                                 daemon=True)
            t.start()
            time.sleep(0.02)

    # scan target + port list covering the whole estate.
    all_ports = sorted({p for _ip, _role, svcs in plan for _n, p, _h in svcs})
    ports = ",".join(str(p) for p in all_ports)
    if n_hosts == 1:
        target = plan[0][0]
    else:
        lo = plan[0][0]
        hi = plan[-1][0].rsplit(".", 1)[1]
        target = f"{lo}-{hi}"          # e.g. 127.0.0.2-5 (nmap range syntax)

    if args.scan:
        import subprocess
        import sys
        import tempfile
        out_dir = tempfile.mkdtemp(prefix="recce-lab-")
        time.sleep(0.5)
        print(f"\n[*] scanning the lab ({target}) -> {out_dir}\n")
        rc = subprocess.run(
            [sys.executable, "-m", "recce", "enum", target, "-Pn", "-p", ports,
             "-o", out_dir, "--profile", "quick"],
            cwd=__file__.rsplit("/tools/", 1)[0]).returncode
        _stop.set()
        print(f"\n[+] lab scan done (rc={rc}); engagement at {out_dir}")
        print(f"    attack path:  python3 -m recce attackpath -o {out_dir}")
        print(f"    open it:      python3 -m recce serve -o {out_dir} --port 8008")
        return rc

    print(f"\n  scan it:  python3 -m recce enum {target} -o /tmp/lab -Pn "
          f"-p {ports} --all-ports\n"
          f"  then:     python3 -m recce attackpath -o /tmp/lab   # cross-host chain\n"
          "  (for TESTING on localhost only — never point this lab at a real network)\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] stopping lab…")
        _stop.set()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
