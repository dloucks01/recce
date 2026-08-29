"""vSphere Web Services SDK probe (vCenter / ESXi, /sdk on 443).

Stdlib-only SOAP client for the vSphere API. The SDK answers a fixed
`RetrieveServiceContent` envelope with an `AboutInfo` block that identifies
the appliance (vCenter vs ESXi), its version and its exact build number —
the ground-truth fingerprint the CVE mapper keys on.

Credentialed flows (SessionManager.Login, HostSystem / VirtualMachine
inventory, SessionList, HostLocalAccountManager, HostDatastoreBrowser)
run only when the operator supplied credentials. Nothing here writes,
execs into a guest, or continues an exploit — findings surface the
capability and a copy-paste command so the operator drives the intrusive
step under ROE.

Air-gap safe: stdlib only. Every socket op has a bounded timeout
scaled through `proxy.scaled()`.
"""
from __future__ import annotations

import http.client
import re
import socket
import ssl
from xml.etree import ElementTree as ET

from ..core import proxy
from ..core.models import Host, Port
from .svccommon import finding_builder


_TIMEOUT = 6.0
_UA = "recce-vsphere/1.0"
_SDK_PATH = "/sdk"

_SDK_PORTS = (443, 5480, 9443)
_HOSTD_AGENT = 902
_VAMI = 5480


_NS = {
    "soap": "http://schemas.xmlsoap.org/soap/envelope/",
    "vim":  "urn:vim25",
}


# --- SOAP envelopes -------------------------------------------------------------

def _envelope(body: str) -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
        ' xmlns:xsd="http://www.w3.org/2001/XMLSchema"'
        ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        '<soapenv:Body>' + body + '</soapenv:Body></soapenv:Envelope>'
    ).encode("utf-8")


_RETRIEVE_SERVICE_CONTENT = _envelope(
    '<RetrieveServiceContent xmlns="urn:vim25">'
    '<_this type="ServiceInstance">ServiceInstance</_this>'
    '</RetrieveServiceContent>')


def _login_envelope(user: str, password: str) -> bytes:
    u = _xml_escape(user)
    p = _xml_escape(password)
    return _envelope(
        '<Login xmlns="urn:vim25">'
        '<_this type="SessionManager">SessionManager</_this>'
        f'<userName>{u}</userName>'
        f'<password>{p}</password>'
        '</Login>')


def _session_list_envelope() -> bytes:
    return _envelope(
        '<SessionList xmlns="urn:vim25">'
        '<_this type="SessionManager">SessionManager</_this>'
        '</SessionList>')


def _retrieve_properties_ex_envelope(propset: str, root_type: str,
                                     root_value: str) -> bytes:
    # A minimal RetrievePropertiesEx: one selection set with the given root and
    # the caller's property paths. The property collector is always accessible
    # through the fixed name 'propertyCollector' returned by ServiceContent.
    return _envelope(
        '<RetrievePropertiesEx xmlns="urn:vim25">'
        '<_this type="PropertyCollector">propertyCollector</_this>'
        '<specSet>'
        '<propSet>'
        f'<type>{root_type}</type>'
        '<all>false</all>'
        + propset +
        '</propSet>'
        '<objectSet>'
        f'<obj type="{root_type}">{root_value}</obj>'
        '<skip>false</skip>'
        '</objectSet>'
        '</specSet>'
        '<options/>'
        '</RetrievePropertiesEx>')


_HOST_LOCAL_ACCOUNTS = _envelope(
    '<RetrieveUserGroups xmlns="urn:vim25">'
    '<_this type="HostLocalAccountManager">ha-localacctmgr</_this>'
    '<searchStr></searchStr>'
    '<exactMatch>false</exactMatch>'
    '<findUsers>true</findUsers>'
    '<findGroups>false</findGroups>'
    '</RetrieveUserGroups>')


def _xml_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;")
             .replace("'", "&apos;"))


# --- transport ------------------------------------------------------------------

def is_vsphere(port: Port) -> bool:
    if not port.is_open:
        return False
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    banner = (port.banner or "").lower()
    if port.portid in _SDK_PORTS:
        return True
    if port.portid == _HOSTD_AGENT:
        return True
    if any(k in svc or k in prod for k in
           ("vsphere", "vcenter", "vmware", "esxi", "esx")):
        return True
    if "vmware/" in banner or "vsphere" in banner or "id_vc_welcome" in banner:
        return True
    return False


def role(port: int) -> str:
    if port == _VAMI:
        return "vami"
    if port == _HOSTD_AGENT:
        return "hostd-agent"
    if port == 9443:
        return "vsphere-client"
    return "sdk"


def _tls_context() -> ssl.SSLContext:
    ctx = ssl._create_unverified_context()
    ctx.check_hostname = False
    return ctx


def _post_soap(ip: str, port: int, body: bytes, action: str = "",
               timeout: float = _TIMEOUT,
               cookie: str = "") -> tuple[int, bytes, str] | None:
    """POST a SOAP envelope to /sdk. Returns (status, body, set_cookie) or None.

    `cookie` re-plays a captured `vmware_soap_session` for authenticated calls.
    """
    conn = None
    try:
        conn = http.client.HTTPSConnection(
            ip, port, timeout=proxy.scaled(timeout), context=_tls_context())
        headers = {
            "Content-Type": 'text/xml; charset="utf-8"',
            "SOAPAction": action or '"urn:vim25/8.0.0.0"',
            "User-Agent": _UA,
            "Connection": "close",
            "Content-Length": str(len(body)),
        }
        if cookie:
            headers["Cookie"] = cookie
        conn.request("POST", _SDK_PATH, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read(2_000_000)
        set_cookie = resp.getheader("Set-Cookie") or ""
        return resp.status, raw, set_cookie
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


def _http_get(ip: str, port: int, path: str,
              timeout: float = _TIMEOUT) -> tuple[int, bytes, dict] | None:
    """Plain HTTPS GET (used for the /ui redirect fingerprint and cert grab)."""
    conn = None
    try:
        conn = http.client.HTTPSConnection(
            ip, port, timeout=proxy.scaled(timeout), context=_tls_context())
        conn.request("GET", path, headers={"User-Agent": _UA,
                                           "Connection": "close"})
        resp = conn.getresponse()
        raw = resp.read(200_000)
        hdrs = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, raw, hdrs
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


def _cert_san(ip: str, port: int, timeout: float = _TIMEOUT) -> dict:
    """Return {cn, sans[]} from the /sdk TLS cert. Empty dict on any failure."""
    out: dict = {"cn": "", "sans": []}
    ctx = _tls_context()
    try:
        with socket.create_connection((ip, port),
                                      timeout=proxy.scaled(timeout)) as raw:
            raw.settimeout(proxy.scaled(timeout))
            with ctx.wrap_socket(raw, server_hostname=ip) as tls:
                cert = tls.getpeercert()
    except (OSError, ssl.SSLError, ValueError):
        return out
    if not cert:
        return out
    for tup in cert.get("subject", ()):
        for k, v in tup:
            if k == "commonName":
                out["cn"] = v
    for k, v in cert.get("subjectAltName", ()):
        if k in ("DNS", "IP Address"):
            out["sans"].append(v)
    return out


# --- SOAP response parsing ------------------------------------------------------

_TAG_RE = re.compile(r"\{[^}]+\}")


def _local(tag: str) -> str:
    return _TAG_RE.sub("", tag)


def _findtext(elem, name: str) -> str:
    """Case-sensitive local-name search (namespace-agnostic)."""
    if elem is None:
        return ""
    for child in elem.iter():
        if _local(child.tag) == name and child.text:
            return child.text.strip()
    return ""


def _findall_local(elem, name: str) -> list:
    return [c for c in elem.iter() if _local(c.tag) == name]


def _parse_service_content(body: bytes) -> dict | None:
    """Extract the AboutInfo fields from a RetrieveServiceContent response."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return None
    about = None
    for c in root.iter():
        if _local(c.tag) == "about":
            about = c
            break
    if about is None:
        return None
    out = {
        "full_name":    _findtext(about, "fullName"),
        "name":         _findtext(about, "name"),
        "vendor":       _findtext(about, "vendor"),
        "version":      _findtext(about, "version"),
        "build":        _findtext(about, "build"),
        "api_type":     _findtext(about, "apiType"),
        "api_version":  _findtext(about, "apiVersion"),
        "instance_uuid": _findtext(about, "instanceUuid"),
        "os_type":      _findtext(about, "osType"),
        "license":      _findtext(about, "licenseProductName"),
    }
    return out


def _is_soap_fault(body: bytes) -> bool:
    return b"Fault" in body[:8192] and b"Envelope" in body[:8192]


def _fault_reason(body: bytes) -> str:
    m = re.search(br"<faultstring[^>]*>([^<]{0,300})</faultstring>", body)
    if m:
        return m.group(1).decode("utf-8", "replace").strip()
    m = re.search(br"<Text[^>]*>([^<]{0,300})</Text>", body)
    if m:
        return m.group(1).decode("utf-8", "replace").strip()
    return ""


def _parse_user_session(body: bytes) -> dict | None:
    """Parse a SessionManager.Login response for a UserSession."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return None
    for c in root.iter():
        if _local(c.tag) == "returnval":
            return {
                "key":            _findtext(c, "key"),
                "user_name":      _findtext(c, "userName"),
                "full_name":      _findtext(c, "fullName"),
                "login_time":     _findtext(c, "loginTime"),
                "last_active":    _findtext(c, "lastActiveTime"),
                "locale":         _findtext(c, "locale"),
                "extension_key":  _findtext(c, "extensionKey"),
            }
    return None


def _parse_session_list(body: bytes) -> list[dict]:
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return []
    out = []
    for rv in _findall_local(root, "returnval"):
        sess = {
            "key":         _findtext(rv, "key"),
            "user_name":   _findtext(rv, "userName"),
            "ip_address":  _findtext(rv, "ipAddress"),
            "user_agent":  _findtext(rv, "userAgent"),
            "login_time":  _findtext(rv, "loginTime"),
            "last_active": _findtext(rv, "lastActiveTime"),
            "call_count":  _findtext(rv, "callCount"),
        }
        if sess["user_name"] or sess["key"]:
            out.append(sess)
    return out


def _parse_local_accounts(body: bytes) -> list[dict]:
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return []
    out = []
    for rv in _findall_local(root, "returnval"):
        principal = _findtext(rv, "principal") or _findtext(rv, "id")
        full = _findtext(rv, "fullName") or _findtext(rv, "name")
        if principal:
            out.append({"principal": principal, "full_name": full})
    return out


def _parse_property_objects(body: bytes) -> list[dict]:
    """Parse RetrievePropertiesEx returnval. Yields {type, ref, props{name:value}}."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return []
    out = []
    for rv in _findall_local(root, "returnval"):
        for obj in _findall_local(rv, "objects"):
            ref_el = None
            for c in obj:
                if _local(c.tag) == "obj":
                    ref_el = c
                    break
            entry = {
                "type": ref_el.get("type") if ref_el is not None else "",
                "ref":  (ref_el.text or "").strip() if ref_el is not None else "",
                "props": {},
            }
            for ps in obj:
                if _local(ps.tag) != "propSet":
                    continue
                name = ""
                val = ""
                for pc in ps:
                    ln = _local(pc.tag)
                    if ln == "name":
                        name = (pc.text or "").strip()
                    elif ln == "val":
                        val = "".join(pc.itertext()).strip()
                if name:
                    entry["props"][name] = val
            out.append(entry)
    return out


# --- CVE / build mapping --------------------------------------------------------

# (api_type, version_prefix, patch_build, cve, title)
# Only entries with a known-good patch build are included; every match is by
# strict integer comparison (`build < patch_build`), so a build we can't parse
# (or one already at/past the patch) never triggers a CVE citation.
_BUILD_CVES: list[tuple[str, str, int, str, str]] = [
    # CVE-2021-21985 — vSphere Client vROps plugin pre-auth RCE (VMSA-2021-0010)
    ("VirtualCenter", "6.5", 17590285, "CVE-2021-21985",
     "vSphere Client vROps plugin pre-auth RCE"),
    ("VirtualCenter", "6.7", 17958471, "CVE-2021-21985",
     "vSphere Client vROps plugin pre-auth RCE"),
    ("VirtualCenter", "7.0", 17920168, "CVE-2021-21985",
     "vSphere Client vROps plugin pre-auth RCE"),
    # CVE-2021-22005 — file-upload analytics service (VMSA-2021-0020)
    ("VirtualCenter", "6.7", 18485185, "CVE-2021-22005",
     "vCenter analytics file-upload pre-auth RCE"),
    ("VirtualCenter", "7.0", 18356314, "CVE-2021-22005",
     "vCenter analytics file-upload pre-auth RCE"),
    # CVE-2023-34048 — DCE-RPC OOB write pre-auth RCE (VMSA-2023-0023)
    ("VirtualCenter", "7.0", 22357613, "CVE-2023-34048",
     "vCenter DCE-RPC out-of-bounds write pre-auth RCE"),
    ("VirtualCenter", "8.0", 22385739, "CVE-2023-34048",
     "vCenter DCE-RPC out-of-bounds write pre-auth RCE"),
    # CVE-2024-37085 — ESXi 'ESX Admins' AD auto-promote priv-esc
    # (VMSA-2024-0013). Fixed builds: 7.0 U3q = 23794027, 8.0 U2b = 23305546.
    ("HostAgent", "7.0", 23794027, "CVE-2024-37085",
     "ESXi 'ESX Admins' AD group auto-promote priv-esc"),
    ("HostAgent", "8.0", 23305546, "CVE-2024-37085",
     "ESXi 'ESX Admins' AD group auto-promote priv-esc"),
]


def build_cves(api_type: str, version: str, build: str) -> list[dict]:
    """Return the list of CVEs the given (api_type, version, build) is below.

    An unparseable build is treated as unknown — NO CVE is cited (the finding
    still fires as an outdated-build advisory keyed on CWE only).
    """
    try:
        b = int(build)
    except (TypeError, ValueError):
        return []
    hits = []
    for at, prefix, patch, cve, title in _BUILD_CVES:
        if at != api_type:
            continue
        if not version.startswith(prefix):
            continue
        if b < patch:
            hits.append({"cve": cve, "title": title, "patch_build": patch})
    return hits


# --- inventory property helpers -------------------------------------------------

_HOSTSYSTEM_PROPS = (
    "name",
    "config.product.build",
    "config.product.fullName",
    "config.network.dnsConfig.hostName",
    "config.network.dnsConfig.domainName",
    "runtime.connectionState",
    "summary.hardware.model",
    "summary.hardware.vendor",
    "summary.managementServerIp",
)

_VM_PROPS = (
    "name",
    "config.guestFullName",
    "config.uuid",
    "guest.hostName",
    "guest.ipAddress",
    "runtime.powerState",
    "snapshot",
)


def _propset(paths) -> str:
    return "".join(f"<pathSet>{p}</pathSet>" for p in paths)


# --- default credentials --------------------------------------------------------

_DEFAULT_SSO_USERS = (
    ("administrator@vsphere.local", "VMware1!"),
    ("administrator@vsphere.local", "vmware"),
    ("administrator@vsphere.local", ""),
)
_DEFAULT_ESXI_USERS = (
    ("root", "vmware"),
    ("root", ""),
    ("root", "password"),
    ("root", "VMware1!"),
)


def _cred_candidates(api_type: str, creds: dict | None) -> list[tuple[str, str]]:
    """Order: operator-supplied first, then vendor defaults for the api type."""
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(u, p):
        key = (u, p)
        if key in seen:
            return
        seen.add(key)
        out.append(key)

    if creds:
        for c in creds.get("vsphere") or ():
            u = c.get("username", "")
            p = c.get("password", "")
            if u:
                add(u, p)
    if api_type == "HostAgent":
        for u, p in _DEFAULT_ESXI_USERS:
            add(u, p)
    else:
        for u, p in _DEFAULT_SSO_USERS:
            add(u, p)
    return out


# --- probe ----------------------------------------------------------------------

def probe(ip: str, port: int = 443, timeout: float = _TIMEOUT,
          creds: dict | None = None, active_auth: bool = False) -> dict | None:
    """Fingerprint the /sdk endpoint, then optionally run credentialed flows.

    Returns None if the endpoint doesn't answer SOAP at all.
    """
    out: dict = {"ip": ip, "port": port, "role": role(port),
                 "reachable": False, "sdk": False}

    # /ui redirect + Server header — a cheap prefilter that names vSphere even
    # before we POST /sdk (matches the punchlist's detect-vsphere-sdk step).
    ui = _http_get(ip, port, "/", timeout=timeout)
    if ui is not None:
        out["reachable"] = True
        status, body, hdrs = ui
        srv = (hdrs.get("server") or "").lower()
        loc = (hdrs.get("location") or "")
        cookie = (hdrs.get("set-cookie") or "")
        body_head = body[:8192].decode("latin-1", "replace")
        out["ui_server"] = hdrs.get("server", "")
        out["ui_location"] = loc
        out["ui_signals"] = {
            "vmware_server": "vmware/" in srv,
            "ui_redirect": "/ui" in loc or "/vsphere-client" in loc,
            "vmware_cookie": "vmware_client" in cookie.lower(),
            "id_vc_welcome": "ID_VC_Welcome" in body_head,
            "id_eesx_welcome": "ID_EESX_Welcome" in body_head,
        }

    # RetrieveServiceContent — the ground-truth fingerprint.
    sc = _post_soap(ip, port, _RETRIEVE_SERVICE_CONTENT, timeout=timeout)
    if sc is None:
        return out if out["reachable"] else None
    status, body, _cookie = sc
    if status != 200 or _is_soap_fault(body):
        # Some appliances answer /sdk with a Server: VMware/* on the 500 body
        # too — surface reachability but no sdk fingerprint.
        return out if out["reachable"] else None

    parsed = _parse_service_content(body)
    if not parsed:
        return out if out["reachable"] else None

    out["reachable"] = True
    out["sdk"] = True
    out.update(parsed)
    out["cves"] = build_cves(parsed.get("api_type", ""), parsed.get("version", ""),
                             parsed.get("build", ""))

    # Cert / SSO-domain extraction — passive, cheap, always run.
    cert = _cert_san(ip, port, timeout=timeout)
    out["cert"] = cert
    sso = _extract_sso_domain(parsed, cert)
    if sso:
        out["sso_domain"] = sso

    if not active_auth:
        return out

    # SessionManager.Login sweep. Follow-on inventory / SessionList calls fire
    # ONLY on a successful login — a failed sweep must never look like the API
    # answered inventory.
    api_type = parsed.get("api_type", "")
    candidates = _cred_candidates(api_type, creds)
    login = _try_logins(ip, port, candidates, timeout=timeout)
    out["login"] = login
    if login.get("success"):
        cookie = login.get("cookie", "")
        sl = _post_soap(ip, port, _session_list_envelope(), timeout=timeout,
                        cookie=cookie)
        if sl and sl[0] == 200:
            out["sessions"] = _parse_session_list(sl[1])
        if api_type == "VirtualCenter":
            hosts = _fetch_hostsystems(ip, port, cookie, timeout)
            if hosts is not None:
                out["managed_hosts"] = hosts
            vms = _fetch_vms(ip, port, cookie, timeout)
            if vms is not None:
                out["managed_vms"] = vms
            out["linked_vcenters"] = _linked_vcenters(hosts or [])
        elif api_type == "HostAgent":
            locals_ = _post_soap(ip, port, _HOST_LOCAL_ACCOUNTS, timeout=timeout,
                                 cookie=cookie)
            if locals_ and locals_[0] == 200:
                out["local_users"] = _parse_local_accounts(locals_[1])
    return out


def _try_logins(ip: str, port: int, candidates: list[tuple[str, str]],
                timeout: float) -> dict:
    """Try each (user, pass) once. Stop on first success. Returns login state."""
    tried: list[str] = []
    for user, password in candidates:
        r = _post_soap(ip, port, _login_envelope(user, password), timeout=timeout)
        if r is None:
            tried.append(f"{user}:network-error")
            continue
        status, body, set_cookie = r
        if status == 200 and not _is_soap_fault(body):
            session = _parse_user_session(body)
            cookie = ""
            if set_cookie:
                # `vmware_soap_session=...; Path=/; ...` — keep only the name=val.
                cookie = set_cookie.split(";", 1)[0].strip()
            return {"success": True, "user": user, "cookie": cookie,
                    "session": session or {}, "attempts": len(tried) + 1}
        tried.append(f"{user}:{(_fault_reason(body) or 'refused')[:80]}")
    return {"success": False, "attempts": len(candidates), "log": tried}


def _fetch_hostsystems(ip: str, port: int, cookie: str,
                       timeout: float) -> list[dict] | None:
    # Traversing the whole inventory tree from ServiceContent.rootFolder needs a
    # SelectionSet chain; instead we ask the property collector for HostSystem
    # container-view style properties by walking from the well-known root.
    env = _retrieve_properties_ex_envelope(
        _propset(_HOSTSYSTEM_PROPS), "HostSystem", "ha-host")
    r = _post_soap(ip, port, env, timeout=timeout, cookie=cookie)
    if not r or r[0] != 200 or _is_soap_fault(r[1]):
        return None
    return _parse_property_objects(r[1])


def _fetch_vms(ip: str, port: int, cookie: str,
               timeout: float) -> list[dict] | None:
    env = _retrieve_properties_ex_envelope(
        _propset(_VM_PROPS), "VirtualMachine", "ha-vm")
    r = _post_soap(ip, port, env, timeout=timeout, cookie=cookie)
    if not r or r[0] != 200 or _is_soap_fault(r[1]):
        return None
    return _parse_property_objects(r[1])


def _linked_vcenters(hosts: list[dict]) -> list[str]:
    seen: set[str] = set()
    for h in hosts:
        ms = (h.get("props") or {}).get("summary.managementServerIp") or ""
        ms = ms.strip()
        if ms:
            seen.add(ms)
    return sorted(seen)


def _stale_snapshot_vms(vms: list[dict]) -> list[str]:
    """Names of powered-off VMs that hold at least one snapshot.

    Powered-off + snapshot present = revert candidate: rolling back the VM
    undoes any post-compromise credential rotation on the guest OS.
    """
    out: list[str] = []
    for vm in vms:
        props = vm.get("props") or {}
        if props.get("runtime.powerState") != "poweredOff":
            continue
        if not (props.get("snapshot") or "").strip():
            continue
        name = props.get("name", "") or vm.get("ref", "")
        if name:
            out.append(name)
    return out


def _extract_sso_domain(parsed: dict, cert: dict) -> str:
    """Extract the SSO / PSC domain from ServiceContent + cert.

    Order of preference: full name suffix ('@vsphere.local'), instanceUuid form
    (rare), and finally the cert CN suffix. Default vSphere is `vsphere.local`.
    """
    full = parsed.get("full_name") or ""
    m = re.search(r"@([a-zA-Z0-9.\-]+)", full)
    if m:
        return m.group(1).lower()
    cn = (cert.get("cn") or "").lower()
    if cn and "." in cn:
        # Take the last two labels as the domain (heuristic; the cert CN in a
        # default vCenter deployment is the appliance FQDN under the SSO domain).
        return ".".join(cn.rstrip(".").split(".")[-2:])
    return ""


# --- narratives + finding builder ----------------------------------------------

_NARRATIVE = {
    "vsphere_fingerprint": (
        "The vSphere Web Services SDK identifies the appliance (vCenter or "
        "ESXi), version and exact build. Build is the honest identifier — "
        "marketing versions cover 30+ builds with different patch states, "
        "so the CVE mapper keys on build."),
    "vsphere_outdated_build": (
        "A build below the vendor patch level for a documented pre-auth RCE. "
        "vCenter compromise is control of the whole virtual estate; ESXi "
        "compromise is hypervisor takeover of every VM on the host."),
    "vsphere_valid_creds": (
        "Valid SSO / ESXi credentials against vSphere. On ESXi this is direct "
        "host takeover; on vCenter it grants API-level control over every "
        "managed host and VM (start/stop, snapshot, reconfigure, guest exec)."),
    "vsphere_sessions": (
        "The active-session list names real operators (not guesses) and their "
        "client IPs — admin workstations worth their own scan."),
    "vsphere_inventory": (
        "One vCenter compromise multiplies into N hypervisor foothold targets; "
        "guest hostnames / IPs seed the rest of the engagement's target set."),
    "vsphere_sso_domain": (
        "Naming the SSO domain enables the administrator@vsphere.local login "
        "attempt and feeds LDAP/Kerberos flows that need the identity source."),
    "vsphere_local_users": (
        "Local ESXi accounts (root, dcui, ...) with API access — routinely "
        "blank or trivial in labs and small ops."),
    "vsphere_linked": (
        "Enhanced Linked Mode / PSC federation: the same SSO creds may work "
        "on the linked vCenter and one can push tokens to another."),
    "vsphere_cert": (
        "The /sdk machine cert SANs enumerate the appliance and (on ESXi) the "
        "host's short + FQDN forms — every SAN feeds known_hostnames."),
    "vsphere_vami": (
        "5480/tcp reachable on the same host — separate auth surface (root/"
        "vmware defaults still common), different CVE class than the SDK."),
    "vsphere_cve_2021_21985": (
        "vSphere Client vROps plugin pre-auth RCE. Recce detects the "
        "vulnerable build; the exploit is opt-in — the operator drives it."),
    "vsphere_cve_2024_37085": (
        "ESXi domain-joined hosts auto-promote members of the AD group "
        "'ESX Admins' to full admin. Widely used by Scattered Spider and "
        "similar ransomware crews to lateral into virtualisation. Patched "
        "builds require the group name to be explicitly configured."),
    "vsphere_stale_snapshot": (
        "Powered-off VMs with an existing snapshot are revert candidates — "
        "reverting bypasses any post-compromise password rotation, EDR "
        "install, or IR containment applied to the guest OS since the "
        "snapshot was taken. Domain controllers and jump hosts are the "
        "highest-value revert targets."),
}

_finding = finding_builder("vsphere", _NARRATIVE)


# --- targets --------------------------------------------------------------------

def vsphere_targets(hosts: list[Host]) -> list[dict]:
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_vsphere(p):
                out.append({"ip": h.ip, "hostname": h.hostname,
                            "port": p.portid, "role": role(p.portid),
                            "product": p.product or ""})
    return out


# --- findings -------------------------------------------------------------------

def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        vami_open = any(p.is_open and p.portid == _VAMI for p in h.ports)
        for p in h.open_ports:
            if not is_vsphere(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr:
                continue
            tgt = f"{h.ip}:{p.portid}"

            if pr.get("sdk"):
                api_type = pr.get("api_type", "")
                version = pr.get("version", "")
                build = pr.get("build", "")
                # Always emit an info-level fingerprint.
                out.append(_finding(
                    "info",
                    f"vSphere SDK reachable ({api_type or 'unknown'})", tgt,
                    f"{pr.get('full_name','vSphere SDK')} — apiType={api_type} "
                    f"version={version} build={build} "
                    f"instanceUuid={pr.get('instance_uuid','')}",
                    "curl",
                    f"curl -sk -X POST https://{h.ip}:{p.portid}/sdk "
                    f"-H 'SOAPAction:\"urn:vim25\"' "
                    "--data '<RetrieveServiceContent .../>'",
                    "Restrict management-plane access to a dedicated OOB "
                    "network; monitor /sdk for unexpected clients.",
                    ["CWE-200"], kind="vsphere_fingerprint"))

                cves = pr.get("cves") or []
                if cves:
                    ids = sorted({c["cve"] for c in cves})
                    titles = "; ".join(c["title"] for c in cves)
                    out.append(_finding(
                        "critical",
                        f"vSphere build {build} vulnerable to {', '.join(ids)}",
                        tgt,
                        f"apiType={api_type} version={version} build={build}. "
                        f"Documented pre-auth issues at this patch level: "
                        f"{titles}. Recce keys on the exact build number (not "
                        "the marketing version) so the citation is honest.",
                        "curl",
                        "# Confirm build: "
                        f"curl -sk https://{h.ip}:{p.portid}/sdk … about.build",
                        "Apply the current vCenter/ESXi patch level (see the "
                        "VMSA for the fixed build); restrict the management "
                        "plane to a dedicated network.",
                        ["CWE-306", "CWE-434", "CWE-502", "CWE-787"],
                        kind="vsphere_outdated_build"))
                    # A specific finding for 21985 so the exploit runbook is
                    # visible in its own row.
                    if any(c["cve"] == "CVE-2021-21985" for c in cves):
                        out.append(_finding(
                            "critical",
                            "vSphere Client pre-auth RCE CVE-2021-21985 candidate",
                            tgt,
                            f"Build {build} predates the VMSA-2021-0010 patch. "
                            "The vROps plugin exposes an unauthenticated "
                            "endpoint that deserialises attacker-supplied "
                            "input. Recce does NOT launch the payload — the "
                            "operator drives it under ROE.",
                            "manual",
                            "# https://github.com/… (opt-in exploit script; "
                            "writes files on the appliance)",
                            "Patch to the VMSA-2021-0010 fixed build; disable "
                            "the vROps plugin if unused.",
                            ["CWE-306", "CWE-502"],
                            kind="vsphere_cve_2021_21985"))
                    if any(c["cve"] == "CVE-2024-37085" for c in cves):
                        out.append(_finding(
                            "critical",
                            "ESXi CVE-2024-37085 candidate "
                            "('ESX Admins' AD auto-promote)",
                            tgt,
                            f"Build {build} predates the VMSA-2024-0013 "
                            "patch. If this ESXi is AD-joined, any AD group "
                            "named 'ESX Admins' is auto-granted full admin "
                            "on the host — used in the wild by Scattered "
                            "Spider et al. for hypervisor lateral movement.",
                            "manual",
                            "# If AD-joined: create AD group 'ESX Admins', "
                            "add attacker principal; SSH/UI as that "
                            "principal grants full ESXi admin.",
                            "Patch to the VMSA-2024-0013 fixed build; if "
                            "AD-joined, set Config.HostAgent.plugins.hostsvc"
                            ".esxAdminsGroup to an unused name and disable "
                            "the auto-add behaviour.",
                            ["CWE-284", "CWE-269"],
                            kind="vsphere_cve_2024_37085"))

                if pr.get("sso_domain"):
                    out.append(_finding(
                        "high", "vSphere SSO domain identified", tgt,
                        f"SSO / PSC domain: {pr['sso_domain']}. Enables the "
                        "administrator@<sso> login attempt and feeds LDAP / "
                        "Kerberos flows that need the identity-source domain.",
                        "curl", "# see fingerprint above",
                        "SSO domain is a design property, not a vuln — "
                        "surface it so the operator can attempt federated "
                        "logins with the appropriate UPN.",
                        ["CWE-200"], kind="vsphere_sso_domain"))

                cert = pr.get("cert") or {}
                if cert.get("cn") or cert.get("sans"):
                    sans = ", ".join(cert.get("sans", [])[:20])
                    out.append(_finding(
                        "medium",
                        "vSphere /sdk TLS cert hostnames enumerated", tgt,
                        f"CN={cert.get('cn','')}, SANs=[{sans}]. Feeds "
                        "known_hostnames for cross-service correlation "
                        "(cert-hostname mine).",
                        "openssl",
                        f"openssl s_client -connect {h.ip}:{p.portid} "
                        "-servername " + (cert.get("cn") or h.ip)
                        + " </dev/null 2>/dev/null | openssl x509 -text",
                        "N/A — informational; feeds cross-service surfaces.",
                        [], kind="vsphere_cert"))

            login = pr.get("login") or {}
            if login.get("success"):
                out.append(_finding(
                    "critical",
                    "vSphere valid credentials accepted", tgt,
                    f"SessionManager.Login accepted user "
                    f"'{login.get('user','?')}' — the returned "
                    f"vmware_soap_session cookie is a live admin API session. "
                    f"On ESXi this is direct host takeover; on vCenter it is "
                    "API control over every managed host and VM.",
                    "govc",
                    f"GOVC_URL=https://{login.get('user','')}"
                    f"@{h.ip} GOVC_INSECURE=1 govc ls -l",
                    "Rotate the compromised account; enforce MFA on SSO; "
                    "restrict the SDK to a dedicated management network.",
                    ["CWE-287", "CWE-521"], kind="vsphere_valid_creds"))

                sessions = pr.get("sessions") or []
                if sessions:
                    ops = sorted({s["user_name"] for s in sessions
                                  if s.get("user_name")})
                    ips = sorted({s["ip_address"] for s in sessions
                                  if s.get("ip_address")})
                    out.append(_finding(
                        "high",
                        f"vSphere active session list enumerated "
                        f"({len(sessions)})", tgt,
                        f"Active operators: {', '.join(ops)[:400]}. "
                        f"Client IPs: {', '.join(ips)[:400]}. Feeds "
                        "known_users (real accounts) and relay_targets "
                        "(admin workstations).",
                        "govc", "govc session.ls",
                        "Rotate any account whose session is unexpected; "
                        "review admin workstation exposure.",
                        ["CWE-200"], kind="vsphere_sessions"))

                mh = pr.get("managed_hosts") or []
                mv = pr.get("managed_vms") or []
                if mh or mv:
                    names = [h_["props"].get("name", "")
                             for h_ in mh if h_.get("props")]
                    out.append(_finding(
                        "critical",
                        f"vCenter inventory enumerated: "
                        f"{len(mh)} ESXi host(s), {len(mv)} VM(s)", tgt,
                        f"Each managed host has its own /sdk and can be "
                        "attacked with the same or vendor-default creds. "
                        f"Hosts: {', '.join([n for n in names if n])[:300]}.",
                        "govc", "govc ls host ; govc ls vm",
                        "Alert on inventory reads from non-management IPs; "
                        "rotate the account used to enumerate.",
                        ["CWE-284"], kind="vsphere_inventory"))

                stale = _stale_snapshot_vms(mv)
                if stale:
                    out.append(_finding(
                        "high",
                        f"vCenter powered-off VMs with snapshots "
                        f"({len(stale)})", tgt,
                        f"Reverting a powered-off VM to an existing snapshot "
                        f"undoes any post-compromise password rotation, EDR "
                        f"install, or IR containment on the guest OS since "
                        f"the snapshot was taken. Affected VMs: "
                        f"{', '.join(stale[:20])[:400]}.",
                        "govc", "govc snapshot.tree -vm <name>",
                        "Consolidate and remove stale snapshots on critical "
                        "assets (DCs, DBs, jump hosts); audit snapshot "
                        "revert operations.",
                        ["CWE-284"], kind="vsphere_stale_snapshot"))

                linked = pr.get("linked_vcenters") or []
                if linked:
                    out.append(_finding(
                        "high",
                        "vCenter Enhanced Linked Mode / peer vCenter(s) named",
                        tgt,
                        "managementServerIp on managed hosts named additional "
                        f"vCenter peers: {', '.join(linked)}. Same SSO creds "
                        "often work across the linked estate.",
                        "govc", "govc about",
                        "Apply the SSO patch level across every linked "
                        "vCenter; rotate SSO admin creds together.",
                        ["CWE-284"], kind="vsphere_linked"))

                locals_ = pr.get("local_users") or []
                if locals_:
                    users = ", ".join(u["principal"] for u in locals_[:20])
                    out.append(_finding(
                        "high",
                        f"ESXi local accounts enumerated ({len(locals_)})",
                        tgt,
                        f"HostLocalAccountManager.RetrieveUserGroups named: "
                        f"{users}. Each account is a spray target — root, "
                        "dcui and vendor service accounts routinely have "
                        "trivial passwords in labs.",
                        "esxcli", "esxcli system account list",
                        "Set strong unique passwords on every enabled ESXi "
                        "local account; disable unused accounts.",
                        ["CWE-521"], kind="vsphere_local_users"))

            if vami_open and p.portid != _VAMI:
                out.append(_finding(
                    "medium",
                    "vCenter VAMI (5480/tcp) reachable alongside SDK", tgt,
                    f"5480/tcp is also open on {h.ip}. VAMI is the "
                    "vCenter Server Appliance Management Interface — separate "
                    "auth surface (root/vmware defaults still common), "
                    "different CVE class than the SDK.",
                    "curl", f"curl -sk https://{h.ip}:5480/",
                    "Restrict VAMI to the OOB management network; rotate the "
                    "appliance root password.",
                    ["CWE-284"], kind="vsphere_vami"))
    return out


# --- runbook --------------------------------------------------------------------

def runbook(ip: str, port: int) -> list[dict]:
    r = role(port)
    if r == "sdk":
        steps = [
            ("fingerprint", "curl",
             f"curl -sk -X POST https://{ip}:{port}/sdk "
             "-H 'Content-Type: text/xml' "
             "--data '<RetrieveServiceContent xmlns=\"urn:vim25\"/>'",
             "Ground-truth build + apiType."),
            ("auth", "govc",
             f"GOVC_URL=https://administrator@vsphere.local@{ip} "
             "GOVC_INSECURE=1 govc about",
             "Try default SSO admin — vsphere.local is the deployment default."),
            ("inventory", "govc",
             f"GOVC_URL=https://<user>@{ip} govc ls -l host ; govc ls -l vm",
             "Enumerate managed hosts + VMs."),
        ]
    elif r == "vami":
        steps = [("auth", "curl",
                  f"curl -sk https://{ip}:5480/rest/appliance/access/consolecli",
                  "Check VAMI console access endpoint.")]
    elif r == "hostd-agent":
        steps = [("nfc", "manual",
                  f"# 902/tcp is the VMware NFC channel to {ip} — "
                  "used for VMDK reads and console.",
                  "Datastore file transfer / NFC.")]
    else:
        steps = []
    return [{"phase": ph, "tool": t, "command": c, "why": w}
            for ph, t, c, w in steps]


def proof_html(command, output, banner: str = "") -> str:
    from .db import mssql
    return mssql.proof_html(command, output, prompt="$ ", banner=banner)


# --- top-level analyze ----------------------------------------------------------

def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "vsphere", 443)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = vsphere_targets(hosts)
    probes: dict = {}
    state: dict = {}
    active_auth = bool(creds) or active
    if active:
        for t, pr in svcprobe.iter_probe(
                targets,
                lambda t: probe(t["ip"], t["port"], creds=creds,
                                active_auth=active_auth),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["api_type"] = pr.get("api_type", "")
                t["version"] = pr.get("version", "")
                t["build"] = pr.get("build", "")
                t["sso_domain"] = pr.get("sso_domain", "")
                t["cve_hits"] = [c["cve"] for c in (pr.get("cves") or [])]
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "role": t["role"], "credfree": runbook(t["ip"], t["port"]),
                 "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
