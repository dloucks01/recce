"""Emit a BloodHound-CE-compatible collection from the engagement store.

Recce READS SharpHound/BloodHound JSON in ad/bloodhound.py; this module writes
its own scan intel back in the same shape so an operator can overlay recce's
findings on their existing BloodHound instance.

Sources — all read-only from the engagement store:
  * ``Host.accounts`` where ``kind in ("user","computer","group","domain")`` are
    the nodes. Any pre-existing ``rid`` that already looks like a full SID is
    used verbatim so recce's own SharpHound-import round-trips; otherwise a
    stable synthetic SID (``S-1-5-21-RECCE-<domain>-<rid>`` when a numeric RID
    is present, else a name-hashed synthesized SID) is emitted.
  * ``Credential`` rows with source in ("cracked","spray-validated") mark the
    corresponding user node as ``Owned=True``; when the credential carries an
    ``origin_ip`` that also names a computer node, a ``HasSession`` edge is
    written from that computer to the user (the operator can see WHO they
    cracked and WHERE the session lived).
  * ``Vuln`` rows whose ``source == "adcs"`` — every ADCS ESC finding recce
    persisted — are emitted as edges from the abusing principal to the CA node
    (a synthesized CA container per unique CA name), with the ESC label folded
    into the edge properties so BloodHound's ADCS overlay lights up.

Output: ``<eng>/bloodhound/<YYYYMMDD_HHMMSS>_recce_push.zip`` containing the
seven per-object-type JSON files BloodHound CE ingests (``users.json``,
``computers.json``, ``groups.json``, ``domains.json``, ``gpos.json``,
``ous.json``, ``containers.json``). Each file's top-level shape mirrors what
``bloodhound.load_graph()`` parses:
    ``{"data": [{...}], "meta": {"type": "<kind>", "count": N, "version": 5}}``

Airgapped, stdlib only (``json`` + ``zipfile``). Read-only against the store.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import zipfile


# BloodHound CE 5.x collection version stamped in each file's meta block.
_BH_VERSION = 5
# The seven per-object-type files BloodHound CE ingests (all are always present,
# even when the corresponding node list is empty — an empty file is a valid
# signal that "this collector visited but found nothing of this kind").
_FILE_KINDS = ("users", "computers", "groups", "domains",
               "gpos", "ous", "containers")

# Credential sources that mean recce PROVED the account (not merely observed).
# These are what mark a user node as Owned=True on push.
_OWNED_SOURCES = frozenset({"cracked", "spray-validated"})


def _now_stamp() -> str:
    """Filesystem-safe UTC timestamp for the output zip name."""
    return time.strftime("%Y%m%d_%H%M%S", time.gmtime())


def _norm_domain(domain: str) -> str:
    """BloodHound canonicalises domain names as UPPER; do the same so a
    recce-emitted node and an existing BloodHound node with the same identity
    hash together across imports."""
    return (domain or "").strip().upper()


def _looks_like_sid(s: str) -> bool:
    """A full SID looks like ``S-1-5-...``; anything else is a bare RID or a
    hand-built key we need to synthesize a SID for."""
    return isinstance(s, str) and s.upper().startswith("S-1-")


def _domain_sid_seed(domain: str) -> str:
    """Deterministic numeric authority for a synthesized domain SID.

    Real domains have a random authority triple; we hash the domain name so
    every push for the same domain yields the same authority (idempotent).
    BloodHound doesn't verify authority triples — it only cares that the SID is
    unique and consistent within one collection."""
    dom = _norm_domain(domain) or "RECCE"
    h = hashlib.sha1(dom.encode("utf-8", "replace")).digest()
    # Three 32-bit fields, each ≤ 2^31-1 so it fits an int SID authority.
    a = int.from_bytes(h[0:4], "big") & 0x7FFFFFFF
    b = int.from_bytes(h[4:8], "big") & 0x7FFFFFFF
    c = int.from_bytes(h[8:12], "big") & 0x7FFFFFFF
    return f"S-1-5-21-{a}-{b}-{c}"


def _synth_sid(domain: str, rid: str, name: str, kind: str) -> str:
    """Best-effort ObjectIdentifier for an account without a real SID.

    Priority:
      1. `rid` is already a full SID → use verbatim (round-trips recce's own
         SharpHound import, where analysis_to_accounts stashed the real SID).
      2. `rid` is a numeric RID → append it to the domain-hashed authority.
      3. Fall back to hashing (kind|domain|name) so the same account across
         two pushes lands on the same SID.
    """
    if _looks_like_sid(rid):
        return rid.upper()
    dom_sid = _domain_sid_seed(domain)
    if rid and str(rid).isdigit():
        return f"{dom_sid}-{rid}"
    key = f"{kind}|{_norm_domain(domain)}|{(name or '').upper()}".encode("utf-8", "replace")
    tail = int.from_bytes(hashlib.sha1(key).digest()[:4], "big") & 0x7FFFFFFF
    return f"{dom_sid}-{tail}"


def _display_name(name: str, domain: str) -> str:
    """BloodHound stores object names as ``UPPER@DOMAIN.TLD``. Keep an existing
    ``@`` suffix intact; append the domain otherwise."""
    n = (name or "").strip()
    if not n:
        return ""
    if "@" in n:
        return n.upper()
    dom = _norm_domain(domain)
    return f"{n.upper()}@{dom}" if dom else n.upper()


def _base_props(acc, dom: str) -> dict:
    """Common BloodHound Properties block for an account."""
    attrs = acc.attrs or {}
    props: dict = {"name": _display_name(acc.name, dom), "domain": dom,
                   "highvalue": False}
    # Lift the discriminators recce's own BloodHound reader (see
    # analysis_to_accounts) round-trips through Account.attrs. `enabled`
    # defaults to True so unspecified accounts are considered spray-relevant
    # (matches how the reader treats a missing `enabled`).
    enabled = attrs.get("enabled")
    props["enabled"] = False if str(enabled).lower() == "false" else True
    for src_key, dst_key in (("admincount", "admincount"),
                             ("kerberoastable", "hasspn"),
                             ("asrep_roastable", "dontreqpreauth")):
        if src_key in attrs:
            v = attrs[src_key]
            if src_key == "admincount":
                props[dst_key] = str(v) in ("1", "True", "true")
            else:
                props[dst_key] = bool(v)
    if str(attrs.get("delegation", "")).lower() == "unconstrained":
        props["unconstraineddelegation"] = True
    if attrs.get("description"):
        props["description"] = str(attrs["description"])
    if attrs.get("spn"):
        props["serviceprincipalnames"] = ([attrs["spn"]]
                                          if isinstance(attrs["spn"], str)
                                          else list(attrs["spn"]))
    return props


def _node_shell(sid: str, props: dict, extras: dict | None = None) -> dict:
    """Wrap a node in the SharpHound object skeleton the reader expects.

    ``Aces`` and the per-type collection lists are always present (even if
    empty) so the reader's ``for ace in obj.get("Aces") or []`` paths never
    trip on a missing key across collector versions."""
    obj: dict = {"ObjectIdentifier": sid, "Properties": props, "Aces": []}
    if extras:
        obj.update(extras)
    return obj


def _classify_account(acc) -> str:
    """Map ``Account.kind`` onto a BloodHound file bucket. Unknown/other kinds
    (share/spn/trust/...) do not land in a per-object-type file — SharpHound
    doesn't model them at the top level either."""
    k = (acc.kind or "").lower()
    return {"user": "users", "computer": "computers",
            "group": "groups", "domain": "domains"}.get(k, "")


def _collect_nodes(hosts) -> tuple[dict, dict]:
    """Walk every host's accounts, produce {kind: [node,...]} plus an index
    ``(kind, name_upper) -> node`` so later passes (owned marking, ADCS edges)
    can look a principal up without re-scanning the whole set.

    Deduplication is first-seen-wins on the composite ``(kind, sid)`` key.
    """
    buckets: dict[str, list[dict]] = {k: [] for k in _FILE_KINDS}
    by_key: dict[tuple, dict] = {}    # (kind, name_upper) -> node
    seen_sids: set[tuple] = set()     # (kind, sid) -> dedupe
    for h in hosts or []:
        for acc in (h.accounts or []):
            kind = _classify_account(acc)
            if not kind or not (acc.name or "").strip():
                continue
            dom = _norm_domain(acc.domain)
            sid = _synth_sid(dom, acc.rid or "", acc.name, kind)
            dedupe_key = (kind, sid)
            if dedupe_key in seen_sids:
                continue
            seen_sids.add(dedupe_key)
            props = _base_props(acc, dom)
            extras: dict = {}
            if kind == "groups":
                extras["Members"] = []
            elif kind == "computers":
                extras.update({"LocalAdmins": {"Collected": False, "Results": []},
                               "RemoteDesktopUsers": {"Collected": False, "Results": []},
                               "PSRemoteUsers": {"Collected": False, "Results": []},
                               "DcomUsers": {"Collected": False, "Results": []},
                               "Sessions": {"Collected": False, "Results": []},
                               "AllowedToDelegate": [],
                               "AllowedToAct": {"Collected": False, "Results": []}})
            elif kind == "domains":
                extras["Trusts"] = []
                extras["ChildObjects"] = []
                extras["Links"] = []
            node = _node_shell(sid, props, extras)
            buckets[kind].append(node)
            by_key[(kind, props["name"])] = node
            # Cross-key lookup by the leading label too (e.g. "ALICE") — ADCS
            # findings sometimes name the principal without a domain suffix.
            short = props["name"].split("@", 1)[0]
            by_key.setdefault((kind, short), node)
    return buckets, by_key


def _mark_owned(buckets: dict, by_key: dict, creds) -> int:
    """Set ``Properties.Owned = True`` on user nodes for every credential whose
    source proves recce actually possesses the account (cracked/spray-
    validated). Returns the count of nodes marked."""
    marked = 0
    for c in creds or []:
        if (c.source or "") not in _OWNED_SOURCES or not c.username:
            continue
        dom = _norm_domain(c.domain)
        candidates = [_display_name(c.username, dom),
                      (c.username or "").upper()]
        for name in candidates:
            node = by_key.get(("users", name))
            if node is not None:
                if not node["Properties"].get("Owned"):
                    node["Properties"]["Owned"] = True
                    node["Properties"]["highvalue"] = True
                    marked += 1
                break
    return marked


def _adcs_edges(buckets: dict, by_key: dict, hosts) -> int:
    """Emit ADCS ESC edges for every Vuln with ``source == "adcs"``.

    The abusing user's node grows an ``Aces`` entry pointing FROM a synthesized
    CA container (in the ``computers`` bucket, matching how SharpHound emits
    CAs) — using the SharpHound edge shape ``{PrincipalSID, RightName}`` so
    ``load_graph()`` picks it up as an edge. The right name is the ESC label
    (``ADCSESC1`` etc.) so an operator viewing the imported collection in
    BloodHound sees the ADCS overlay on the recce-added nodes.

    Returns the number of edges emitted.
    """
    n = 0
    ca_sids: dict[str, str] = {}      # ca_name -> synthesized SID
    for h in hosts or []:
        dom_hint = ""
        for a in (h.accounts or []):
            if _classify_account(a) == "domains":
                dom_hint = _norm_domain(a.domain or a.name)
                break
        for v in (h.vulns or []):
            if (v.source or "").lower() != "adcs":
                continue
            # script_id shape from bloodhound.findings_to_vulns:
            #   "ad-adcs-esc1:<who>|<target>"
            sid_field = v.script_id or ""
            if not sid_field.startswith("ad-adcs-"):
                continue
            head, _, rest = sid_field.partition(":")
            esc = head[len("ad-"):]                          # "adcs-esc1"
            esc_label = esc.replace("-", "").upper()         # "ADCSESC1"
            who_part, _, tgt_part = rest.partition("|")
            who = (who_part or "").strip().split(",")[0].strip()  # first enroller
            ca_name = (tgt_part or "").split("@")[-1].strip() or "recce-ca"
            # Resolve or synthesize the CA node in `computers`.
            ca_sid = ca_sids.get(ca_name)
            if ca_sid is None:
                ca_sid = _synth_sid(dom_hint, "", f"CA:{ca_name}", "computers")
                ca_sids[ca_name] = ca_sid
                ca_props = {"name": _display_name(ca_name, dom_hint),
                            "domain": dom_hint, "highvalue": True,
                            "enabled": True, "isca": True}
                buckets["computers"].append(_node_shell(ca_sid, ca_props, {
                    "LocalAdmins": {"Collected": False, "Results": []},
                    "RemoteDesktopUsers": {"Collected": False, "Results": []},
                    "PSRemoteUsers": {"Collected": False, "Results": []},
                    "DcomUsers": {"Collected": False, "Results": []},
                    "Sessions": {"Collected": False, "Results": []},
                    "AllowedToDelegate": [],
                    "AllowedToAct": {"Collected": False, "Results": []},
                }))
                by_key[("computers", ca_props["name"])] = buckets["computers"][-1]
            # Locate the abusing user node; skip cleanly if it wasn't in scope.
            user_node = (by_key.get(("users", _display_name(who, dom_hint)))
                         or by_key.get(("users", (who or "").upper())))
            if user_node is None:
                continue
            user_sid = user_node["ObjectIdentifier"]
            ca_node = buckets["computers"][-1] if ca_sid == buckets["computers"][-1]["ObjectIdentifier"] \
                else next(x for x in buckets["computers"]
                          if x["ObjectIdentifier"] == ca_sid)
            ca_node["Aces"].append({"PrincipalSID": user_sid,
                                    "PrincipalType": "User",
                                    "RightName": esc_label,
                                    "IsInherited": False})
            n += 1
    return n


def _write_zip(zip_path: str, buckets: dict) -> None:
    """Emit the seven per-kind JSON files into a single zip. Every file is
    written even if its bucket is empty (count=0) so consumers can rely on the
    complete set being present."""
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for kind in _FILE_KINDS:
            data = buckets.get(kind, [])
            payload = {"data": data,
                       "meta": {"type": kind, "count": len(data),
                                "version": _BH_VERSION,
                                "methods": 0}}
            zf.writestr(f"{kind}.json",
                        json.dumps(payload, ensure_ascii=False, indent=2))


def build_zip(hosts, creds, out_dir: str, *, overwrite: bool = False,
              stamp: str | None = None) -> tuple[str, dict]:
    """Build a BloodHound CE ingest zip from the engagement store.

    Args:
        hosts: iterable of ``Host`` (read-only; typically ``store.all_hosts()``).
        creds: iterable of ``Credential`` (read-only; ``store.all_credentials()``).
        out_dir: engagement directory (``bloodhound/`` is created under it).
        overwrite: rewrite the zip in place if a same-name file exists.
        stamp: override the timestamp (tests). Default: current UTC.

    Returns ``(zip_path, summary)`` where summary carries the per-file counts.
    """
    stamp = stamp or _now_stamp()
    dest_dir = os.path.join(out_dir, "bloodhound")
    os.makedirs(dest_dir, exist_ok=True)
    zip_path = os.path.join(dest_dir, f"{stamp}_recce_push.zip")
    if os.path.exists(zip_path) and not overwrite:
        # Second-resolution collision: append a monotonic suffix rather than
        # silently clobber a prior push the operator might still be uploading.
        i = 1
        while os.path.exists(os.path.join(
                dest_dir, f"{stamp}_recce_push.{i}.zip")):
            i += 1
        zip_path = os.path.join(dest_dir, f"{stamp}_recce_push.{i}.zip")

    buckets, by_key = _collect_nodes(hosts)
    owned_n = _mark_owned(buckets, by_key, creds)
    adcs_n = _adcs_edges(buckets, by_key, hosts)
    _write_zip(zip_path, buckets)
    summary = {"zip": zip_path,
               "counts": {k: len(buckets.get(k, [])) for k in _FILE_KINDS},
               "owned": owned_n, "adcs_edges": adcs_n}
    return zip_path, summary
