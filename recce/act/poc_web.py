"""In-memory PoC collection for the WebUI Exploit tab.

recce already generates real proof-of-concept artifacts for CONFIRMED findings
(recce/act/poc.py): tailored web PoCs (git-dumper, JWT forge, SSTI, GraphQL dump,
heapdump grep…), build-recipe PoCs (LD_PRELOAD / DLL-hijack / redis-rce / pg-rce…),
and pwntools skeletons for memory-corruption findings. The CLI writes them to disk;
this surfaces the same content in memory so the WebUI can show/copy/download each
script. Every artifact is a proof (benign marker + an ROE-swap line), built from a
published technique with the target's own parameters — not new weaponized code.
"""
from __future__ import annotations

import copy

from ..core.tracking import vuln_row_key
from . import poc

_LANG = {"py": "python", "sh": "bash", "c": "c", "dll": "c", "html": "html",
         "js": "javascript", "rb": "ruby", "txt": "text", "ps1": "powershell"}


def _lang(fname: str) -> str:
    return _LANG.get(fname.rsplit(".", 1)[-1].lower(), "text")


def _art(kind, host, filename, source, proves, finding="", build=None, deliver="", proof=""):
    return {"kind": kind, "host": host, "filename": filename, "lang": _lang(filename),
            "source": source, "proves": proves, "finding": finding or proves,
            "build": list(build or []), "deliver": deliver, "proof": proof}


def collect(hosts, *, scope: str = "engagement", target: str = "") -> dict:
    """Gather the PoC artifacts for a scope. scope: engagement | host (target=ip)
    | finding (target=finding_key — resolves to that finding's host)."""
    if scope == "host":
        sel = [h for h in hosts if h.ip == target]
    elif scope == "finding":
        # Narrow precisely to the ONE finding: clone its host carrying only that
        # vuln, so the generators emit that finding's PoC(s), not the whole host's.
        sel = []
        for h in hosts:
            v = next((x for x in h.vulns if vuln_row_key(x) == target), None)
            if v is not None:
                clone = copy.copy(h)
                clone.vulns = [v]
                clone.local_findings = []      # host-general privesc PoCs aren't this finding
                sel = [clone]
                break
    else:
        scope, sel = "engagement", [h for h in hosts if h.is_up]

    arts: list[dict] = []
    for h in sel:
        for fname, content, note in poc.web_pocs_for_host(h):
            arts.append(_art("web", h.ip, fname, content, note, note))
        for fname, content, note in poc.pwntools_for_host(h):
            arts.append(_art("pwntools", h.ip, fname, content, note, note,
                             build=["pip install pwntools"],
                             deliver="run on the operator box; set OFFSET from the crash",
                             proof="control of the saved return address (find OFFSET via the cyclic pattern first)"))
        for _key, r in poc.select_for_host(h).items():
            for fname, content in r.get("files", {}).items():
                arts.append(_art("recipe", h.ip, fname, content, r.get("proof", ""),
                                 r.get("name", ""), build=r.get("build", []),
                                 deliver=r.get("deliver", ""), proof=r.get("proof", "")))

    # Dedup by filename (recipe sources are shared across hosts).
    seen: set = set()
    uniq: list[dict] = []
    for a in arts:
        if a["filename"] in seen:
            continue
        seen.add(a["filename"])
        uniq.append(a)
    uniq.sort(key=lambda a: (a["kind"] != "pwntools", a["host"], a["filename"]))
    return {"artifacts": uniq,
            "meta": {"scope": scope, "target": target, "hosts": len(sel), "count": len(uniq)}}
