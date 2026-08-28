"""Per-CVE PoC dossiers + harness skeletons, assembled from recce's OFFLINE intel.

For each CVE this gathers, with no network:
  - the version->CVE signature (vulndb): title, severity, CWE, affected range, fix;
  - KEV (CISA known-exploited) and EPSS (30-day exploitation probability);
  - the Exploit-DB entries that reference the CVE (searchsploit) - the *actual published
    PoC code*, by its local path (present in the airgap bundle);
  - a mapped Metasploit module / published tool (exploitref);
  - a matching PoC build recipe (poc.RECIPES) when the weakness type is one recce knows;
  - the hosts in the current engagement that carry the CVE.

It writes a Markdown dossier and a runnable Python *harness skeleton* per CVE.

recce REFERENCES published exploits and SCAFFOLDS a harness; it does not author
weaponized exploit code. The harness pins the target, runs a safe check, points at the
published exploit, and marks the single [TESTER] line where the operator runs the
ROE-approved action. Authorized-testing use only.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

from . import poc
from ..vuln import epss, exploitref, kev, vulndb

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def valid_cve(s: str) -> bool:
    return bool(_CVE_RE.fullmatch(s.strip()))


def _harness_safe(s: str) -> str:
    """Neutralize scan-derived free-text (finding titles, Exploit-DB paths) for embedding
    inside the generated harness's triple-quoted docstring/comments, so a title containing
    `\"\"\"`, a backslash or a newline can't produce invalid Python."""
    return (s or "").replace("\\", "/").replace('"""', "'''").replace("\r", " ").replace("\n", " ")


def sig_for_cve(cve: str) -> dict | None:
    cve = cve.upper()
    return next((s for s in vulndb.SIGNATURES
                 if cve in [c.upper() for c in s.get("cves", [])]), None)


def edb_for_cve(cve: str) -> list[dict]:
    """Exploit-DB entries referencing this CVE via `searchsploit --cve` (offline).
    Returns [{edb_id, title, path, type}], or [] if searchsploit/exploitdb is absent."""
    if not shutil.which("searchsploit"):
        return []
    num = cve.upper().replace("CVE-", "")
    try:
        proc = subprocess.run(
            ["searchsploit", "--cve", num, "--json", "--disable-colour"],
            capture_output=True, text=True, timeout=30)
        data = json.loads(proc.stdout or "{}")
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError, ValueError):
        return []
    rows = data.get("RESULTS_EXPLOIT", []) if isinstance(data, dict) else []
    out = []
    for r in rows:
        out.append({"edb_id": r.get("EDB-ID", ""), "title": r.get("Title", ""),
                    "path": r.get("Path", ""), "type": r.get("Type", "")})
    return out


def _recipe_for(cve: str, sig: dict | None) -> tuple[str | None, dict | None]:
    text = " ".join(filter(None, [cve, (sig or {}).get("title", ""), (sig or {}).get("desc", "")]))
    key = poc.recipe_key_for(text)
    return (key, poc.RECIPES[key]) if (key and key in poc.RECIPES) else (None, None)


def gather(cve: str, hosts: list) -> dict:
    """Assemble everything recce knows about `cve` offline + who's affected here."""
    cve = cve.upper()
    sig = sig_for_cve(cve)
    affected = []
    for h in hosts:
        for v in getattr(h, "vulns", []):
            if cve in [x.upper() for x in (v.ids or [])]:
                affected.append({"ip": h.ip, "port": v.port,
                                 "title": v.title or v.script_id or cve,
                                 "severity": v.severity or "info",
                                 "confidence": v.confidence or ""})
    sev = (sig or {}).get("severity") or (affected[0]["severity"] if affected else "unknown")
    key, recipe = _recipe_for(cve, sig)
    return {
        "cve": cve, "sig": sig, "affected": affected, "severity": sev,
        "title": (sig or {}).get("title") or (affected[0]["title"] if affected else cve),
        "cwe": list((sig or {}).get("cwe", [])),
        "kev": kev.is_kev(cve), "epss": epss.score_for(cve),
        "remediation": (sig or {}).get("remediation", ""),
        "desc": (sig or {}).get("desc", ""),
        "msf": exploitref.proven_exploit_ref([cve], (sig or {}).get("title", "")) or "",
        "edb": edb_for_cve(cve),
        "recipe_key": key, "recipe": recipe,
    }


def _pct(x: float) -> str:
    return f"{round((x or 0) * 100)}%"


def render_dossier(d: dict) -> str:
    cve = d["cve"]
    L = [f"# {cve} — {d['title']}", ""]
    flags = []
    if d["kev"]:
        flags.append("🔥 CISA KEV (known-exploited)")
    if d["epss"]:
        flags.append(f"EPSS {_pct(d['epss'])}")
    flags.append(f"severity: {d['severity']}")
    if d["cwe"]:
        flags.append("CWE " + ", ".join(d["cwe"]))
    L += ["> " + "  ·  ".join(flags), ""]
    if d["desc"]:
        L += ["## What it is", d["desc"], ""]

    L += ["## Affected in this engagement"]
    if d["affected"]:
        for a in d["affected"]:
            tgt = f"{a['ip']}" + (f":{a['port']}" if a["port"] else "")
            L.append(f"- `{tgt}` — {a['title']} ({a['confidence'] or 'unconfirmed'})")
    else:
        L.append("- (none detected here — supplied CVE; confirm the target is affected first)")
    L.append("")

    L += ["## Published exploit / tool  *(recce references these — it did not write them)*"]
    if d["msf"]:
        L.append(f"- **Metasploit / tool:** {d['msf']}")
    if d["edb"]:
        L.append("- **Exploit-DB (local, in the airgap bundle):**")
        for e in d["edb"][:12]:
            L.append(f"  - EDB-{e['edb_id']} — {e['title']}  →  `{e['path']}`")
    if not d["msf"] and not d["edb"]:
        L.append("- No mapped msf module / Exploit-DB entry offline. Develop from the "
                 "references + the harness skeleton, using the check below to validate.")
    L.append("")

    if d["recipe"]:
        r = d["recipe"]
        L += [f"## PoC build recipe — {r.get('name', d['recipe_key'])}"]
        for fn in (r.get("files") or {}):
            L.append(f"- writes `{fn}`")
        for step in (r.get("build") or []):
            L.append(f"- build: `{step}`")
        if r.get("deliver"):
            L.append(f"- deliver: {r['deliver']}")
        if r.get("proof"):
            L.append(f"- proof: {r['proof']}")
        L.append("")

    L += ["## Develop the PoC",
          "1. Confirm the target is actually affected — run `check()` in `poc.py` "
          "(safe, non-destructive) or `recce verify --run`.",
          "2. Use the published exploit above (Exploit-DB path / msf module) as your PoC, "
          "or implement `exploit()` in `poc.py` — within your rules of engagement.",
          "3. Capture the proof (screenshot / output) for the write-up; revert anything you changed.",
          "",
          "> ⚖️ Authorized testing only. recce assembles references and a scaffold; it does "
          "not ship a weaponized exploit — use the purpose-built published tool within scope.",
          ""]
    if d["remediation"]:
        L += ["## Remediation", d["remediation"], ""]
    return "\n".join(L)


def render_harness(d: dict) -> str:
    cve = d["cve"]
    a = d["affected"][0] if d["affected"] else {}
    target = a.get("ip", "TARGET-IP")
    port = a.get("port") or 0
    refs = []
    if d["msf"]:
        refs.append(d["msf"])
    for e in d["edb"][:5]:
        refs.append(f"EDB-{e['edb_id']}: {e['path']}")
    ref_block = "\n".join(f"#   - {_harness_safe(r)}" for r in refs) or "#   - (none mapped offline)"
    all_targets = [f'("{x["ip"]}", {x["port"] or 0})' for x in d["affected"]] or [f'("{target}", {port})']
    title = _harness_safe(d["title"])
    return f'''#!/usr/bin/env python3
"""PoC harness scaffold for {cve} — {title}.

AUTHORIZED TESTING ONLY. This is a scaffold, not a weaponized exploit: it pins the
target, runs a SAFE check, and points at the PUBLISHED exploit. Implement the
ROE-approved proof action in exploit(), or run the referenced published tool instead.

Published exploit / tool (recce references these; it did not author them):
{ref_block}

Affected in the engagement: {", ".join(f"{x['ip']}:{x['port'] or ''}" for x in d["affected"]) or "(supplied CVE)"}
"""
import sys

# (ip, port) targets recce found affected by {cve} in this engagement:
TARGETS = [{", ".join(all_targets)}]


def check(ip: str, port: int) -> bool:
    """Safe, non-destructive confirmation that ip:port is affected by {cve}.
    Implement the appropriate check (banner/version read, benign behavioural probe).
    recce's own detection lives in `recce verify --run`; mirror that logic here."""
    raise NotImplementedError("implement a non-destructive check for {cve}")


def exploit(ip: str, port: int) -> None:
    """[TESTER] Run the ROE-approved proof action here, or invoke the published exploit
    referenced in the header (Exploit-DB path / msf module). recce does not ship the
    weaponized exploit — use the purpose-built published tool, within your scope."""
    raise NotImplementedError("[TESTER] wire up the ROE-approved published exploit for {cve}")


def main() -> int:
    print(f"[*] {cve} PoC scaffold — {{len(TARGETS)}} target(s)")
    for ip, port in TARGETS:
        try:
            ok = check(ip, port)
        except NotImplementedError as e:
            print(f"[!] {{ip}}:{{port}} check not implemented — {{e}}")
            continue
        print(f"[{{'+' if ok else '-'}}] {{ip}}:{{port}} affected={{ok}}"
              + ("  -> run exploit() within ROE" if ok else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def generate(cves: list[str], hosts: list, out_dir: str,
             with_exploits: bool = False) -> list[dict]:
    """Write eng/poc/<CVE>/{<CVE>.md, poc.py} for each CVE. Returns per-CVE summaries."""
    base = os.path.join(out_dir, "poc")
    os.makedirs(base, exist_ok=True)
    results = []
    for cve in cves:
        cve = cve.upper()
        d = gather(cve, hosts)
        cdir = os.path.join(base, cve)
        os.makedirs(cdir, exist_ok=True)
        # Explicit UTF-8, not the platform default: both files embed real finding
        # titles/descriptions (from the engagement or an ingested tool), which can
        # carry non-ASCII - the platform default is locale-dependent (e.g. cp1252
        # on Windows) and would raise UnicodeEncodeError there.
        with open(os.path.join(cdir, f"{cve}.md"), "w", encoding="utf-8") as fh:
            fh.write(render_dossier(d))
        with open(os.path.join(cdir, "poc.py"), "w", encoding="utf-8") as fh:
            fh.write(render_harness(d))
        copied = 0
        if with_exploits:
            used: set[str] = set()
            for e in d["edb"]:
                src = e.get("path", "")
                if not (src and os.path.isfile(src)):
                    continue
                name = os.path.basename(src)
                if name in used:                       # two EDB entries can share a
                    name = f"{e.get('edb_id') or 'edb'}-{name}"   # basename - keep both
                if name in used:
                    continue
                try:
                    shutil.copy2(src, os.path.join(cdir, name))
                    used.add(name)
                    copied += 1
                except OSError:
                    pass
        results.append({"cve": cve, "affected": len(d["affected"]), "kev": d["kev"],
                        "epss": d["epss"], "edb": len(d["edb"]), "msf": bool(d["msf"]),
                        "recipe": d["recipe_key"], "exploits_copied": copied, "dir": cdir})
    return results
