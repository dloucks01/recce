"""Active-scan bridges to external red-team tools recce doesn't reimplement.

Each function shells out to the tool, captures its native output, and returns
a list of `Vuln` (or similar) objects the existing import pipeline understands.
This is deliberately thin — recce authors no scanner engines here; it drives
the standards (nuclei, certipy) that testers already trust, and folds their
output into the shared engagement.

Every runner:
  * checks the tool binary is on PATH (returns a friendly "not installed"
    Vuln so the operator sees WHY nothing happened),
  * writes the raw output to `<out_dir>/raw/<tool>_<target>.<ext>` for
    provenance + retryable ingest,
  * caps run time with a subprocess timeout so a hung tool can't hang the
    whole scan job.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from urllib.parse import urlparse

from ..core.models import Vuln
from ..intake import importers


_TOOL_TIMEOUT = 900     # 15 minutes per host — enough for a moderate nuclei run


def _which(tool: str) -> str | None:
    return shutil.which(tool)


def _missing_tool(tool: str, target: str, install_hint: str) -> Vuln:
    return Vuln(
        ip=target, port=0, protocol="tcp",
        script_id=f"external-{tool}-missing",
        state="", title=f"{tool} not installed on the recce host",
        output=f"{tool!r} isn't on PATH — install it to enable this active scan.\n\n{install_hint}",
        severity="info", ids=[], cwes=[], source=f"external-{tool}",
        confidence="info", qod=0, qod_type="")


def run_nuclei(target: str, out_dir: str, *, extra_args: list[str] | None = None,
               timeout: int = _TOOL_TIMEOUT) -> tuple[list[Vuln], str, str | None]:
    """Run `nuclei -u <target>` and return (findings, raw_json_path, error).

    target: an http(s) URL, or a host[:port] we'll wrap as http:// . The
    caller (CLI handler) decides how many targets to iterate over.
    """
    bin_path = _which("nuclei")
    if bin_path is None:
        return ([_missing_tool("nuclei", target,
                               "brew install nuclei  # or:\n  "
                               "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")],
                "", "nuclei binary not found")
    # Normalize target → URL. If the tester passed a bare host we default to
    # http:// (nuclei will follow-redirect to https where it lands).
    url = target if "://" in target else f"http://{target}"
    parsed = urlparse(url)
    host_slug = parsed.netloc.replace(":", "_") or target.replace(":", "_")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"nuclei_{host_slug}.json")
    argv = [bin_path, "-u", url,
            "-jsonl", "-o", out_path,
            "-silent",
            "-severity", "info,low,medium,high,critical",
            "-timeout", "15",
            "-retries", "1"]
    if extra_args:
        argv.extend(extra_args)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ([], out_path, f"nuclei timed out after {timeout}s against {url}")
    except OSError as e:
        return ([], out_path, f"failed to run nuclei: {e}")
    # nuclei exits 0 even when it finds nothing. Errors go to stderr.
    if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
        # Still return silence with the tool's stderr as context (helps debug
        # "why no findings" — e.g. rate limit, network unreachable).
        if proc.returncode != 0:
            return ([], out_path,
                    f"nuclei rc={proc.returncode}: {(proc.stderr or '').strip()[:400]}")
        return ([], out_path, None)
    with open(out_path) as fh:
        data = fh.read()
    try:
        vulns = importers.parse_nuclei(data, include_info=False)
    except Exception as e:  # noqa: BLE001 — parse failure surfaces, doesn't blow up scan
        return ([], out_path, f"failed to parse nuclei output: {e}")
    return (vulns, out_path, None)


def run_certipy(target_dc_ip: str, user: str, password: str, domain: str,
                out_dir: str, *, timeout: int = _TOOL_TIMEOUT
                ) -> tuple[str, str | None]:
    """Run `certipy find` against an AD-CS enrollment endpoint and return
    (raw_json_path, error). The path is then fed to the existing `recce ad`
    importer which folds ESC1..ESC15 findings into the engagement.

    Requires operator creds — a domain user is enough; a privileged account
    yields more (some templates only enumerate as an authenticated principal).
    """
    bin_path = _which("certipy") or _which("certipy-ad")
    if bin_path is None:
        # No missing-tool Vuln here — this returns (path, err) so the CLI
        # handler emits a friendly issue instead.
        return ("", "certipy not installed. Install with: pipx install certipy-ad")
    if not (user and password and target_dc_ip and domain):
        return ("", "certipy needs -u, -p, -d, --dc-ip (domain user + DC IP + domain)")
    os.makedirs(out_dir, exist_ok=True)
    stem = os.path.join(out_dir, f"certipy_{target_dc_ip.replace(':','_')}_{int(time.time())}")
    # `-output` writes <stem>_Certipy.json (+ .txt); we consume the JSON.
    argv = [bin_path, "find",
            "-u", f"{user}@{domain}",
            "-p", password,
            "-dc-ip", target_dc_ip,
            "-output", stem,
            "-vulnerable"]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ("", f"certipy timed out after {timeout}s")
    except OSError as e:
        return ("", f"failed to run certipy: {e}")
    # Certipy writes <stem>_Certipy.json by convention.
    json_path = f"{stem}_Certipy.json"
    if not os.path.exists(json_path):
        # Fall back to any json file starting with the stem (certipy naming
        # differs between versions).
        cand = [p for p in os.listdir(out_dir)
                if p.startswith(os.path.basename(stem)) and p.endswith(".json")]
        if cand:
            json_path = os.path.join(out_dir, cand[0])
    if not os.path.exists(json_path):
        return ("", f"certipy rc={proc.returncode} produced no JSON: "
                f"{(proc.stderr or proc.stdout or '').strip()[:400]}")
    return (json_path, None)
