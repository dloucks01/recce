"""Phase 2 — declarative user-contributable parsers.

The problem: not every scanner has a stable output format the built-in
parsers can pin. Internal tools drift, tester one-liners are one-off, older
tool versions look nothing like newer ones. Instead of expanding parsers_*.py
for every request, testers can drop a small JSON (or YAML if PyYAML is
installed) definition into `~/.recce/parsers/` (or `<engagement>/parsers/`)
and recce auto-loads it into the SCANNER_PARSERS registry — no Python, no
restart, no PR.

## Schema

    {
      "name": "my-scanner",              # unique key registered in SCANNER_PARSERS
      "description": "…",                # shown in ImportModal dropdown
      "detect": {
        "filename_glob": "*.myss",       # any match wins
        "content_re": "^my-scanner v",   # either or both may be set
        "content_substr": "my-scanner"   # cheap prefilter before regex
      },
      "match": {
        "target_re": "^Target:\\s+(?P<target>\\S+)",   # host extraction (line-scoped)
        "port_default": 443
      },
      "findings": [
        {
          "marker_re": "^\\[CRIT\\]\\s+(?P<title>.+?)(?:\\s+at\\s+(?P<port>\\d+))?$",
          "severity": "critical",
          "source": "my-scanner",         # else falls back to `name`
          "confidence": "confirmed"       # optional; else "likely"
        }
      ]
    }

Named groups understood in `marker_re`: `title`, `port`, `ip`, `cve`,
`output`. Any not present are inferred from `match.target_re` (for the ip)
or `match.port_default` (for the port). `title` is required.

## Locations scanned

Loaded once per process at first import, in this order (later wins):
  1. ``recce/intake/user_parsers_bundled/`` — shipped example parsers
  2. ``$XDG_CONFIG_HOME/recce/parsers/`` (or ``~/.recce/parsers/``)
  3. ``$RECCE_USER_PARSERS`` (env var; colon-separated dir list)
  4. ``<engagement>/parsers/`` — set via `set_engagement_parser_dir`

Any file that fails to load logs a warning and is skipped — never breaks
the built-in importer surface.
"""
from __future__ import annotations

import json
import logging
import os
import re
from fnmatch import fnmatch

from ..models import Vuln


_log = logging.getLogger("recce.intake.parsers_user")

_LOADED: dict[str, dict] = {}          # name -> spec (raw, for introspection)
_SPECS: list[tuple[dict, callable]] = []  # ordered list of (spec, callable)
_ENGAGEMENT_DIR: str | None = None
_DID_LOAD = False


# ---- schema validation -------------------------------------------------------

_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_CONFIDENCES = {"confirmed", "likely", "potential", "info"}


def _validate(spec: dict, source_path: str) -> tuple[bool, str]:
    """Return (ok, reason). A failing spec is logged + skipped, never raises
    at load time — a broken user parser must not break other imports."""
    if not isinstance(spec, dict):
        return False, "top-level must be an object"
    name = spec.get("name", "")
    if not isinstance(name, str) or not re.match(r"^[a-z0-9][a-z0-9_-]{1,40}$", name, re.I):
        return False, "name must be a short kebab-case identifier"
    detect = spec.get("detect") or {}
    if not isinstance(detect, dict) or not detect:
        return False, "detect must be a non-empty object"
    if not any(k in detect for k in ("filename_glob", "content_re", "content_substr")):
        return False, "detect must have at least one of: filename_glob, content_re, content_substr"
    findings = spec.get("findings") or []
    if not isinstance(findings, list) or not findings:
        return False, "findings must be a non-empty list"
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            return False, f"findings[{i}] must be an object"
        if "marker_re" not in f:
            return False, f"findings[{i}] missing marker_re"
        try:
            compiled = re.compile(f["marker_re"], re.M)
        except re.error as e:
            return False, f"findings[{i}].marker_re bad regex: {e}"
        # A marker_re without a named `title` capture group produces zero
        # findings at parse time (the loop falls back to group(1), which
        # for reasoning-model-drafted specs is usually not the title). Reject
        # at validate time so the tester sees a specific error instead of a
        # silently-empty parser.
        if "title" not in compiled.groupindex:
            return False, (f"findings[{i}].marker_re must include a named "
                           f"capture group `(?P<title>...)` — that's how the "
                           f"finding title is extracted")
        sev = f.get("severity", "info")
        if sev not in _SEVERITIES:
            return False, f"findings[{i}].severity must be one of {sorted(_SEVERITIES)}"
        conf = f.get("confidence", "likely")
        if conf not in _CONFIDENCES:
            return False, f"findings[{i}].confidence must be one of {sorted(_CONFIDENCES)}"
    return True, ""


# ---- parser factory ----------------------------------------------------------

def _make_parser(spec: dict):
    """Turn a validated spec dict into a callable parser: text -> list[Vuln].

    Pre-compiles every regex once. `target_re` is line-anchored via re.M so
    the tester writes patterns as they see them; same for finding markers."""
    match = spec.get("match") or {}
    target_re = re.compile(match["target_re"], re.M) if match.get("target_re") else None
    port_default = match.get("port_default")
    source_label = spec.get("source") or spec["name"]
    finding_rules = []
    for f in spec["findings"]:
        finding_rules.append({
            "re": re.compile(f["marker_re"], re.M),
            "severity": f.get("severity", "info"),
            "confidence": f.get("confidence", "likely"),
            "source": f.get("source") or source_label,
            "script_id_prefix": f"user-{spec['name']}",
        })

    def parse(text: str) -> list[Vuln]:
        if not text:
            return []
        # Extract the "primary" target if a target_re is set — used as the
        # default IP for findings whose marker_re didn't capture one.
        default_ip = ""
        if target_re is not None:
            m = target_re.search(text)
            if m:
                # Prefer a named 'target' group, else the first group.
                default_ip = (m.groupdict().get("target")
                              if m.groupdict() else None) or (m.group(1) if m.groups() else "")
                # If it's a URL, strip to host
                if "://" in default_ip:
                    default_ip = default_ip.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        out: list[Vuln] = []
        for rule in finding_rules:
            for m in rule["re"].finditer(text):
                gd = m.groupdict()
                title = gd.get("title") or (m.group(1) if m.groups() else "").strip()
                if not title:
                    continue
                ip = gd.get("ip") or default_ip or spec["name"]
                port = gd.get("port")
                try:
                    port_i = int(port) if port else port_default
                except (TypeError, ValueError):
                    port_i = port_default
                cve = gd.get("cve") or ""
                extra = gd.get("output") or ""
                out.append(Vuln(
                    ip=ip, port=port_i, protocol="tcp",
                    script_id=f"{rule['script_id_prefix']}-{rule['severity']}",
                    state="finding", title=title.strip()[:120],
                    output=(extra or m.group(0))[:2000],
                    severity=rule["severity"],
                    ids=[cve.upper()] if cve else [],
                    source=rule["source"], confidence=rule["confidence"]))
        return out
    return parse


# ---- load-time discovery -----------------------------------------------------

def _load_from_dir(dir_path: str) -> int:
    """Load every valid parser file under dir_path. Returns count loaded."""
    if not os.path.isdir(dir_path):
        return 0
    n = 0
    for name in sorted(os.listdir(dir_path)):
        low = name.lower()
        path = os.path.join(dir_path, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except OSError as e:
            _log.warning("user parser %s: read failed: %s", path, e)
            continue
        spec = None
        if low.endswith(".json"):
            try:
                spec = json.loads(text)
            except ValueError as e:
                _log.warning("user parser %s: bad JSON: %s", path, e)
                continue
        elif low.endswith((".yaml", ".yml")):
            try:
                import yaml   # optional dep, only if the user has it
                spec = yaml.safe_load(text)
            except ImportError:
                _log.warning("user parser %s: PyYAML not installed; skip "
                             "(pip install pyyaml, or convert to .json)", path)
                continue
            except Exception as e:  # noqa: BLE001 — yaml can throw many things
                _log.warning("user parser %s: bad YAML: %s", path, e)
                continue
        else:
            continue
        ok, why = _validate(spec, path)
        if not ok:
            _log.warning("user parser %s: %s", path, why)
            continue
        _LOADED[spec["name"]] = spec
        _SPECS.append((spec, _make_parser(spec)))
        n += 1
    return n


def _candidate_dirs() -> list[str]:
    dirs = []
    # 1) bundled examples
    dirs.append(os.path.join(os.path.dirname(__file__), "user_parsers_bundled"))
    # 2) user config
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    dirs.append(os.path.join(xdg, "recce", "parsers"))
    dirs.append(os.path.expanduser("~/.recce/parsers"))
    # 3) env override (colon-sep list)
    env = os.environ.get("RECCE_USER_PARSERS", "")
    for d in env.split(os.pathsep):
        if d.strip():
            dirs.append(d.strip())
    # 4) engagement-local
    if _ENGAGEMENT_DIR:
        dirs.append(os.path.join(_ENGAGEMENT_DIR, "parsers"))
    # dedupe preserving order
    seen, out = set(), []
    for d in dirs:
        if d not in seen:
            seen.add(d); out.append(d)
    return out


def ensure_loaded() -> None:
    """Discover + validate + register all user parsers. Called once at
    first import; safe to call again — subsequent calls are no-ops unless
    reset() was called (e.g. from tests)."""
    global _DID_LOAD
    if _DID_LOAD:
        return
    _DID_LOAD = True
    for d in _candidate_dirs():
        n = _load_from_dir(d)
        if n:
            _log.info("recce user parsers: loaded %d from %s", n, d)


def reset() -> None:
    """Drop the load-once guard so a subsequent ensure_loaded() picks up any
    new/changed files. Test-only."""
    global _DID_LOAD
    _LOADED.clear()
    _SPECS.clear()
    _DID_LOAD = False


def set_engagement_parser_dir(path: str) -> None:
    """Configure <engagement>/parsers/ before ensure_loaded(). Idempotent."""
    global _ENGAGEMENT_DIR
    _ENGAGEMENT_DIR = path


# ---- integration -------------------------------------------------------------

def detect_user_parser(text: str, filename: str = "") -> str:
    """Sniff `text` (and `filename`) against every loaded user parser's
    `detect` block. Returns the parser name whose detect matched, or ''."""
    ensure_loaded()
    fn = (filename or "").lower()
    for spec, _fn in _SPECS:
        d = spec.get("detect") or {}
        # Cheap tests first
        if d.get("filename_glob") and fn and fnmatch(fn, d["filename_glob"].lower()):
            return spec["name"]
        substr = d.get("content_substr")
        if substr and substr.lower() in text[:8000].lower():
            # Optional regex confirmation
            if d.get("content_re"):
                try:
                    if re.search(d["content_re"], text[:8000], re.M):
                        return spec["name"]
                except re.error:
                    pass
                continue
            return spec["name"]
        if d.get("content_re") and not substr:
            try:
                if re.search(d["content_re"], text[:8000], re.M):
                    return spec["name"]
            except re.error:
                pass
    return ""


def user_parsers() -> dict:
    """{name: callable} — used by the SCANNER_PARSERS extension."""
    ensure_loaded()
    return {spec["name"]: fn for spec, fn in _SPECS}


def user_parser_specs() -> list[dict]:
    """List of loaded specs (for the ImportModal dropdown to enumerate)."""
    ensure_loaded()
    return list(_LOADED.values())


def test_spec(spec: dict, sample_text: str) -> dict:
    """Dry-run a spec against sample_text without registering it. Returns
    {ok, error?, count, sample:[{severity,title,ip,port}]}. Powers the
    Build-parser "Test" button so testers see what their parser would
    extract before saving."""
    ok, why = _validate(spec, "<test>")
    if not ok:
        return {"ok": False, "error": why, "count": 0, "sample": []}
    parser = _make_parser(spec)
    try:
        vulns = parser(sample_text)
    except Exception as e:  # noqa: BLE001 — return diagnostic, don't raise
        return {"ok": False, "error": f"parse crashed: {e}", "count": 0, "sample": []}
    return {"ok": True, "count": len(vulns),
            "sample": [{"severity": v.severity, "title": v.title,
                        "ip": v.ip, "port": v.port} for v in vulns[:10]]}


def save_spec_to_engagement(spec: dict, eng_dir: str) -> tuple[bool, str]:
    """Persist a user-authored parser to <engagement>/parsers/<name>.json
    and refresh the loader so it's live immediately. Returns (ok, path or error)."""
    ok, why = _validate(spec, "<save>")
    if not ok:
        return False, why
    import json as _json
    parsers_dir = os.path.join(eng_dir, "parsers")
    os.makedirs(parsers_dir, exist_ok=True)
    name = spec["name"]
    path = os.path.join(parsers_dir, f"{name}.json")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            _json.dump(spec, fh, indent=2, ensure_ascii=False)
    except OSError as e:
        return False, f"write failed: {e}"
    return True, path


def delete_spec_from_engagement(name: str, eng_dir: str) -> bool:
    """Remove a user parser file from <engagement>/parsers/. Returns True if
    a file was removed. Caller is expected to refresh() afterwards."""
    if not re.match(r"^[a-z0-9][a-z0-9_-]{1,40}$", name, re.I):
        return False
    path = os.path.join(eng_dir, "parsers", f"{name}.json")
    if not os.path.isfile(path):
        return False
    try:
        os.remove(path)
        return True
    except OSError:
        return False
