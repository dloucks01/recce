# User parsers (Phase 2)

Declarative parsers that recce loads at startup. Drop a `.json` (or `.yaml`
if you have PyYAML) file into any of these directories and it registers as
a new parser under its `name`, available in the ImportModal dropdown and
`SCANNER_PARSERS[name]`:

1. `~/.config/recce/parsers/` (XDG) or `~/.recce/parsers/`
2. `$RECCE_USER_PARSERS` (env var; colon-separated list of dirs)
3. `<engagement>/parsers/` — travels with the engagement dir

Later locations override earlier ones (engagement-local wins).

## Schema

See `example-scanner.json` for a fully annotated template. The minimum:

```json
{
  "name": "my-scanner",
  "detect": { "filename_glob": "*.myss" },
  "findings": [
    { "marker_re": "^\\[CRIT\\]\\s+(?P<title>.+)$", "severity": "critical" }
  ]
}
```

Named regex groups understood in `marker_re`:
- `title` — required. What the finding is called.
- `ip` — host to attach to (else `match.target_re` extracts it, else the
  parser's `name` is used as a synthetic host).
- `port` — else `match.port_default`.
- `cve` — a CVE-YYYY-NNNN string attaches to the finding's IDs.
- `output` — the raw evidence (else the whole matched line is used).

All regexes compile once at load time. Broken files log a warning and are
skipped — a bad user parser never breaks the built-in importers.

## Iterating

`ensure_loaded()` runs once per process — restart `recce serve` (or call
`recce.intake.parsers_user.reset()` from a test) to pick up edits.
