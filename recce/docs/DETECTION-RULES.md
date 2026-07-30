# Custom detection rules (data-driven detection)

> SOTA roadmap Stage 6. Add or override version→CVE detections as **data**, no Python.
> Load with `recce run|enum|vulns|scan --rules FILE`.

recce's built-in knowledge base (`recce/vulndb.py` `SIGNATURES`) matches the product +
version data `enum` collected against a curated CVE set. You can extend or override it with
a JSON rule file — the airgap-friendly, stdlib-only form of a Nuclei-style template.

## Format

A JSON object with a `rules` list (or a bare list). Each rule mirrors a built-in signature:

```json
{
  "rules": [
    {
      "product": ["acmeapp", "acme app"],      // whole-token product/service match (any)
      "ge": "1.0", "lt": "2.4.1",               // version range: eq | lt | le | ge | gt
      "absent": ["ubuntu", "debian", "+deb"],   // NEGATIVE matcher: skip if the banner
                                                //   contains any of these (decoys / distro
                                                //   backports) — the main FP reducer
      "severity": "high",                        // critical | high | medium | low | info
      "title": "AcmeApp < 2.4.1 auth bypass",   // also the dedupe key
      "cves": ["CVE-2024-99999"],
      "cwe": ["CWE-287"],
      "remediation": "Upgrade AcmeApp to 2.4.1+.",
      "desc": "What/why for the operator.",
      "os": "windows",                           // optional OS gate
      "advisory": true                           // product-only lead (confidence "potential")
    }
  ]
}
```

Fields (all optional except `product` + `title`):

| Field | Meaning |
|---|---|
| `product` | list of whole-token substrings matched against `product`/`service` (any matches) |
| `eq` / `lt` / `le` / `ge` / `gt` | version bounds (omit all → a product-only advisory) |
| **`absent`** | **negative matcher** — the rule does NOT fire if the banner (product/service/version/extrainfo) contains any of these. Use it to exclude decoys or distro-backported builds. |
| `os` / `os_lt` / `dc_only` | gate to an OS / OS-version / a domain controller |
| `severity` | CVSS-ish bucket (defaults to `medium`) |
| `title` / `cves` / `cwe` / `remediation` / `desc` | the finding |
| `advisory` | `true` → product-only informational lead (QoD "potential", hidden below the default filter) |

## Behavior

- Rules are **merged** into the built-ins for the run (they don't replace them).
- A version match still flows through the whole pipeline: QoD scoring, distro-backport
  downgrade, dedup, refutation, KEV/EPSS prioritization, and the honest tiering.
- A malformed rule or file is **skipped, never fatal** — a bad rule can't break a scan.

## Example

```
recce run 10.0.0.0/24 -o eng --rules my-appliance-cves.json
```

Loads your rules, prints how many were added, then scans with them in effect.
