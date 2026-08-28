# Custom detection rules

Add or override version-to-CVE detections as data, no Python. Load with `--rules FILE`.

## Format

A JSON object with a `rules` list. Each rule mirrors a built-in signature:

```json
{
  "rules": [
    {
      "product": ["acmeapp", "acme app"],
      "ge": "1.0", "lt": "2.4.1",
      "absent": ["ubuntu", "debian", "+deb"],
      "severity": "high",
      "title": "AcmeApp < 2.4.1 auth bypass",
      "cves": ["CVE-2024-99999"],
      "cwe": ["CWE-287"],
      "remediation": "Upgrade AcmeApp to 2.4.1+."
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `product` | List of substrings matched against product/service (any matches). Required. |
| `eq`/`lt`/`le`/`ge`/`gt` | Version bounds. Omit all for a product-only advisory. |
| `absent` | Negative matcher — rule skips if banner contains any of these (distro backports). |
| `os`/`os_lt`/`dc_only` | Gate to an OS / OS version / domain controller. |
| `severity` | critical / high / medium / low / info (default: medium). |
| `title`/`cves`/`cwe`/`remediation`/`desc` | The finding. `title` required. |
| `advisory` | `true` for product-only informational leads (QoD "potential"). |

Rules are merged into the built-ins, flow through the full pipeline (QoD, dedup, KEV/EPSS), and a malformed rule is skipped, never fatal.

```bash
recce run 10.0.0.0/24 -o eng --rules my-appliance-cves.json
```
