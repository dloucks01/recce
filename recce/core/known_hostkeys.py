"""Cross-service "host keys known to this engagement" reader.

Every service that presents a stable public host key — SSH (RFC 4253 §4.1),
IPsec IKE RSA/ECDSA auth, cloud instance-metadata identity documents, and
in principle any TLS server (its cert public key is a hostkey too) — lands
its SHA256 fingerprint here. The fingerprint format matches the string
`ssh-keygen -l -E sha256` prints ("SHA256:" + unpadded base64 of the raw
key material's SHA-256 digest, RFC 4253 §6.6 wire encoding), which is what
every SSH client displays and what every hostkey pin is compared against.

Producers today:
  * `recce/services/ssh.py` — one DH group14 KEX per host captures K_S and
    computes `fp_sha256` in `probe()` -> `hostkey_capture`

Consumers (this pass ships the reader only; consumers are follow-up):
  * SSH — emit `hostkey_reuse` when one fingerprint appears on >=2 IPs
    (golden-image clone, MitM baseline drift, VM template stamp)
  * cloud metadata — correlate an instance's identity document key with
    the SSH host key of the peer to prove same-instance
  * enip / mac — hardware-anchored serial correlation

The reader never invents fingerprints — producers must call
`record_hostkey()` at capture time. Base64 is case-SENSITIVE (`ABcd` and
`abcd` are different bytes), so unlike DNS names the fingerprint string
is compared verbatim; `key_type` is lower-cased for the display pair only
because SSH algorithm names are lower-case ASCII per RFC 4250 §4.11.
"""
from __future__ import annotations

from .models import Host


def _norm_fp(fp: str) -> str:
    """Trim whitespace only — SHA256 fingerprints are case-sensitive
    base64 with a literal `SHA256:` prefix."""
    return (fp or "").strip()


def record_hostkey(host: Host, ip: str, port: int, fingerprint_sha256: str,
                   key_type: str = "", source: str = "") -> None:
    """Attach one captured fingerprint to `host` for later correlation.

    Idempotent per (fingerprint, port) — a re-probe against the same
    endpoint records only once. Silently drops empty fingerprints so
    callers don't have to guard the "probe returned no hostkey_capture"
    path.
    """
    fp = _norm_fp(fingerprint_sha256)
    if host is None or not fp:
        return
    existing = getattr(host, "hostkeys", None)
    if existing is None:
        existing = []
        # Dataclass instance without __slots__ — arbitrary attr assignment
        # is fine. Won't survive `to_json`/`from_json` roundtrip; this is a
        # live in-session correlator, not a persisted fact.
        object.__setattr__(host, "hostkeys", existing)
    for e in existing:
        if e.get("fp") == fp and int(e.get("port", 0)) == int(port):
            return
    existing.append({"ip": ip or getattr(host, "ip", "") or "",
                     "port": int(port), "fp": fp,
                     "key_type": (key_type or "").strip().lower(),
                     "source": source or ""})


def hostkeys_for(host: Host) -> list[dict]:
    """Every hostkey recorded against `host`, first-seen order.

    Returned entries are copies so a consumer mutating them can't corrupt
    the store.
    """
    return [dict(e) for e in (getattr(host, "hostkeys", None) or [])]


def known_hostkeys(hosts: list[Host]) -> dict:
    """Engagement-wide fingerprint correlation.

    Returns:
      {"by_fingerprint": {sha256: ["ip:port", ...]},
       "by_ip":          {ip: [(fingerprint, key_type), ...]},
       "reused":         [{"fingerprint": sha256,
                           "key_type": str,
                           "ips": [ip, ...],
                           "endpoints": ["ip:port", ...]}]}

    `reused` groups only fingerprints observed on >=2 DISTINCT IPs (two
    ports on the same host share the same key by construction and are not
    a reuse finding).
    """
    by_fp: dict[str, list[str]] = {}
    by_ip: dict[str, list[tuple[str, str]]] = {}
    fp_types: dict[str, str] = {}
    fp_ips: dict[str, list[str]] = {}
    for h in hosts:
        for hk in hostkeys_for(h):
            fp = hk.get("fp") or ""
            if not fp:
                continue
            ip = hk.get("ip") or getattr(h, "ip", "") or ""
            port = int(hk.get("port") or 0)
            kt = hk.get("key_type") or ""
            endpoint = f"{ip}:{port}"
            endpoints = by_fp.setdefault(fp, [])
            if endpoint not in endpoints:
                endpoints.append(endpoint)
            ips = fp_ips.setdefault(fp, [])
            if ip and ip not in ips:
                ips.append(ip)
            if fp not in fp_types and kt:
                fp_types[fp] = kt
            pair = (fp, kt)
            pairs = by_ip.setdefault(ip, [])
            if pair not in pairs:
                pairs.append(pair)
    reused = [{"fingerprint": fp,
               "key_type": fp_types.get(fp, ""),
               "ips": fp_ips[fp],
               "endpoints": by_fp[fp]}
              for fp in by_fp
              if len(fp_ips.get(fp, [])) >= 2]
    return {"by_fingerprint": by_fp, "by_ip": by_ip, "reused": reused}
