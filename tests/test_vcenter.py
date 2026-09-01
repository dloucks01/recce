"""Tests for recce.services.vsphere — /sdk SOAP probe + inventory."""
from __future__ import annotations

import unittest
from unittest import mock

from recce.core.models import Host, Port
from recce.services import vsphere


# --- wire-derived SOAP fixtures ------------------------------------------------
# The bodies below are shaped exactly like the vSphere API 8.0 documented
# responses (soap-envelope + urn:vim25 payload), captured from a lab vCenter
# and an ESXi host and reduced to the fields the parser reads.

VCENTER_SC = b"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
 <soapenv:Body>
  <RetrieveServiceContentResponse xmlns="urn:vim25">
   <returnval>
    <rootFolder type="Folder">group-d1</rootFolder>
    <propertyCollector type="PropertyCollector">propertyCollector</propertyCollector>
    <sessionManager type="SessionManager">SessionManager</sessionManager>
    <about>
     <name>VMware vCenter Server</name>
     <fullName>VMware vCenter Server 7.0.3 build-19717403</fullName>
     <vendor>VMware, Inc.</vendor>
     <version>7.0.3</version>
     <build>19717403</build>
     <localeVersion>INTL</localeVersion>
     <localeBuild>000</localeBuild>
     <osType>linux-x64</osType>
     <productLineId>vpx</productLineId>
     <apiType>VirtualCenter</apiType>
     <apiVersion>7.0.3.0</apiVersion>
     <instanceUuid>a9c6d1b3-9c1e-4a2c-8f22-1cf0c7f5f4a1</instanceUuid>
     <licenseProductName>VMware VirtualCenter Server</licenseProductName>
     <licenseProductVersion>7.0</licenseProductVersion>
    </about>
   </returnval>
  </RetrieveServiceContentResponse>
 </soapenv:Body>
</soapenv:Envelope>"""


ESXI_SC = b"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Body>
  <RetrieveServiceContentResponse xmlns="urn:vim25">
   <returnval>
    <about>
     <name>VMware ESXi</name>
     <fullName>VMware ESXi 7.0.3 build-19193900</fullName>
     <vendor>VMware, Inc.</vendor>
     <version>7.0.3</version>
     <build>19193900</build>
     <osType>vmnix-x86</osType>
     <productLineId>embeddedEsx</productLineId>
     <apiType>HostAgent</apiType>
     <apiVersion>7.0.3.0</apiVersion>
     <instanceUuid></instanceUuid>
     <licenseProductName>VMware ESX Server</licenseProductName>
    </about>
   </returnval>
  </RetrieveServiceContentResponse>
 </soapenv:Body>
</soapenv:Envelope>"""


LOGIN_OK = b"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Body>
  <LoginResponse xmlns="urn:vim25">
   <returnval>
    <key>52fa9c23-1234-abcd-5678-9abcdef01234</key>
    <userName>administrator@vsphere.local</userName>
    <fullName>Administrator vsphere.local</fullName>
    <loginTime>2026-08-01T09:00:00Z</loginTime>
    <lastActiveTime>2026-08-01T09:00:00Z</lastActiveTime>
    <locale>en</locale>
    <messageLocale>en</messageLocale>
    <extensionKey></extensionKey>
    <ipAddress>10.0.0.42</ipAddress>
    <userAgent>recce-vsphere/1.0</userAgent>
    <callCount>1</callCount>
   </returnval>
  </LoginResponse>
 </soapenv:Body>
</soapenv:Envelope>"""


LOGIN_FAIL = b"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Body>
  <soapenv:Fault>
   <faultcode>ServerFaultCode</faultcode>
   <faultstring>Cannot complete login due to an incorrect user name or password.</faultstring>
   <detail>
    <InvalidLoginFault xmlns="urn:vim25"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:type="InvalidLogin"/>
   </detail>
  </soapenv:Fault>
 </soapenv:Body>
</soapenv:Envelope>"""


SESSION_LIST = b"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Body>
  <SessionListResponse xmlns="urn:vim25">
   <returnval>
    <key>aaaa</key><userName>alice@vsphere.local</userName>
    <ipAddress>10.0.0.11</ipAddress><userAgent>PowerCLI</userAgent>
    <loginTime>2026-08-01T08:00:00Z</loginTime>
    <lastActiveTime>2026-08-01T09:00:00Z</lastActiveTime>
    <callCount>42</callCount>
   </returnval>
   <returnval>
    <key>bbbb</key><userName>svc_backup@corp.local</userName>
    <ipAddress>10.0.0.99</ipAddress><userAgent>veeam</userAgent>
    <loginTime>2026-08-01T07:00:00Z</loginTime>
    <lastActiveTime>2026-08-01T09:01:00Z</lastActiveTime>
    <callCount>1200</callCount>
   </returnval>
  </SessionListResponse>
 </soapenv:Body>
</soapenv:Envelope>"""


HOSTSYSTEMS = b"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Body>
  <RetrievePropertiesExResponse xmlns="urn:vim25">
   <returnval>
    <objects>
     <obj type="HostSystem">host-9</obj>
     <propSet><name>name</name><val xsi:type="xsd:string"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
       xmlns:xsd="http://www.w3.org/2001/XMLSchema">esx01.corp.local</val></propSet>
     <propSet><name>config.product.build</name><val>19193900</val></propSet>
     <propSet><name>summary.managementServerIp</name><val>10.0.0.5</val></propSet>
    </objects>
    <objects>
     <obj type="HostSystem">host-12</obj>
     <propSet><name>name</name><val>esx02.corp.local</val></propSet>
     <propSet><name>summary.managementServerIp</name><val>10.0.0.7</val></propSet>
    </objects>
   </returnval>
  </RetrievePropertiesExResponse>
 </soapenv:Body>
</soapenv:Envelope>"""


VMS = b"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Body>
  <RetrievePropertiesExResponse xmlns="urn:vim25">
   <returnval>
    <objects>
     <obj type="VirtualMachine">vm-101</obj>
     <propSet><name>name</name><val>dc01</val></propSet>
     <propSet><name>guest.hostName</name><val>dc01.corp.local</val></propSet>
     <propSet><name>guest.ipAddress</name><val>10.0.0.10</val></propSet>
     <propSet><name>runtime.powerState</name><val>poweredOn</val></propSet>
    </objects>
   </returnval>
  </RetrievePropertiesExResponse>
 </soapenv:Body>
</soapenv:Envelope>"""


LOCAL_USERS = b"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Body>
  <RetrieveUserGroupsResponse xmlns="urn:vim25">
   <returnval xsi:type="HostAccountSpec"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <principal>root</principal><fullName>root</fullName>
   </returnval>
   <returnval xsi:type="HostAccountSpec"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <principal>dcui</principal><fullName>DCUI User</fullName>
   </returnval>
   <returnval xsi:type="HostAccountSpec"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <principal>vpxuser</principal><fullName>VMware VirtualCenter</fullName>
   </returnval>
  </RetrieveUserGroupsResponse>
 </soapenv:Body>
</soapenv:Envelope>"""


class FingerprintTests(unittest.TestCase):
    def test_parse_vcenter_service_content(self):
        parsed = vsphere._parse_service_content(VCENTER_SC)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["api_type"], "VirtualCenter")
        self.assertEqual(parsed["version"], "7.0.3")
        self.assertEqual(parsed["build"], "19717403")
        self.assertEqual(parsed["vendor"], "VMware, Inc.")
        self.assertIn("vCenter", parsed["full_name"])
        self.assertEqual(parsed["instance_uuid"],
                         "a9c6d1b3-9c1e-4a2c-8f22-1cf0c7f5f4a1")

    def test_parse_esxi_service_content(self):
        parsed = vsphere._parse_service_content(ESXI_SC)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["api_type"], "HostAgent")
        self.assertEqual(parsed["build"], "19193900")

    def test_parse_service_content_rejects_junk(self):
        self.assertIsNone(vsphere._parse_service_content(b"not xml"))
        self.assertIsNone(vsphere._parse_service_content(b"<root/>"))


class BuildCveMapTests(unittest.TestCase):
    def test_vcenter_7_below_2023_34048_matches(self):
        hits = vsphere.build_cves("VirtualCenter", "7.0.3", "19717403")
        cves = {h["cve"] for h in hits}
        # 7.0 patch build for 21985 is 17920168, for 22005 is 18356314, for
        # 2023-34048 is 22357613. 19717403 is above 21985/22005 fix but below
        # the 2023-34048 fix.
        self.assertIn("CVE-2023-34048", cves)
        self.assertNotIn("CVE-2021-21985", cves)
        self.assertNotIn("CVE-2021-22005", cves)

    def test_vcenter_7_ancient_matches_all(self):
        hits = vsphere.build_cves("VirtualCenter", "7.0.0", "16749653")
        cves = {h["cve"] for h in hits}
        self.assertIn("CVE-2021-21985", cves)
        self.assertIn("CVE-2021-22005", cves)
        self.assertIn("CVE-2023-34048", cves)

    def test_patched_vcenter_no_hits(self):
        hits = vsphere.build_cves("VirtualCenter", "8.0.2", "22385740")
        self.assertEqual(hits, [])

    def test_esxi_never_matches_vcenter_cves(self):
        # HostAgent must not pick up vCenter-only CVEs even at ancient builds.
        # (HostAgent-scoped CVEs, e.g. 2024-37085, may still match.)
        hits = vsphere.build_cves("HostAgent", "7.0.3", "1")
        cves = {h["cve"] for h in hits}
        for vc_only in ("CVE-2021-21985", "CVE-2021-22005", "CVE-2023-34048"):
            self.assertNotIn(vc_only, cves)

    def test_unparseable_build_never_cites_cve(self):
        self.assertEqual(
            vsphere.build_cves("VirtualCenter", "7.0", ""), [])
        self.assertEqual(
            vsphere.build_cves("VirtualCenter", "7.0", "unknown"), [])


class SessionParsingTests(unittest.TestCase):
    def test_login_ok(self):
        sess = vsphere._parse_user_session(LOGIN_OK)
        self.assertIsNotNone(sess)
        self.assertEqual(sess["user_name"], "administrator@vsphere.local")
        self.assertTrue(sess["key"].startswith("52fa9c23"))

    def test_login_fault_detected(self):
        self.assertTrue(vsphere._is_soap_fault(LOGIN_FAIL))
        reason = vsphere._fault_reason(LOGIN_FAIL)
        self.assertIn("incorrect", reason.lower())

    def test_session_list_parses(self):
        sess = vsphere._parse_session_list(SESSION_LIST)
        self.assertEqual(len(sess), 2)
        users = sorted(s["user_name"] for s in sess)
        self.assertIn("alice@vsphere.local", users)
        self.assertIn("svc_backup@corp.local", users)
        ips = sorted(s["ip_address"] for s in sess)
        self.assertEqual(ips, ["10.0.0.11", "10.0.0.99"])


class InventoryParsingTests(unittest.TestCase):
    def test_hostsystems(self):
        objs = vsphere._parse_property_objects(HOSTSYSTEMS)
        self.assertEqual(len(objs), 2)
        self.assertEqual(objs[0]["type"], "HostSystem")
        self.assertEqual(objs[0]["props"]["name"], "esx01.corp.local")
        peers = vsphere._linked_vcenters(objs)
        self.assertEqual(peers, ["10.0.0.5", "10.0.0.7"])

    def test_vms(self):
        objs = vsphere._parse_property_objects(VMS)
        self.assertEqual(len(objs), 1)
        self.assertEqual(objs[0]["props"]["guest.hostName"], "dc01.corp.local")
        self.assertEqual(objs[0]["props"]["runtime.powerState"], "poweredOn")

    def test_local_users(self):
        us = vsphere._parse_local_accounts(LOCAL_USERS)
        principals = sorted(u["principal"] for u in us)
        self.assertEqual(principals, ["dcui", "root", "vpxuser"])


class SsoDomainTests(unittest.TestCase):
    def test_sso_domain_from_full_name(self):
        parsed = {"full_name": "VMware vCenter administrator@vsphere.local"}
        self.assertEqual(vsphere._extract_sso_domain(parsed, {}), "vsphere.local")

    def test_sso_domain_from_cert_cn(self):
        parsed = {"full_name": "VMware vCenter Server 7.0.3"}
        cert = {"cn": "vcsa01.corp.local", "sans": []}
        # cn suffix heuristic — last two labels.
        self.assertEqual(vsphere._extract_sso_domain(parsed, cert), "corp.local")


class IsVsphereTests(unittest.TestCase):
    def test_port_443_is_candidate(self):
        p = Port(portid=443, state="open")
        self.assertTrue(vsphere.is_vsphere(p))

    def test_hostd_agent_902_is_candidate(self):
        self.assertTrue(vsphere.is_vsphere(Port(portid=902, state="open")))

    def test_vmware_banner_hits(self):
        p = Port(portid=8443, state="open",
                 banner="Server: VMware/1.0 ID_VC_Welcome")
        self.assertTrue(vsphere.is_vsphere(p))

    def test_closed_port_is_rejected(self):
        self.assertFalse(vsphere.is_vsphere(Port(portid=443, state="closed")))

    def test_role_labels(self):
        self.assertEqual(vsphere.role(443), "sdk")
        self.assertEqual(vsphere.role(902), "hostd-agent")
        self.assertEqual(vsphere.role(5480), "vami")
        self.assertEqual(vsphere.role(9443), "vsphere-client")


class ProbeTests(unittest.TestCase):
    """Drive vsphere.probe() with a scripted transport."""

    def _install_scripted_transport(self, script, sc_body=VCENTER_SC):
        """Return a mock that answers _post_soap in the order given by `script`.

        `script` is a list of (status, body, set_cookie) tuples consumed in
        order. The first RetrieveServiceContent POST is answered from `sc_body`
        automatically so tests only script the follow-on calls.
        """
        calls = []
        queue = list(script)

        def fake_post(ip, port, body, action="", timeout=vsphere._TIMEOUT,
                       cookie=""):
            calls.append({"body": body, "cookie": cookie})
            if b"RetrieveServiceContent" in body:
                return 200, sc_body, ""
            # T2 SessionManager pre-auth reachability probe: identified by the
            # synthetic canary UPN. Auto-answer so scripted queues stay aligned
            # with the credentialed calls the tests care about.
            if vsphere._T2_CANARY_USER.encode() in body:
                return 200, LOGIN_FAIL, ""
            if not queue:
                return None
            return queue.pop(0)

        return fake_post, calls

    def test_passive_fingerprint_no_auth(self):
        fake_post, _ = self._install_scripted_transport([])
        with mock.patch.object(vsphere, "_post_soap", fake_post), \
             mock.patch.object(vsphere, "_http_get", return_value=None), \
             mock.patch.object(vsphere, "_cert_san",
                               return_value={"cn": "", "sans": []}):
            out = vsphere.probe("10.0.0.5", 443, active_auth=False)
        self.assertTrue(out["sdk"])
        self.assertEqual(out["api_type"], "VirtualCenter")
        self.assertEqual(out["build"], "19717403")
        self.assertIn("CVE-2023-34048", {c["cve"] for c in out["cves"]})
        self.assertNotIn("login", out)

    def test_login_success_drives_full_credentialed_flow(self):
        script = [
            # SessionManager.Login for administrator@vsphere.local:VMware1!
            (200, LOGIN_OK, "vmware_soap_session=abcd1234; Path=/; HttpOnly"),
            # SessionList
            (200, SESSION_LIST, ""),
            # HostSystem PropertyCollector
            (200, HOSTSYSTEMS, ""),
            # VirtualMachine PropertyCollector
            (200, VMS, ""),
        ]
        fake_post, calls = self._install_scripted_transport(script)
        with mock.patch.object(vsphere, "_post_soap", fake_post), \
             mock.patch.object(vsphere, "_http_get", return_value=None), \
             mock.patch.object(vsphere, "_cert_san",
                               return_value={"cn": "vcsa.corp.local",
                                             "sans": ["vcsa.corp.local"]}):
            out = vsphere.probe("10.0.0.5", 443, active_auth=True)
        self.assertTrue(out["login"]["success"])
        self.assertEqual(out["login"]["user"], "administrator@vsphere.local")
        self.assertEqual(out["login"]["cookie"], "vmware_soap_session=abcd1234")
        self.assertEqual(len(out["sessions"]), 2)
        self.assertEqual(len(out["managed_hosts"]), 2)
        self.assertEqual(len(out["managed_vms"]), 1)
        self.assertEqual(out["linked_vcenters"], ["10.0.0.5", "10.0.0.7"])
        # Follow-on calls (SessionList / inventory) must carry the session
        # cookie the Login response returned; the Login POST itself does not.
        followon = [c for c in calls
                    if b"RetrieveServiceContent" not in c["body"]
                    and b"<Login " not in c["body"]]
        self.assertTrue(followon)
        for c in followon:
            self.assertEqual(c["cookie"], "vmware_soap_session=abcd1234")

    def test_login_all_defaults_fail(self):
        # Every login attempt returns a SOAP fault -> login["success"] False,
        # and no follow-on inventory / session-list calls fire.
        def always_fault(ip, port, body, action="", timeout=vsphere._TIMEOUT,
                        cookie=""):
            if b"RetrieveServiceContent" in body:
                return 200, VCENTER_SC, ""
            return 200, LOGIN_FAIL, ""

        with mock.patch.object(vsphere, "_post_soap", always_fault), \
             mock.patch.object(vsphere, "_http_get", return_value=None), \
             mock.patch.object(vsphere, "_cert_san",
                               return_value={"cn": "", "sans": []}):
            out = vsphere.probe("10.0.0.5", 443, active_auth=True)
        self.assertFalse(out["login"]["success"])
        self.assertNotIn("sessions", out)
        self.assertNotIn("managed_hosts", out)

    def test_esxi_credentialed_flow_hits_local_accounts(self):
        script = [
            (200, LOGIN_OK, "vmware_soap_session=deadbeef; Path=/"),
            (200, SESSION_LIST, ""),
            (200, LOCAL_USERS, ""),
        ]
        fake_post, calls = self._install_scripted_transport(script, sc_body=ESXI_SC)
        with mock.patch.object(vsphere, "_post_soap", fake_post), \
             mock.patch.object(vsphere, "_http_get", return_value=None), \
             mock.patch.object(vsphere, "_cert_san",
                               return_value={"cn": "", "sans": []}):
            out = vsphere.probe("10.0.0.5", 443, active_auth=True)
        self.assertTrue(out["login"]["success"])
        self.assertEqual(out["api_type"], "HostAgent")
        self.assertEqual({u["principal"] for u in out["local_users"]},
                         {"root", "dcui", "vpxuser"})
        # No HostSystem/VirtualMachine calls for ESXi (they'd be redundant).
        auth_bodies = [c["body"] for c in calls
                       if b"RetrieveServiceContent" not in c["body"]]
        self.assertFalse(any(b"HostSystem" in b for b in auth_bodies))

    def test_probe_returns_none_when_sdk_unreachable(self):
        with mock.patch.object(vsphere, "_post_soap", return_value=None), \
             mock.patch.object(vsphere, "_http_get", return_value=None), \
             mock.patch.object(vsphere, "_cert_san",
                               return_value={"cn": "", "sans": []}):
            out = vsphere.probe("10.0.0.5", 443, active_auth=False)
        self.assertIsNone(out)


class FindingsTests(unittest.TestCase):
    def _host_with_port(self, ip="10.0.0.5", ports=(443,)):
        h = Host(ip=ip)
        for p in ports:
            h.ports.append(Port(portid=p, state="open", service="https"))
        return h

    def test_findings_emit_fingerprint_and_outdated_build(self):
        h = self._host_with_port()
        pr = {
            "ip": h.ip, "port": 443, "role": "sdk", "reachable": True, "sdk": True,
            "api_type": "VirtualCenter", "version": "7.0.3",
            "build": "19717403", "full_name": "VMware vCenter 7.0.3",
            "instance_uuid": "abc", "cves": vsphere.build_cves(
                "VirtualCenter", "7.0.3", "19717403"),
            "cert": {"cn": "vcsa.corp.local", "sans": ["vcsa.corp.local"]},
            "sso_domain": "corp.local",
        }
        fs = vsphere.findings([h], {(h.ip, 443): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("vsphere_fingerprint", kinds)
        self.assertIn("vsphere_outdated_build", kinds)
        self.assertIn("vsphere_sso_domain", kinds)
        self.assertIn("vsphere_cert", kinds)
        outdated = next(f for f in fs if f["kind"] == "vsphere_outdated_build")
        self.assertEqual(outdated["severity"], "critical")
        self.assertIn("CVE-2023-34048", outdated["title"])

    def test_valid_creds_finding_and_session_finding(self):
        h = self._host_with_port()
        pr = {
            "ip": h.ip, "port": 443, "role": "sdk", "reachable": True, "sdk": True,
            "api_type": "VirtualCenter", "version": "8.0.2", "build": "22385740",
            "full_name": "VMware vCenter 8.0.2", "instance_uuid": "z",
            "cves": [],
            "cert": {"cn": "", "sans": []},
            "login": {"success": True, "user": "administrator@vsphere.local",
                      "cookie": "vmware_soap_session=xx", "attempts": 1},
            "sessions": vsphere._parse_session_list(SESSION_LIST),
            "managed_hosts": vsphere._parse_property_objects(HOSTSYSTEMS),
            "managed_vms": vsphere._parse_property_objects(VMS),
            "linked_vcenters": ["10.0.0.5", "10.0.0.7"],
        }
        fs = vsphere.findings([h], {(h.ip, 443): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("vsphere_valid_creds", kinds)
        self.assertIn("vsphere_sessions", kinds)
        self.assertIn("vsphere_inventory", kinds)
        self.assertIn("vsphere_linked", kinds)
        # No outdated-build finding on the patched build.
        self.assertNotIn("vsphere_outdated_build", kinds)

    def test_vami_adjacent_finding(self):
        h = self._host_with_port(ports=(443, 5480))
        pr = {"ip": h.ip, "port": 443, "role": "sdk", "reachable": True,
              "sdk": True, "api_type": "VirtualCenter", "version": "8.0",
              "build": "22385740", "cves": [], "cert": {"cn": "", "sans": []}}
        fs = vsphere.findings([h], {(h.ip, 443): pr})
        self.assertIn("vsphere_vami", {f["kind"] for f in fs})

    def test_cve_21985_gets_dedicated_row(self):
        h = self._host_with_port()
        pr = {
            "ip": h.ip, "port": 443, "role": "sdk", "reachable": True,
            "sdk": True, "api_type": "VirtualCenter", "version": "6.7.0",
            "build": "1", "cves": vsphere.build_cves(
                "VirtualCenter", "6.7.0", "1"),
            "cert": {"cn": "", "sans": []},
        }
        fs = vsphere.findings([h], {(h.ip, 443): pr})
        self.assertIn("vsphere_cve_2021_21985", {f["kind"] for f in fs})


class AnalyzeTests(unittest.TestCase):
    def test_analyze_maps_targets_and_findings(self):
        h = Host(ip="10.0.0.5")
        h.ports.append(Port(portid=443, state="open", service="https"))

        def fake_probe(ip, port, creds=None, active_auth=False):
            return {
                "ip": ip, "port": port, "role": "sdk", "reachable": True,
                "sdk": True, "api_type": "VirtualCenter", "version": "7.0.3",
                "build": "19717403", "full_name": "VMware vCenter",
                "instance_uuid": "u",
                "cves": vsphere.build_cves("VirtualCenter", "7.0.3", "19717403"),
                "cert": {"cn": "vcsa.corp.local", "sans": []},
                "sso_domain": "corp.local",
                "login": {"success": False, "attempts": 3},
            }

        with mock.patch.object(vsphere, "probe", side_effect=fake_probe):
            res = vsphere.analyze([h], active=True)
        self.assertEqual(res["stats"]["targets"], 1)
        self.assertGreater(res["stats"]["findings"], 0)
        self.assertEqual(res["targets"][0]["cve_hits"], ["CVE-2023-34048"])


class FindingsToVulnsTests(unittest.TestCase):
    def test_findings_to_vulns_shape(self):
        fs = [{
            "category": "vsphere", "severity": "critical",
            "title": "vSphere valid credentials accepted",
            "target": "10.0.0.5:443",
            "detail": "SessionManager.Login accepted user 'administrator@vsphere.local'",
            "tool": "govc", "command": "govc about",
            "remediation": "rotate creds", "cwes": ["CWE-287"],
            "kind": "vsphere_valid_creds", "narrative": "x",
        }]
        by_ip = vsphere.findings_to_vulns(fs)
        self.assertIn("10.0.0.5", by_ip)
        v = by_ip["10.0.0.5"][0]
        self.assertEqual(v.source, "vsphere")
        self.assertEqual(v.port, 443)
        self.assertTrue(v.script_id.startswith("vsphere:"))


# --- CVE-2024-37085 (ESXi 'ESX Admins' AD auto-promote priv-esc) --------------

# Wire-derived AboutInfo for an unpatched ESXi 7.0 U3o (build 22348816 <
# 23794027 which is the VMSA-2024-0013 fix). Reduced from a lab capture.
ESXI_7U3O_SC = b"""<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
 <soapenv:Body>
  <RetrieveServiceContentResponse xmlns="urn:vim25">
   <returnval>
    <about>
     <name>VMware ESXi</name>
     <fullName>VMware ESXi 7.0.3 build-22348816</fullName>
     <vendor>VMware, Inc.</vendor>
     <version>7.0.3</version>
     <build>22348816</build>
     <apiType>HostAgent</apiType>
     <apiVersion>7.0.3.0</apiVersion>
    </about>
   </returnval>
  </RetrieveServiceContentResponse>
 </soapenv:Body>
</soapenv:Envelope>"""


class Cve202437085Tests(unittest.TestCase):
    def test_unpatched_esxi_7_matches(self):
        hits = vsphere.build_cves("HostAgent", "7.0.3", "22348816")
        self.assertIn("CVE-2024-37085", {h["cve"] for h in hits})

    def test_unpatched_esxi_8_matches(self):
        hits = vsphere.build_cves("HostAgent", "8.0.2", "22380479")
        self.assertIn("CVE-2024-37085", {h["cve"] for h in hits})

    def test_patched_esxi_7_u3q_clears(self):
        # 7.0 U3q fixed build = 23794027; boundary must NOT fire.
        hits = vsphere.build_cves("HostAgent", "7.0.3", "23794027")
        self.assertNotIn("CVE-2024-37085", {h["cve"] for h in hits})

    def test_patched_esxi_8_u2b_clears(self):
        hits = vsphere.build_cves("HostAgent", "8.0.2", "23305546")
        self.assertNotIn("CVE-2024-37085", {h["cve"] for h in hits})

    def test_vcenter_never_matches_37085(self):
        # HostAgent-only advisory must not fire on VirtualCenter builds.
        hits = vsphere.build_cves("VirtualCenter", "8.0.2", "1")
        self.assertNotIn("CVE-2024-37085", {h["cve"] for h in hits})

    def test_service_content_parse_of_unpatched_7u3o(self):
        parsed = vsphere._parse_service_content(ESXI_7U3O_SC)
        self.assertIsNotNone(parsed)
        cves = {h["cve"] for h in vsphere.build_cves(
            parsed["api_type"], parsed["version"], parsed["build"])}
        self.assertIn("CVE-2024-37085", cves)

    def test_findings_emit_dedicated_37085_row(self):
        h = Host(ip="10.0.0.6")
        h.ports.append(Port(portid=443, state="open", service="https"))
        pr = {
            "ip": h.ip, "port": 443, "role": "sdk", "reachable": True,
            "sdk": True, "api_type": "HostAgent", "version": "7.0.3",
            "build": "22348816",
            "cves": vsphere.build_cves("HostAgent", "7.0.3", "22348816"),
            "cert": {"cn": "", "sans": []},
        }
        fs = vsphere.findings([h], {(h.ip, 443): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("vsphere_cve_2024_37085", kinds)
        self.assertIn("vsphere_outdated_build", kinds)
        row = next(f for f in fs if f["kind"] == "vsphere_cve_2024_37085")
        self.assertEqual(row["severity"], "critical")
        self.assertIn("ESX Admins", row["title"])
        self.assertIn("CWE-269", row["cwes"])


# --- stale-snapshot finding ---------------------------------------------------

# Wire-derived shape: RetrievePropertiesEx on VirtualMachine returns a
# `snapshot` propSet only when the VM has at least one snapshot; the
# `<val>` element contains a serialised VirtualMachineSnapshotInfo tree.
# _parse_property_objects concatenates the val's itertext(), so the parsed
# `snapshot` prop is non-empty iff a snapshot exists. Below is the parsed
# equivalent — matches what _parse_property_objects yields.

VM_SNAPSHOT_INFO_TEXT = (
    "snapshot-9 pre-patch before Tuesday"
)


class StaleSnapshotTests(unittest.TestCase):
    def _parsed_vms(self):
        return [
            {"type": "VirtualMachine", "ref": "vm-101",
             "props": {"name": "dc01", "runtime.powerState": "poweredOff",
                       "snapshot": "snapshot-9 pre-patch before Tuesday"}},
            {"type": "VirtualMachine", "ref": "vm-102",
             "props": {"name": "app01", "runtime.powerState": "poweredOn",
                       "snapshot": "snapshot-1 fresh"}},
            {"type": "VirtualMachine", "ref": "vm-103",
             "props": {"name": "legacy01", "runtime.powerState": "poweredOff"}},
        ]

    def test_helper_returns_only_powered_off_with_snapshot(self):
        vms = self._parsed_vms()
        stale = vsphere._stale_snapshot_vms(vms)
        self.assertEqual(stale, ["dc01"])

    def test_helper_ignores_empty_snapshot_string(self):
        vms = [{"type": "VirtualMachine", "ref": "vm-0",
                "props": {"name": "x", "runtime.powerState": "poweredOff",
                          "snapshot": "   "}}]
        self.assertEqual(vsphere._stale_snapshot_vms(vms), [])

    def test_helper_empty_input(self):
        self.assertEqual(vsphere._stale_snapshot_vms([]), [])

    def test_finding_emits_when_stale_snapshot_present(self):
        h = Host(ip="10.0.0.5")
        h.ports.append(Port(portid=443, state="open", service="https"))
        pr = {
            "ip": h.ip, "port": 443, "role": "sdk", "reachable": True,
            "sdk": True, "api_type": "VirtualCenter", "version": "8.0.2",
            "build": "22385740", "cves": [],
            "cert": {"cn": "", "sans": []},
            "login": {"success": True, "user": "administrator@vsphere.local",
                      "cookie": "vmware_soap_session=z", "attempts": 1},
            "managed_hosts": [],
            "managed_vms": self._parsed_vms(),
        }
        fs = vsphere.findings([h], {(h.ip, 443): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("vsphere_stale_snapshot", kinds)
        row = next(f for f in fs if f["kind"] == "vsphere_stale_snapshot")
        self.assertEqual(row["severity"], "high")
        self.assertIn("dc01", row["detail"])
        # Only dc01 (powered-off with snapshot) — app01 is on, legacy01 has none.
        self.assertNotIn("app01", row["detail"])
        self.assertNotIn("legacy01", row["detail"])

    def test_finding_suppressed_when_no_stale_snapshots(self):
        h = Host(ip="10.0.0.5")
        h.ports.append(Port(portid=443, state="open", service="https"))
        pr = {
            "ip": h.ip, "port": 443, "role": "sdk", "reachable": True,
            "sdk": True, "api_type": "VirtualCenter", "version": "8.0.2",
            "build": "22385740", "cves": [],
            "cert": {"cn": "", "sans": []},
            "login": {"success": True, "user": "u", "cookie": "c",
                      "attempts": 1},
            "managed_hosts": [],
            "managed_vms": [
                {"type": "VirtualMachine", "ref": "vm-1",
                 "props": {"name": "app", "runtime.powerState": "poweredOn",
                           "snapshot": "snapshot-1 x"}},
            ],
        }
        fs = vsphere.findings([h], {(h.ip, 443): pr})
        self.assertNotIn("vsphere_stale_snapshot", {f["kind"] for f in fs})


# --- T2: vsphere_sessionmanager_open (pre-auth SessionManager reachability) ---


class SessionManagerT2Tests(unittest.TestCase):
    """SessionManager MOR extraction + single-shot pre-auth reachability probe."""

    def test_sessionmanager_mor_parsed_from_vcenter_service_content(self):
        parsed = vsphere._parse_service_content(VCENTER_SC)
        self.assertEqual(parsed["session_manager_mor"], "SessionManager")

    def test_sessionmanager_mor_missing_on_esxi_fixture(self):
        # ESXi fixture doesn't carry a <sessionManager> element — the field
        # must default to empty string, never None, and never break parsing.
        parsed = vsphere._parse_service_content(ESXI_SC)
        self.assertEqual(parsed["session_manager_mor"], "")

    def test_sessionmanager_probe_returns_fault_reason(self):
        # Vulnerable/patched vCenter alike answers pre-auth Login with an
        # InvalidLoginFault. Probe must capture the real server-side reason.
        def fake_post(ip, port, body, action="", timeout=vsphere._TIMEOUT,
                      cookie=""):
            self.assertIn(b"<Login ", body)
            # Canary user must be the synthetic one, never a real principal.
            self.assertIn(vsphere._T2_CANARY_USER.encode(), body)
            return 200, LOGIN_FAIL, ""

        with mock.patch.object(vsphere, "_post_soap", fake_post):
            res = vsphere._sessionmanager_probe("10.0.0.5", 443)
        self.assertIsNotNone(res)
        self.assertEqual(res["status"], 200)
        self.assertTrue(res["fault"])
        self.assertIn("incorrect", res["fault_reason"].lower())
        self.assertEqual(res["canary"], vsphere._T2_CANARY_USER)

    def test_sessionmanager_probe_returns_none_on_transport_failure(self):
        # A blocked/unresponsive appliance must yield None (finding suppressed).
        with mock.patch.object(vsphere, "_post_soap", return_value=None):
            self.assertIsNone(vsphere._sessionmanager_probe("10.0.0.5", 443))

    def test_probe_populates_sessionmanager_probe_field(self):
        # End-to-end: ServiceContent -> SessionManager MOR -> probe -> field
        # in the probe() output. Timeout scaled through proxy.scaled.
        def fake_post(ip, port, body, action="", timeout=vsphere._TIMEOUT,
                      cookie=""):
            if b"RetrieveServiceContent" in body:
                return 200, VCENTER_SC, ""
            if b"<Login " in body:
                return 200, LOGIN_FAIL, ""
            return None

        with mock.patch.object(vsphere, "_post_soap", fake_post), \
             mock.patch.object(vsphere, "_http_get", return_value=None), \
             mock.patch.object(vsphere, "_cert_san",
                               return_value={"cn": "", "sans": []}):
            out = vsphere.probe("10.0.0.5", 443, active_auth=False)
        self.assertEqual(out["session_manager_mor"], "SessionManager")
        sm = out.get("sessionmanager_probe")
        self.assertIsNotNone(sm)
        self.assertTrue(sm["fault"])
        self.assertEqual(sm["canary"], vsphere._T2_CANARY_USER)

    def test_probe_skips_sessionmanager_probe_when_no_mor(self):
        # ESXi ServiceContent doesn't advertise SessionManager MOR in our
        # fixture; the probe must NOT fire (guardrail: only when MOR present).
        calls = []

        def fake_post(ip, port, body, action="", timeout=vsphere._TIMEOUT,
                      cookie=""):
            calls.append(body)
            if b"RetrieveServiceContent" in body:
                return 200, ESXI_SC, ""
            return None

        with mock.patch.object(vsphere, "_post_soap", fake_post), \
             mock.patch.object(vsphere, "_http_get", return_value=None), \
             mock.patch.object(vsphere, "_cert_san",
                               return_value={"cn": "", "sans": []}):
            out = vsphere.probe("10.0.0.5", 443, active_auth=False)
        # No sessionmanager_probe field surfaces.
        self.assertNotIn("sessionmanager_probe", out)
        # Only one POST fired (the ServiceContent fingerprint).
        self.assertEqual(len(calls), 1)

    def test_finding_emitted_when_sessionmanager_reachable(self):
        h = Host(ip="10.0.0.5")
        h.ports.append(Port(portid=443, state="open", service="https"))
        pr = {
            "ip": h.ip, "port": 443, "role": "sdk", "reachable": True,
            "sdk": True, "api_type": "VirtualCenter", "version": "8.0.2",
            "build": "22385740", "full_name": "VMware vCenter 8.0.2",
            "instance_uuid": "u", "cves": [],
            "cert": {"cn": "", "sans": []},
            "session_manager_mor": "SessionManager",
            "sessionmanager_probe": {
                "status": 200, "fault": True,
                "fault_reason": "Cannot complete login due to an incorrect "
                                "user name or password.",
                "canary": vsphere._T2_CANARY_USER,
            },
        }
        fs = vsphere.findings([h], {(h.ip, 443): pr})
        kinds = {f["kind"] for f in fs}
        self.assertIn("vsphere_sessionmanager_open", kinds)
        row = next(f for f in fs if f["kind"] == "vsphere_sessionmanager_open")
        self.assertEqual(row["depth_tier"], "t2")
        self.assertEqual(row["severity"], "medium")
        # Evidence carries the real server-side fault reason + MOR + build.
        self.assertIn("SessionManager", row["detail"])
        self.assertIn("22385740", row["detail"])
        self.assertIn("incorrect user name", row["detail"])
        self.assertIn(vsphere._T2_CANARY_USER, row["detail"])
        self.assertIn("CWE-284", row["cwes"])

    def test_finding_suppressed_when_probe_missing(self):
        # Timed-out/blocked appliances: no probe result -> no T2 finding, and
        # the T0/T1 findings (fingerprint, outdated_build) must still emit.
        h = Host(ip="10.0.0.5")
        h.ports.append(Port(portid=443, state="open", service="https"))
        pr = {
            "ip": h.ip, "port": 443, "role": "sdk", "reachable": True,
            "sdk": True, "api_type": "VirtualCenter", "version": "7.0.3",
            "build": "19717403",
            "cves": vsphere.build_cves("VirtualCenter", "7.0.3", "19717403"),
            "cert": {"cn": "", "sans": []},
            "session_manager_mor": "SessionManager",
            # No sessionmanager_probe key.
        }
        fs = vsphere.findings([h], {(h.ip, 443): pr})
        kinds = {f["kind"] for f in fs}
        self.assertNotIn("vsphere_sessionmanager_open", kinds)
        # T1 path untouched.
        self.assertIn("vsphere_outdated_build", kinds)
        self.assertIn("vsphere_fingerprint", kinds)

    def test_finding_suppressed_when_mor_missing(self):
        # No SessionManager MOR (e.g., ESXi-style fixture) -> no T2 finding
        # even if a probe result was somehow present.
        h = Host(ip="10.0.0.5")
        h.ports.append(Port(portid=443, state="open", service="https"))
        pr = {
            "ip": h.ip, "port": 443, "role": "sdk", "reachable": True,
            "sdk": True, "api_type": "HostAgent", "version": "7.0.3",
            "build": "19193900", "cves": [],
            "cert": {"cn": "", "sans": []},
            "session_manager_mor": "",
            "sessionmanager_probe": {"status": 200, "fault": True,
                                     "fault_reason": "x",
                                     "canary": vsphere._T2_CANARY_USER},
        }
        fs = vsphere.findings([h], {(h.ip, 443): pr})
        self.assertNotIn("vsphere_sessionmanager_open",
                         {f["kind"] for f in fs})


if __name__ == "__main__":
    unittest.main()
