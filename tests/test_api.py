"""API enumeration — OpenAPI/Swagger + GraphQL discovery over web services (mocked HTTP)."""

import unittest

from recce.services import api, web
from recce.core.models import Host, Port


def _mock_fetch(responses):
    def f(ip, port, path="/", method="GET", body=None, **kw):
        return responses.get(path)          # (status, headers, body) or None
    return f


class SpecParseTest(unittest.TestCase):
    def test_endpoint_count(self):
        spec = '{"openapi":"3.0.0","paths":{"/a":{"get":{}},"/b":{"get":{},"post":{}}}}'
        self.assertEqual(api._spec_endpoint_count(spec), 3)

    def test_non_spec_returns_none(self):
        self.assertIsNone(api._spec_endpoint_count('{"just":"some json"}'))
        self.assertIsNone(api._spec_endpoint_count("not json at all"))


class AnalyzeTest(unittest.TestCase):
    def setUp(self):
        self._orig = web._fetch

    def tearDown(self):
        web._fetch = self._orig

    def _host(self):
        return Host(ip="10.0.0.1", up_reason="syn-ack",
                    ports=[Port(portid=80, protocol="tcp", state="open", service="http")])

    def test_finds_swagger_and_graphql(self):
        web._fetch = _mock_fetch({
            "/openapi.json": (200, {}, '{"openapi":"3.0","paths":{"/x":{"get":{}}}}'),
            "/graphql": (200, {}, '{"data":{"__schema":{"queryType":{"name":"Query"}}}}'),
        })
        a = api.analyze([self._host()])
        titles = {f["title"] for f in a["findings"]}
        self.assertIn("OpenAPI/Swagger spec exposed", titles)
        # Title now includes the full-schema follow-up marker.
        self.assertTrue(any(t.startswith("GraphQL introspection enabled") for t in titles),
                        f"expected a GraphQL introspection finding, got {titles}")
        self.assertEqual(a["targets"], [{"ip": "10.0.0.1", "port": 80}])

    def test_no_api_surface_is_no_findings(self):
        web._fetch = _mock_fetch({})            # everything 404/None
        self.assertEqual(api.analyze([self._host()])["findings"], [])

    def test_inactive_probes_nothing_but_lists_targets(self):
        web._fetch = _mock_fetch({"/openapi.json": (200, {}, '{"openapi":"3.0","paths":{}}')})
        a = api.analyze([self._host()], active=False)
        self.assertEqual(a["findings"], [])
        self.assertEqual(len(a["targets"]), 1)

    def test_findings_become_api_sourced_vulns(self):
        web._fetch = _mock_fetch({
            "/graphql": (200, {}, '{"data":{"__schema":{"queryType":{"name":"Q"}}}}')})
        a = api.analyze([self._host()])
        by_ip = api.findings_to_vulns(a["findings"])
        vulns = by_ip["10.0.0.1"]
        self.assertTrue(vulns)
        self.assertEqual(vulns[0].source, "api")


if __name__ == "__main__":
    unittest.main()


class SpecEnumerationTest(unittest.TestCase):
    """Full spec enumeration: broken-auth, IDOR/BOLA, and embedded-credential harvest."""

    def setUp(self):
        self._orig = web._fetch

    def tearDown(self):
        web._fetch = self._orig

    def _host(self):
        return Host(ip="10.0.0.1", up_reason="syn-ack",
                    ports=[Port(portid=80, protocol="tcp", state="open", service="http")])

    def test_broken_auth_idor_and_cred_harvest(self):
        spec = ('{"openapi":"3.0.0",'
                '"components":{"securitySchemes":{"bearer":{"type":"http"}}},'
                '"servers":[{"url":"https://svc:apikey123@api.internal/"}],'
                '"security":[{"bearer":[]}],'
                '"paths":{'
                '"/users/{id}":{"get":{"security":[{"bearer":[]}]}},'
                '"/health":{"get":{"security":[]}}}}')
        web._fetch = _mock_fetch({
            "/openapi.json": (200, {}, spec),
            "/users/1": (200, {}, '{"id":1,"name":"alice","email":"alice@corp"}'),
            "/users/2": (200, {}, '{"id":2,"name":"bob","email":"bob@corp"}'),
            "/health": (200, {}, '{"status":"ok"}'),
        })
        analysis = api.analyze([self._host()], active=True)
        titles = " || ".join(f["title"] for f in analysis["findings"])
        self.assertIn("OpenAPI/Swagger spec exposed", titles)
        self.assertIn("without authentication", titles)          # broken auth
        self.assertIn("IDOR / BOLA on /users/{id}", titles)      # object enumeration
        # embedded spec credential harvested to the store
        self.assertTrue(any(c.secret == "apikey123" for c in analysis["credentials"]))

    def test_broken_auth_promoted_to_t2_when_body_leaks_pii(self):
        """A vulnerable target — unauth-200 body carries real emails + a JWT +
        an AWS key — must upgrade the broken-auth finding to depth_tier=t2 and
        surface the captured evidence in the detail text."""
        spec = ('{"openapi":"3.0.0",'
                '"components":{"securitySchemes":{"bearer":{"type":"http"}}},'
                '"security":[{"bearer":[]}],'
                '"paths":{"/users":{"get":{"security":[{"bearer":[]}]}}}}')
        # Body with three distinct PII shapes — RFC5322-ish emails, a JWT-shaped
        # token (base64url header.payload.signature), and an AKIA access key id.
        # None of these were produced by recce encoders; they're canonical wire
        # shapes copied by hand from the specs.
        pii_body = (
            '[{"email":"alice@example.com","token":'
            '"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij_k-lmnop"},'
            '{"email":"bob@corp.net","aws":"AKIAIOSFODNN7EXAMPLE"},'
            '{"email":"eve@example.com"}]')
        web._fetch = _mock_fetch({
            "/openapi.json": (200, {}, spec),
            "/users": (200, {}, pii_body),
        })
        analysis = api.analyze([self._host()], active=True)
        broken = [f for f in analysis["findings"]
                  if "broken auth" in f["title"].lower()]
        self.assertEqual(len(broken), 1)
        self.assertEqual(broken[0].get("depth_tier"), "t2")
        # Evidence surfaced to the tester: emails and JWT + AWS key indicators.
        det = broken[0]["detail"].lower()
        self.assertIn("proof-of-read captured", det)
        self.assertIn("emails=", det)
        self.assertIn("jwt-tokens=", det)
        self.assertIn("aws-access-key-ids=", det)

    def test_broken_auth_stays_t1_when_body_is_clean(self):
        """A patched-ish target — unauth-200 body has no PII / secret shapes —
        must keep the T1 broken-auth finding as-is (no depth_tier bump)."""
        spec = ('{"openapi":"3.0.0",'
                '"components":{"securitySchemes":{"bearer":{"type":"http"}}},'
                '"security":[{"bearer":[]}],'
                '"paths":{"/health":{"get":{"security":[{"bearer":[]}]}}}}')
        web._fetch = _mock_fetch({
            "/openapi.json": (200, {}, spec),
            # 200 with a real-looking body >8 bytes but no PII / secret shapes.
            "/health": (200, {}, '{"status":"ok","uptime":42}'),
        })
        analysis = api.analyze([self._host()], active=True)
        broken = [f for f in analysis["findings"]
                  if "broken auth" in f["title"].lower()]
        self.assertEqual(len(broken), 1)
        self.assertNotEqual(broken[0].get("depth_tier"), "t2")
        self.assertNotIn("proof-of-read", broken[0]["detail"].lower())

    def test_broken_auth_absent_when_endpoint_unreachable(self):
        """If the enumerator can't reach the secured endpoint (timeout / None
        response), no broken-auth finding emits at all — T2 mining never runs."""
        spec = ('{"openapi":"3.0.0",'
                '"components":{"securitySchemes":{"bearer":{"type":"http"}}},'
                '"security":[{"bearer":[]}],'
                '"paths":{"/users":{"get":{"security":[{"bearer":[]}]}}}}')
        # Only the spec resolves; the secured GET returns None (unreachable).
        web._fetch = _mock_fetch({"/openapi.json": (200, {}, spec)})
        analysis = api.analyze([self._host()], active=True)
        self.assertFalse(any("broken auth" in f["title"].lower()
                             for f in analysis["findings"]))

    def test_mine_pii_helper_on_wire_shapes(self):
        """Unit-check the mining helper on canonical wire shapes — an RFC5322
        email, a three-segment JWT, and an AKIA access-key id — plus the
        negative case that plain scalar JSON returns no hits."""
        # Positive shapes copied by hand from RFC / vendor docs, NOT constructed
        # via recce encoders.
        hits = api._mine_pii(
            '{"user":"root@example.org",'
            '"jwt":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_ature_here_ok",'
            '"key":"AKIAIOSFODNN7EXAMPLE"}')
        joined = " ".join(hits)
        self.assertIn("emails=", joined)
        self.assertIn("jwt-tokens=", joined)
        self.assertIn("aws-access-key-ids=", joined)
        # Negative: pure numeric / status body -> no hits.
        self.assertEqual(api._mine_pii('{"status":"ok","count":42}'), [])
        # Negative: empty / falsy body.
        self.assertEqual(api._mine_pii(""), [])

    def test_no_idor_when_bodies_identical(self):
        # same object for every id (or a static page) must NOT be flagged IDOR.
        spec = ('{"openapi":"3.0.0",'
                '"components":{"securitySchemes":{"x":{"type":"http"}}},'
                '"paths":{"/items/{id}":{"get":{}}}}')
        web._fetch = _mock_fetch({
            "/openapi.json": (200, {}, spec),
            "/items/1": (200, {}, '{"same":"page"}'),
            "/items/2": (200, {}, '{"same":"page"}'),
        })
        analysis = api.analyze([self._host()], active=True)
        self.assertNotIn("IDOR", " ".join(f["title"] for f in analysis["findings"]))
