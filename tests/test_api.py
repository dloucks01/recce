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
