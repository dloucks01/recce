"""API enumeration — OpenAPI/Swagger + GraphQL discovery over web services (mocked HTTP)."""

import unittest

from recce import api, web
from recce.models import Host, Port


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
        self.assertIn("GraphQL introspection enabled", titles)
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
