"""serviceenum.py mirrors recce-service.sh's service/port -> script maps by hand.
Nothing enforced that they stay in sync, so they could silently drift (a name/port
added to one but not the other). These tests parse the shell driver's case statements
and assert both sides resolve every service name / port identically, and that every
mapped script actually exists.
"""
import pathlib
import re
import unittest

from recce import serviceenum

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SH = _ROOT / "recce" / "scripts" / "recce-service.sh"
_SVCDIR = _ROOT / "recce" / "scripts" / "services"


def _parse_case(func: str) -> dict[str, str]:
    """{pattern: svc} from a `func() { case "$1" in <pat>) echo <svc>;; ... }` block."""
    text = _SH.read_text()
    m = re.search(rf"^{func}\(\)\s*\{{(.*?)^\}}", text, re.S | re.M)
    if not m:
        raise AssertionError(f"{func} not found in {_SH}")
    out: dict[str, str] = {}
    # finditer, not line-by-line: port_to_svc packs several `NN) echo svc;;` per line.
    for cm in re.finditer(r'([\w|/.*-]+)\)\s*echo\s+("?[\w-]*"?)\s*;;', m.group(1)):
        pats, svc = cm.group(1), cm.group(2).strip('"')
        if pats == "*" or not svc:          # the default arm / empty result
            continue
        for pat in pats.split("|"):
            out[pat.strip().lower()] = svc
    return out


class ServiceEnumParityTest(unittest.TestCase):
    def test_name_map_parity_both_directions(self):
        sh = _parse_case("name_to_svc")
        # Every service name the shell driver knows resolves the same in Python.
        for name, svc in sh.items():
            self.assertEqual(serviceenum.script_for(name, 0), svc,
                             f"name '{name}': shell -> {svc}, python -> "
                             f"{serviceenum.script_for(name, 0)}")
        # ...and every name Python knows is mapped identically by the shell driver.
        for name, svc in serviceenum._NAME.items():
            self.assertEqual(sh.get(name.lower()), svc,
                             f"name '{name}' -> {svc} in python but "
                             f"{sh.get(name.lower())!r} in recce-service.sh")

    def test_port_map_parity_both_directions(self):
        sh = {int(k): v for k, v in _parse_case("port_to_svc").items()}
        for port, svc in sh.items():
            self.assertEqual(serviceenum.script_for("", port), svc,
                             f"port {port}: shell -> {svc}, python -> "
                             f"{serviceenum.script_for('', port)}")
        for port, svc in serviceenum._PORT.items():
            self.assertEqual(sh.get(port), svc,
                             f"port {port} -> {svc} in python but "
                             f"{sh.get(port)!r} in recce-service.sh")

    def test_every_mapped_script_exists(self):
        for svc in set(serviceenum._NAME.values()) | set(serviceenum._PORT.values()):
            self.assertTrue((_SVCDIR / f"{svc}.sh").is_file(),
                            f"serviceenum maps to '{svc}' but "
                            f"recce/scripts/services/{svc}.sh is missing")


if __name__ == "__main__":
    unittest.main()
