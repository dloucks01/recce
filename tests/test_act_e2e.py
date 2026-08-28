"""End-to-end Act-phase test over a full, realistic engagement.

Seeds the high-fidelity mock engagement (DC + members + Linux web/DB + a non-AD NAS
+ the full loot/cred surface) and asserts the ranked action plan matches what a
pentester would actually prioritise. This is also the tuning oracle for the
impact/confidence/leverage weights: if a weight change reorders the plan wrongly,
one of these assertions breaks.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recce import act                                    # noqa: E402
from recce.cli import _open_paths                        # noqa: E402
from recce.core.store import Store                            # noqa: E402
from tools.mock_engagement import build                  # noqa: E402


class ActEndToEndTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        build(cls.d, hosts=16, seed=99)
        st = Store(_open_paths(cls.d)["db"])
        try:
            cls.cards = act.action_plan(st.all_hosts(), st.all_credentials(), cls.d)
        finally:
            st.close()

    @classmethod
    def tearDownClass(cls):
        __import__("shutil").rmtree(cls.d, ignore_errors=True)

    def _by(self, archetype):
        return [c for c in self.cards if c.archetype == archetype]

    # --- the plan surfaces every archetype the engagement warrants ----------------
    def test_all_relevant_archetypes_present(self):
        kinds = {c.archetype for c in self.cards}
        for want in ("loot", "spray", "exploit", "escalate", "crack"):
            self.assertIn(want, kinds, f"missing {want} card")

    # --- the single most valuable move is the synthesized route to DA (keystone) --
    def test_top_priority_is_the_route_to_domain_admin(self):
        top = act.top_moves(self.cards, n=1)[0]
        self.assertEqual(top.archetype, "ad-path")
        self.assertEqual(top.yields, "Domain Admin")
        others = [c for c in self.cards if c is not top and c.tier in (act.AUTO, act.READY)]
        self.assertTrue(all(top.score >= c.score for c in others))

    # --- and the top concrete exploit step is the DC RCE -> domain compromise ------
    def test_top_exploit_is_the_dc_rce(self):
        exp = sorted(self._by("exploit"), key=lambda c: -c.score)
        self.assertIn("Zerologon", exp[0].title)
        self.assertEqual(exp[0].yields, "domain compromise")

    # --- P3: a known-module exploit carries the REAL PoC command, not a writeup ----
    def test_exploit_cards_carry_a_real_poc_command(self):
        eb = next(c for c in self._by("exploit") if "EternalBlue" in c.title)
        self.assertIn("ms17_010", eb.command.lower())     # the actual msf module
        self.assertFalse(eb.command.startswith("recce writeup"))

    # --- P3: the AD-path keystone summarises a real domain-dominance route --------
    def test_adpath_keystone_present_and_maxed(self):
        ad = self._by("ad-path")
        self.assertEqual(len(ad), 1)
        self.assertEqual(ad[0].leverage, 2.0)
        self.assertTrue(ad[0].command.startswith("recce attackpath"))

    # --- weight sanity: cred loot beats data loot; spray beats a single cred loot -
    def test_cred_loot_outranks_data_loot(self):
        loot = self._by("loot")
        cred_loot = [c for c in loot if "credentials" in c.yields]
        data_loot = [c for c in loot if "credentials" not in c.yields]
        self.assertTrue(cred_loot and data_loot)
        self.assertGreater(min(c.score for c in cred_loot),
                           max(c.score for c in data_loot))

    def test_spray_is_the_top_auto_card(self):
        auto = [c for c in self.cards if c.tier == act.AUTO]
        auto.sort(key=lambda c: -c.score)
        self.assertEqual(auto[0].archetype, "spray")

    # --- confirmed exploits outrank a low-QoD lead --------------------------------
    def test_confirmed_exploit_outranks_a_version_lead(self):
        # every exploit in READY is confirmed/likely; any LEAD-tier exploit ranks after.
        ready_exp = [c for c in self._by("exploit") if c.tier == act.READY]
        lead_exp = [c for c in self._by("exploit") if c.tier == act.LEAD]
        if lead_exp:                                     # mock may or may not have one
            self.assertGreater(min(c.score for c in ready_exp),
                               max(c.score for c in lead_exp))

    # --- loot is deduped: one card per engagement-wide command --------------------
    def test_loot_is_deduped_by_command(self):
        cmds = [c.command for c in self._by("loot")]
        self.assertEqual(len(cmds), len(set(cmds)), "loot cards not deduped by command")
        # the web-cred loot collapsed several hosts into one card
        web = [c for c in self._by("loot") if c.command.startswith("recce web")]
        self.assertEqual(len(web), 1)
        self.assertGreater(web[0].count, 1)

    # --- the plan is tier-ordered (auto -> ready -> blocked -> lead) --------------
    def test_plan_is_tier_ordered(self):
        tiers = [c.tier for c in self.cards]
        self.assertEqual(tiers, sorted(tiers))

    # --- crack cards carry the right hashcat mode from the loot notes -------------
    def test_crack_cards_have_hashcat_modes(self):
        crack = self._by("crack")
        self.assertTrue(crack)
        modes = {c.command.split("-m ", 1)[1].split()[0] for c in crack if "-m " in c.command}
        self.assertIn("1000", modes)          # an NT hash (localadmin secretsdump)


if __name__ == "__main__":
    unittest.main()
