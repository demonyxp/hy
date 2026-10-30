import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("hy", Path(__file__).parents[1] / "hy.py")
hy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hy)


class TrafficTests(unittest.TestCase):
    def test_rates_round_trip_without_scientific_notation(self):
        for value in ("0", "0.001", "10", "10000", "001.500"):
            parsed = hy.rate_mbps(value)
            self.assertEqual(hy.rate_mbps(parsed), parsed)
        for value in ("-1", "nan", "inf", "1e2", "10001", "0.0001", "1; flush ruleset"):
            with self.assertRaises(ValueError):
                hy.rate_mbps(value)

    def test_rules_only_touch_owned_table_and_hy_udp_port(self):
        state = {"port": 24443, "traffic": {"enabled": True, "limits": {
            "203.0.113.7": {"upload": "10", "download": "20"},
            "2001:db8::1": {"upload": "0", "download": "1.5"}}}}
        rules = hy.traffic_rules(state, False)
        self.assertIn("udp dport 24443 jump upload_limits", rules)
        self.assertIn("udp sport 24443 jump download_limits", rules)
        self.assertIn("ip saddr 203.0.113.7 limit rate over 1250000 bytes/second", rules)
        self.assertIn("ip6 daddr 2001:db8::1 limit rate over 187500 bytes/second", rules)
        self.assertNotIn("tcp", rules)
        self.assertNotIn("flush ruleset", rules)
        refresh = hy.traffic_rules(state, True)
        self.assertNotIn("flush set", refresh)
        self.assertNotIn("delete table", refresh)
        self.assertNotIn("add table", refresh)
        state["traffic"]["limits"] = {"1.2.3.4;drop": {"upload": "1"}}
        with self.assertRaises(ValueError):
            hy.traffic_rules(state, True)

    def test_snapshot_handles_ipv4_ipv6_and_unrelated_objects(self):
        payload = {"nftables": [
            {"set": {"name": "up4", "elem": [{"elem": {"val": "203.0.113.7", "counter": {"bytes": 120}}}]}},
            {"set": {"name": "down4", "elem": [{"elem": {"val": "203.0.113.7", "counter": {"bytes": 900}}}]}},
            {"set": {"name": "up6", "elem": [{"elem": {"val": "2001:db8::1", "counter": {"bytes": 50}}}]}},
            {"rule": {"comment": "not a counter set"}}]}
        result = hy.traffic_snapshot(payload)
        self.assertEqual(result["203.0.113.7"], {"upload": 120, "download": 900})
        self.assertEqual(result["2001:db8::1"], {"upload": 50, "download": 0})
        self.assertEqual(hy.traffic_snapshot(None), {})

    def test_foreign_table_is_never_adopted(self):
        tables = {"nftables": [{"table": {"family": "inet", "name": hy.TRAFFIC_TABLE}}]}
        with patch.object(hy.shutil, "which", return_value="/usr/sbin/nft"), \
             patch.object(hy, "output", side_effect=[json.dumps(tables), json.dumps(tables),
                                                      'table inet hy_traffic {\n\tcomment "foreign"\n}']):
            with self.assertRaises(ValueError):
                hy.nft_table()

    def test_old_nft_json_requires_exact_table_level_owner(self):
        tables = {"nftables": [{"table": {"family": "inet", "name": hy.TRAFFIC_TABLE}}]}
        cases = [
            ('table inet hy_traffic {\n\tcomment "demonyxp/hy"\n\tchain incoming { }\n}', True),
            ('table inet hy_traffic {\n\tcomment "foreign"\n}', False),
            ('table inet hy_traffic {\n\tchain incoming {\n\t\tcomment "demonyxp/hy"\n}\n}', False),
            ('table inet another_table {\n\tcomment "demonyxp/hy"\n}', False),
        ]
        for header, owned in cases:
            with self.subTest(header=header), patch.object(hy.shutil, "which", return_value="/usr/sbin/nft"), \
                 patch.object(hy, "output", side_effect=[json.dumps(tables), json.dumps(tables), header]):
                if owned:
                    self.assertEqual(hy.nft_table(), tables)
                else:
                    with self.assertRaises(ValueError):
                        hy.nft_table()

    def test_editing_one_direction_preserves_other_limit(self):
        state = {"traffic": {"enabled": True, "limits": {"203.0.113.7": {"upload": "10", "download": "20"}}}}
        with patch.object(hy, "load_state", return_value=state), patch.object(hy, "save_traffic") as save:
            hy.set_limit("203.0.113.7", download="5")
        self.assertEqual(save.call_args.args[1]["limits"]["203.0.113.7"], {"upload": "10", "download": "5"})
        self.assertEqual(state["traffic"]["limits"]["203.0.113.7"]["download"], "20")


if __name__ == "__main__":
    unittest.main()
