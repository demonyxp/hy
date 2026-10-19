import base64
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlsplit

spec = importlib.util.spec_from_file_location("hy", Path(__file__).parents[1] / "hy.py")
hy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hy)


def fixture():
    return {"owner": hy.MARKER, "domain": "vpn.example.com", "server": "2001:db8::1",
            "port": 24443, "password": "secret:@/#? 中文123456", "name": "韩国-测试",
            "obfs": "obfs &?#中文", "cert_source": "/cert.pem", "key_source": "/key.pem"}


class ConfigTests(unittest.TestCase):
    def test_ip_mode_needs_no_domain_or_existing_certificate(self):
        answers = ["2", "203.0.113.10", "24443", "test-password-123456", "IP节点", "n"]
        with patch.object(hy, "prompt", side_effect=answers), patch.object(hy, "check_certificate") as check:
            state = hy.collect_state()
        self.assertEqual(state["cert_mode"], "selfsigned")
        self.assertEqual(state["server"], "203.0.113.10")
        self.assertEqual(state["domain"], "hy.invalid")
        check.assert_not_called()
        self.assertEqual(hy.ip_literal("[2001:db8::1]"), "2001:db8::1")
        for value in ("example.com", "https://1.2.3.4", "1.2.3.4:443", "fe80::1%eth0"):
            with self.assertRaises(ValueError):
                hy.ip_literal(value)

    def test_self_signed_exports_keep_certificate_identity(self):
        state = {**fixture(), "cert_mode": "selfsigned", "domain": "hy.invalid",
                 "cert_sha256": "a" * 64, "cert_pem": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"}
        files = hy.client_files(state)
        query = parse_qs(urlsplit(files["node.txt"].strip()).query)
        self.assertEqual(query["insecure"], ["1"])
        self.assertEqual(query["pinSHA256"], [state["cert_sha256"]])
        node = json.loads(files["clash.yaml"])["proxies"][0]
        self.assertTrue(node["skip-cert-verify"])
        self.assertEqual(node["fingerprint"], state["cert_sha256"])
        native = json.loads(files["native.json"])["tls"]
        self.assertEqual(native["pinSHA256"], state["cert_sha256"])
        tls = json.loads(files["sing-box.json"])["outbounds"][0]["tls"]
        self.assertFalse(tls["insecure"])
        self.assertEqual(tls["certificate"], state["cert_pem"].splitlines())
        del state["cert_sha256"]
        with self.assertRaises(ValueError):
            hy.client_files(state)

    def test_special_characters_round_trip_across_clients(self):
        state = fixture()
        files = hy.client_files(state)
        link = files["node.txt"].strip()
        url = urlsplit(link)
        self.assertEqual(url.hostname, state["server"])
        self.assertEqual(url.port, state["port"])
        self.assertEqual(unquote(url.username), state["password"])
        self.assertEqual(unquote(url.fragment), state["name"])
        self.assertEqual(parse_qs(url.query)["obfs-password"], [state["obfs"]])
        self.assertEqual(base64.b64decode(files["hiddify.txt"]).decode(), files["node.txt"])
        self.assertEqual(files["v2rayn.txt"], files["hiddify.txt"])
        self.assertEqual(files["clash.yaml"], files["flclash.yaml"])
        clash = json.loads(files["flclash.yaml"])["proxies"][0]
        self.assertEqual(clash["password"], state["password"])
        self.assertFalse(clash["skip-cert-verify"])
        native = json.loads(files["native.json"])
        self.assertEqual(native["auth"], state["password"])
        self.assertFalse(native["tls"]["insecure"])
        outbound = json.loads(files["sing-box.json"])["outbounds"][0]
        self.assertEqual(outbound["password"], state["password"])
        self.assertEqual(outbound["obfs"]["password"], state["obfs"])
        self.assertEqual(outbound["server"], state["server"])
        self.assertEqual(outbound["tls"]["server_name"], state["domain"])
        self.assertFalse(outbound["tls"]["insecure"])

    def test_optional_obfs_does_not_leave_stale_parameters(self):
        state = fixture()
        state["obfs"] = ""
        self.assertNotIn("obfs", hy.server_config(state))
        files = hy.client_files(state)
        self.assertNotIn("obfs", parse_qs(urlsplit(files["node.txt"].strip()).query))
        self.assertNotIn("obfs", json.loads(files["flclash.yaml"])["proxies"][0])
        self.assertNotIn("obfs", json.loads(files["sing-box.json"])["outbounds"][0])

    def test_invalid_addresses_and_ports_are_rejected(self):
        for value in ("https://vpn.example.com", "x;rm -rf /", "*.example.com", "127.0.0.1", "a..com", "-a.com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                hy.domain(value)
        for value in (0, 65536, "443;reboot", "-1", "1.0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                hy.port_number(value)

    def test_release_without_trusted_digest_is_rejected(self):
        asset = {"name": "hysteria-linux-amd64", "digest": "sha256:" + "a" * 64,
                 "browser_download_url": f"https://github.com/{hy.REPO}/releases/download/app/v2.13.0/hysteria-linux-amd64"}
        self.assertEqual(hy.release_asset({"assets": [asset]}, "x86_64"), asset)
        for change in ({"digest": None}, {"digest": "sha256:wrong"}, {"browser_download_url": "https://evil.test/core"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                hy.release_asset({"assets": [{**asset, **change}]}, "x86_64")

    def test_occupied_udp_port_is_not_ignored(self):
        with patch.object(hy, "output", return_value="UNCONN 0 0 *:24443 *:*"), self.assertRaises(ValueError):
            hy.check_port(24443)

    def test_failed_config_restart_restores_old_config(self):
        old, new = fixture(), fixture()
        new["port"] = 24444
        with patch.object(hy, "load_state", return_value=old), \
             patch.object(hy, "collect_state", return_value=new), \
             patch.object(hy, "check_port"), patch.object(hy, "backup", return_value=Path("snapshot")), \
             patch.object(hy, "service_active", return_value=True), patch.object(hy, "write_config"), \
             patch.object(hy, "restart_checked", side_effect=[RuntimeError("test failure"), None]) as restart, \
             patch.object(hy, "restore_config") as restore, patch.object(hy, "export_files") as export:
            with self.assertRaises(RuntimeError):
                hy.configure()
            restore.assert_called_once_with(Path("snapshot"))
            self.assertEqual(restart.call_count, 2)
            export.assert_not_called()

    def test_atomic_write_does_not_modify_symlink_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / "original"
            original.write_text("keep")
            link = root / "link"
            try:
                link.symlink_to(original)
            except OSError:
                self.skipTest("当前账户不能创建符号链接")
            hy.atomic_write(link, "new")
            self.assertEqual(original.read_text(), "keep")
            self.assertFalse(link.is_symlink())

    def test_subscription_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            token = "a" * 48
            try:
                (root / ("hy-sub-" + token)).symlink_to(root.parent, target_is_directory=True)
            except OSError:
                self.skipTest("当前账户不能创建符号链接")
            with self.assertRaises(ValueError):
                hy.publication_dir({"root": str(root), "token": token})


if __name__ == "__main__":
    unittest.main()
