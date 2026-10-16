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
