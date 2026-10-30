"""验证 IP 订阅的真实 HTTP 响应、访问边界及 TCP 防火墙隔离。"""
import http.client
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from test_hy import hy, fixture


class SubscriptionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "subscription.json"
        self.files = hy.client_files(fixture())
        self.data = {"owner": hy.MARKER, "port": 24444, "ipv6": False, "token": "a" * 48,
                     "files": {name: self.files[name] for name in hy.SUBSCRIPTIONS}}
        hy.atomic_write(self.path, hy.json_text(self.data))
        self.server = hy.SubscriptionServer(("127.0.0.1", 0), self.path)
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def request(self, path, method="GET"):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            conn.request(method, path)
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def test_all_client_formats_and_head(self):
        for name in hy.SUBSCRIPTIONS:
            status, headers, body = self.request("/hy-sub-" + self.data["token"] + "/" + name)
            self.assertEqual(status, 200)
            self.assertEqual(body, self.files[name].encode())
            self.assertEqual(headers["Cache-Control"], "no-store")
        status, headers, body = self.request("/hy-sub-" + self.data["token"] + "/hiddify.txt?refresh=1", "HEAD")
        self.assertEqual((status, body), (200, b""))
        self.assertEqual(int(headers["Content-Length"]), len(self.files["hiddify.txt"].encode()))

    def test_wrong_tokens_directories_and_files_are_not_served(self):
        prefix = "/hy-sub-" + self.data["token"]
        for path in ("/", "/subscription.json", "/etc/hy/state.json", prefix + "/", prefix + "/state.json",
                     prefix + "/../state.json", prefix + "/%2e%2e/state.json", "/hy-sub-wrong/hiddify.txt",
                     prefix + "/.hy-owner", prefix + "/native.json"):
            with self.subTest(path=path):
                status, _, body = self.request(path)
                self.assertEqual(status, 404)
                self.assertNotIn(fixture()["password"].encode(), body)

    def test_refresh_and_revocation_without_restarting_server(self):
        old = "/hy-sub-" + self.data["token"] + "/hiddify.txt"
        self.data["token"] = "b" * 48
        self.data["files"]["hiddify.txt"] = "new contents\n"
        hy.atomic_write(self.path, hy.json_text(self.data))
        self.assertEqual(self.request(old)[0], 404)
        self.assertEqual(self.request("/hy-sub-" + "b" * 48 + "/hiddify.txt")[2], b"new contents\n")
        self.path.unlink()
        self.assertEqual(self.request(old)[0], 503)

    def test_connection_limit_releases_no_extra_slots(self):
        for _ in range(32):
            self.assertTrue(self.server.slots.acquire(blocking=False))
        try:
            with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
                self.request("/")
        finally:
            for _ in range(32):
                self.server.slots.release()
        self.assertEqual(self.request("/hy-sub-" + self.data["token"] + "/hiddify.txt")[0], 200)

    def test_ipv6_url_and_legacy_https_url(self):
        p = hy.http_publication("2001:db8::1", 24444, "a" * 48)
        self.assertTrue(hy.subscription_url(p, "hiddify.txt").startswith("http://[2001:db8::1]:24444/"))
        self.assertTrue(hy.subscription_url(p, "hiddify.txt", local=True).startswith("http://[::1]:24444/"))
        p = {"url": "https://vpn.example.com", "token": "a" * 48}
        self.assertEqual(hy.subscription_url(p, "clash.yaml"), p["url"] + "/hy-sub-" + p["token"] + "/clash.yaml")

    def test_ipv6_http_listener(self):
        try:
            server = hy.SubscriptionServer(("::1", 0), self.path, ipv6=True)
        except OSError:
            self.skipTest("测试环境没有 IPv6 回环接口")
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
        thread.start()
        conn = http.client.HTTPConnection("::1", server.server_port, timeout=3)
        try:
            conn.request("GET", "/hy-sub-" + self.data["token"] + "/hiddify.txt")
            response = conn.getresponse()
            self.assertEqual((response.status, response.read()), (200, self.files["hiddify.txt"].encode()))
        finally:
            conn.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_same_number_udp_does_not_conflict_with_tcp(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.bind(("127.0.0.1", self.server.server_port))
            self.assertEqual(self.request("/")[0], 404)

    def test_tcp_firewall_cleanup_preserves_owned_udp_rule(self):
        records = [{"backend": "ufw", "port": 24444, "comment": "udp-owned"},
                   {"backend": "ufw", "port": 24444, "protocol": "tcp", "comment": "tcp-owned"}]
        with patch.object(hy, "DATA", Path(self.tmp.name)), \
             patch.object(hy, "output", return_value="ufw allow 24444/udp comment udp-owned\nufw allow 24444/tcp comment tcp-owned"), \
             patch.object(hy, "run") as run:
            hy.save_firewall(records)
            hy.firewall_prune(protocol="tcp")
            self.assertEqual(hy.firewall_records(), records[:1])
            self.assertIn("24444/tcp", run.call_args.args[0])

    def test_failed_first_start_removes_candidate_and_keeps_node_state(self):
        root = Path(self.tmp.name)
        state = {**fixture(), "publication": hy.http_publication("127.0.0.1", 24444)}
        state_path = root / "state.json"
        state_path.write_bytes(b"existing-node-state")
        original_write = hy.atomic_write
        def fail_restart(args, **kwargs):
            if args == ["systemctl", "restart", hy.SUB_SERVICE]:
                raise subprocess.CalledProcessError(1, args)
        # Windows 单元测试不设置 Unix 文件组；真实权限由 systemd 集成测试验证。
        def write(path, content, mode=0o600, gid=None):
            return original_write(path, content, mode)
        with patch.object(hy, "ETC", root / "etc"), patch.object(hy, "DATA", root / "data"), \
             patch.object(hy, "UNIT_DIR", root / "units"), patch.object(hy, "STATE", state_path), \
             patch.object(hy, "group_id", return_value=0), patch.object(hy, "atomic_write", side_effect=write), \
             patch.object(hy.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)), \
             patch.object(hy, "run", side_effect=fail_restart) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                hy.activate_http_subscription(state)
            self.assertFalse(hy.subscription_config_path().exists())
            self.assertEqual(state_path.read_bytes(), b"existing-node-state")
            self.assertIn(unittest.mock.call(["systemctl", "disable", "--now", hy.SUB_SERVICE]), run.call_args_list)


if __name__ == "__main__":
    unittest.main()
