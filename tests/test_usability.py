"""快速部署、更新保留状态和防火墙边界的回归测试。"""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch, Mock

from test_hy import hy, fixture


class UsabilityTests(unittest.TestCase):
    def test_release_metadata_matches_manager_and_bootstrap(self):
        root = Path(hy.__file__).parent
        release = json.loads((root / "release.json").read_text())
        self.assertEqual(release["version"], hy.VERSION)
        self.assertEqual(release["sha256"], hashlib.sha256((root / "hy.py").read_bytes()).hexdigest())
        self.assertIn("VERSION=v" + hy.VERSION, (root / "install.sh").read_text(encoding="utf-8"))

    def test_noninteractive_prompt_never_accepts_defaults(self):
        with patch.object(hy.sys, "stdin", io.StringIO("y\n")), patch("builtins.input") as read:
            with self.assertRaisesRegex(ValueError, "交互终端"):
                hy.prompt("确认", "y")
            with self.assertRaisesRegex(ValueError, "交互终端"):
                hy.ask_valid("确认", str, "y")
            read.assert_not_called()

    def test_discovery_rejects_private_addresses_and_falls_back(self):
        with patch.object(hy, "output", side_effect=["10.0.0.1", OSError(), "2606:4700:4700::1111"]) as call:
            self.assertEqual(hy.detect_public_ip(), "2606:4700:4700::1111")
            self.assertIn("-6", call.call_args.args[0])
        with patch.object(hy, "output", side_effect=OSError()):
            self.assertIsNone(hy.detect_public_ip())

    def test_quick_install_manual_ip_port_conflict_and_cancel(self):
        with patch.object(hy, "detect_public_ip", return_value=None), \
             patch.object(hy, "output", side_effect=["occupied", ""]), \
             patch.object(hy, "prompt", side_effect=["1", "10.0.0.1", "1.1.1.1", "2", "y"]):
            state = hy.installation_state()
        self.assertEqual(state["server"], "1.1.1.1")
        self.assertEqual(state["port"], 24444)
        self.assertEqual(state["firewall_mode"], "manual")
        self.assertEqual(state["cert_mode"], "selfsigned")
        self.assertGreaterEqual(len(state["password"]), 16)
        with patch.object(hy, "quick_state", return_value=state), patch.object(hy, "prompt", side_effect=["1", "1", "n"]):
            with self.assertRaisesRegex(ValueError, "取消"):
                hy.installation_state()

    def test_advanced_retries_bad_certificate_password_and_name(self):
        answers = ["1", "vpn.example.com", "vpn.example.com", "/bad", "/bad", "/cert", "/key",
                   "24443", "short", "secure-password-123456", "DIRECT", "正常节点", "n"]
        with patch.object(hy, "prompt", side_effect=answers), patch.object(hy, "check_port"), \
             patch.object(hy, "check_certificate", side_effect=[ValueError("bad"), None]):
            state = hy.collect_state()
        self.assertEqual(state["password"], "secure-password-123456")
        self.assertEqual(state["name"], "正常节点")

    def test_reinstall_preserves_all_legacy_state_without_service_commands(self):
        for version in ("0.1.0", "0.2.0", "0.3.0"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                state = {**fixture(), "version": version, "publication": {"token": "a" * 48},
                         "cert_sha256": "b" * 64, "traffic": {"enabled": True, "limits": {"1.1.1.1": {"upload": "50"}}}}
                before = json.dumps(state).encode()
                path = root / "state.json"
                path.write_bytes(before)
                with patch.object(hy, "STATE", path), patch.object(hy, "LIB", root), \
                     patch.object(hy, "run") as run, patch.object(hy, "installation_state") as wizard:
                    hy.install()
                    hy.install()
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual((root / "hy.py").read_bytes(), Path(hy.__file__).read_bytes())
                run.assert_not_called()
                wizard.assert_not_called()

    def test_self_update_rejects_bad_hash_syntax_and_downgrade(self):
        for content, version, wrong_hash in ((b"bad", hy.VERSION, True), (b"if broken", hy.VERSION, False),
                                              (b"", "0.3.0", False)):
            metadata = json.dumps({"version": version, "sha256": "a" * 64 if wrong_hash else hashlib.sha256(content).hexdigest()}).encode()
            with patch.object(hy, "load_state", return_value=fixture()), \
                 patch.object(hy, "fetch_manager", side_effect=[metadata, content]), patch.object(hy, "atomic_write") as write:
                with self.assertRaises((ValueError, SyntaxError)):
                    hy.self_update()
                write.assert_not_called()

    def test_self_update_only_replaces_manager(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "hy.py").write_text("old manager")
            content = f'VERSION = "{hy.VERSION}"\n'.encode()
            meta = json.dumps({"version": hy.VERSION, "sha256": hashlib.sha256(content).hexdigest()}).encode()
            with patch.object(hy, "LIB", root), patch.object(hy, "load_state", return_value=fixture()), \
                 patch.object(hy, "fetch_manager", side_effect=[meta, content]), \
                 patch.object(hy, "backup", return_value=root / "backup"), patch.object(hy, "run") as run:
                (root / "backup").mkdir()
                hy.self_update()
            self.assertEqual((root / "hy.py").read_bytes(), content)
            self.assertEqual((root / "backup/hy.py").read_text(), "old manager")
            run.assert_not_called()

    def test_doctor_continues_after_missing_certificate_and_timer(self):
        with patch.object(hy, "load_state", return_value=fixture()), patch.object(hy, "service_active", return_value=False), \
             patch.object(hy, "check_certificate", side_effect=ValueError("missing cert")), \
             patch.object(hy, "output", side_effect=["", ValueError("missing timer"), ValueError("timer stopped")]), \
             patch.object(hy.socket, "getaddrinfo", side_effect=OSError("dns failure")), \
             patch.object(hy, "firewall_backend", return_value=None), contextlib.redirect_stdout(io.StringIO()) as out:
            hy.doctor()
        for value in ("missing cert", "missing timer", "dns failure", "本机防火墙", "不能证明公网"):
            self.assertIn(value, out.getvalue())


class FirewallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.patch = patch.object(hy, "DATA", Path(self.tmp.name))
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.state = {"port": 24443, "firewall_mode": "auto"}

    def test_unknown_or_manual_does_not_write_rules(self):
        with patch.object(hy, "firewall_backend", return_value=None), patch.object(hy, "run") as run:
            hy.firewall_apply(self.state)
            hy.firewall_apply({**self.state, "firewall_mode": "manual"})
        run.assert_not_called()
        self.assertEqual(hy.firewall_records(), [])
        with patch.object(hy.shutil, "which", return_value="/usr/sbin/ufw"), \
             patch.object(hy, "output", side_effect=subprocess.CalledProcessError(1, ["ufw"])):
            self.assertIsNone(hy.firewall_backend())

    def test_ufw_existing_rule_is_not_owned_or_deleted(self):
        with patch.object(hy, "firewall_backend", return_value="ufw"), \
             patch.object(hy, "output", return_value="ufw allow 24443/udp comment 'user rule'"), patch.object(hy, "run") as run:
            hy.firewall_apply(self.state)
            hy.firewall_prune()
        run.assert_not_called()
        self.assertEqual(hy.firewall_records(), [])

    def test_ufw_idempotence_migration_and_cleanup(self):
        rules = []
        def command(args, **kwargs):
            if "delete" in args:
                rules.remove("ufw " + " ".join(args[3:]))
            else:
                rules.append(" ".join(args))
        with patch.object(hy, "firewall_backend", return_value="ufw"), \
             patch.object(hy, "output", side_effect=lambda args: "\n".join(rules)), patch.object(hy, "run", side_effect=command):
            hy.firewall_apply(self.state)
            hy.firewall_apply(self.state)
            self.assertEqual(len(rules), 1)
            hy.firewall_apply({**self.state, "port": 24444})
            hy.firewall_prune(24443)
            self.assertEqual(len(rules), 1)
            self.assertIn("24443/udp", rules[0])
            hy.firewall_prune()
        self.assertEqual(rules, [])
        self.assertEqual(hy.firewall_records(), [])

    def test_firewalld_partial_failure_records_allow_rollback(self):
        present = set()
        def query(args, **kwargs):
            self.assertIn("--zone=public", args)
            return Mock(returncode=0 if ("--permanent" in args) in present else 1)
        def mutate(args, **kwargs):
            permanent = "--permanent" in args
            if any(x.startswith("--add-port") for x in args):
                if permanent:
                    raise subprocess.CalledProcessError(1, args)
                present.add(permanent)
            else:
                present.discard(permanent)
        with patch.object(hy, "firewall_backend", return_value="firewalld"), \
             patch.object(hy, "output", return_value="public (default)\n  interfaces: eth0"), \
             patch.object(hy.subprocess, "run", side_effect=query), patch.object(hy, "run", side_effect=mutate):
            with self.assertRaises(subprocess.CalledProcessError):
                hy.firewall_apply(self.state)
            self.assertEqual(present, set())
            hy.firewall_prune()
        self.assertEqual(present, set())
        self.assertEqual(hy.firewall_records(), [])

    def test_cleanup_failure_retains_record_for_retry(self):
        record = {"backend": "ufw", "port": 24443, "comment": "hy-test"}
        hy.save_firewall([record])
        with patch.object(hy, "output", return_value="ufw allow 24443/udp comment hy-test"), \
             patch.object(hy, "run", side_effect=OSError("busy")):
            hy.firewall_prune()
        self.assertEqual(hy.firewall_records(), [record])

    def test_uninstall_retains_tool_when_firewall_cannot_be_cleaned(self):
        with patch.object(hy, "load_state", return_value=self.state), \
             patch.object(hy, "prompt", return_value="UNINSTALL"), patch.object(hy, "backup"), \
             patch.object(hy, "firewall_prune", return_value=[{"port": 24443}]), \
             patch.object(hy, "unpublish") as unpublish, patch.object(hy, "run") as run:
            with self.assertRaisesRegex(ValueError, "保留安装"):
                hy.uninstall()
        unpublish.assert_not_called()
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
