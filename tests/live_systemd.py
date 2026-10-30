"""仅在一次性 root/systemd 容器运行，创建测试 CA 并执行真实 HY2 握手。"""
import contextlib
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
from unittest.mock import patch
from client_cores import check_clients
from legacy_upgrade import check_upgrades

if os.environ.get("HY_DISPOSABLE_TEST") != "1" or not Path("/.dockerenv").exists():
    raise SystemExit("拒绝运行：仅限设置 HY_DISPOSABLE_TEST=1 的一次性 Docker 容器。")

spec = importlib.util.spec_from_file_location("hy", Path(__file__).parents[1] / "hy.py")
hy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hy)


def run(args):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


class TestHTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"hy-end-to-end-ok")

    def log_message(self, *args):
        pass


def connect(state, reject=False):
    config = json.loads(hy.client_files(state)["native.json"])
    config["socks5"]["listen"] = "127.0.0.1:18081"
    config_path = Path("/tmp/hy-live-client.json")
    config_path.write_text(json.dumps(config))
    with open("/tmp/hy-live-client.log", "w") as log:
        client = subprocess.Popen([str(hy.BIN), "client", "-c", str(config_path)], stdout=log, stderr=log)
        try:
            for _ in range(3 if reject else 20):
                time.sleep(0.2)
                result = subprocess.run(["curl", "-fsS", "--noproxy", "", "--proxy", "socks5h://127.0.0.1:18081",
                                         "--max-time", "3", "http://127.0.0.1:18080/"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if result.returncode == 0:
                    assert not reject, "错误指纹不应建立连接"
                    assert result.stdout == b"hy-end-to-end-ok"
                    return
                if client.poll() is not None:
                    break
            if not reject:
                raise AssertionError("真实 HY2 握手失败；查看 /tmp/hy-live-client.log")
        finally:
            client.terminate()
            client.wait(timeout=10)


with tempfile.TemporaryDirectory(prefix="hy-live-") as tmp:
    root = Path(tmp)
    ca, ca_key = root / "ca.crt", root / "ca.key"
    key, cert, csr = root / "key.pem", root / "fullchain.pem", root / "request.csr"
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key),
         "-out", str(ca), "-subj", "/CN=HY disposable test CA", "-days", "3",
         "-addext", "basicConstraints=critical,CA:TRUE"])
    run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
         "-out", str(csr), "-subj", "/CN=vpn.example.test"])
    extensions = root / "extensions.cnf"
    extensions.write_text("subjectAltName=DNS:vpn.example.test\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n")
    run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
         "-CAcreateserial", "-out", str(cert), "-days", "3", "-extfile", str(extensions)])
    cert.write_bytes(cert.read_bytes() + ca.read_bytes())
    if shutil.which("update-ca-certificates"):
        shutil.copy2(ca, "/usr/local/share/ca-certificates/hy-disposable.crt")
        run(["update-ca-certificates"])
    else:
        shutil.copy2(ca, "/etc/pki/ca-trust/source/anchors/hy-disposable.crt")
        run(["update-ca-trust", "extract"])
    hy.check_certificate(cert, key, "vpn.example.test")
    state = {"owner": hy.MARKER, "domain": "vpn.example.test", "server": "127.0.0.1", "port": 24443,
             "password": "disposable-test:@/#?12345", "name": "测试节点", "obfs": "",
             "cert_source": str(cert), "key_source": str(key)}
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 18080), TestHTTP)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        # 在隔离容器里实际下载、校验、创建账户、安装并启动 systemd 服务。
        with patch.object(hy, "installation_state", return_value=state), patch.object(hy, "prompt", return_value="n"), \
             contextlib.redirect_stdout(io.StringIO()):
            hy.install()
        assert hy.service_active()
        assert hy.output(["systemctl", "show", "-p", "User", "--value", hy.SERVICE]) == hy.USER
        installed = hy.load_state()
        connect(installed)
        print("PASS: install / systemd low-privilege service / real HY2 proxy request")
        check_clients(hy, installed)
        with contextlib.redirect_stdout(io.StringIO()):
            hy.ensure_monitor()
            hy.set_limit("127.0.0.1", upload="1000", download="1000")
        installed = hy.load_state()
        connect(installed)
        totals = hy.traffic_snapshot(hy.nft_table())["127.0.0.1"]
        assert totals["upload"] > 0 and totals["download"] > 0
        print("PASS: real HY2 connection with IP counters and limits")

        # 故意写入无效的监听地址，验证启动失败后的真实回滚和权限恢复。
        valid_builder = hy.server_config

        def broken_config(s):
            config = valid_builder(s)
            config["listen"] = "invalid listen address"
            return config

        with patch.object(hy, "collect_state", return_value=installed), patch.object(hy, "server_config", side_effect=broken_config):
            try:
                hy.configure()
            except (RuntimeError, subprocess.CalledProcessError):
                pass
            else:
                raise AssertionError("无效配置未被拒绝")
        connect(hy.load_state())
        print("PASS: failed configuration rollback / restored certificate permissions")

        # 测试同一批导出参数开启混淆后仍可建立真实连接。
        changed = {**installed, "obfs": "test-obfs-special:&?#12345"}
        with patch.object(hy, "collect_state", return_value=changed), contextlib.redirect_stdout(io.StringIO()):
            hy.configure()
        connect(hy.load_state())
        print("PASS: Salamander / escaped client authentication")
        check_clients(hy, hy.load_state())

        # 模拟通过校验但无法工作的升级程序，确认保留旧二进制及可用配置。
        def bad_download(destination):
            Path(destination).write_text("#!/bin/sh\nexit 1\n")
            os.chmod(destination, 0o755)
            return "app/v2.99.0"

        before = hy.BIN.read_bytes()
        with patch.object(hy, "download_core", side_effect=bad_download):
            try:
                hy.update()
            except (RuntimeError, subprocess.CalledProcessError):
                pass
            else:
                raise AssertionError("无效内核未触发回滚")
        assert hy.BIN.read_bytes() == before
        connect(hy.load_state())
        print("PASS: failed core update rollback")

        # 发布只允许指定随机目录，撤销时保留用户原有网站文件。
        webroot = Path("/var/www/hy-disposable")
        webroot.mkdir(parents=True, exist_ok=True)
        (webroot / "index.html").write_text("keep existing website")
        published = hy.load_state()
        published["publication"] = hy.publication_settings(str(webroot), "https://vpn.example.test")
        hy.atomic_write(hy.STATE, hy.json_text(published))
        with patch.object(hy.urllib.request, "urlopen", side_effect=OSError("offline fixture")), contextlib.redirect_stdout(io.StringIO()):
            hy.publish_files(published)
        target = hy.publication_dir(published["publication"])
        for name in hy.SUBSCRIPTIONS:
            assert (target / name).read_text() == hy.client_files(published)[name]
        hy.unpublish()
        assert not target.exists()
        assert (webroot / "index.html").read_text() == "keep existing website"
        print("PASS: static subscription publish / removal preserves existing site")

        core_copy = root / "core-copy"
        shutil.copy2(hy.BIN, core_copy)
        with patch.object(hy, "prompt", return_value="UNINSTALL"):
            hy.uninstall()
        assert not hy.ETC.exists() and not hy.BIN.exists()
        assert (hy.DATA / "backups").is_dir()
        assert not hy.service_active()
        assert hy.nft_table() is None
        print("PASS: uninstall retains backups")

        def reuse_download(destination):
            shutil.copy2(core_copy, destination)
            return installed["core_version"]

        with patch.object(hy, "installation_state", return_value=state), patch.object(hy, "download_core", side_effect=reuse_download), \
             patch.object(hy, "prompt", return_value="n"), contextlib.redirect_stdout(io.StringIO()):
            hy.install()
        connect(hy.load_state())
        print("PASS: reinstall after uninstall")

        # 纯 IP 首次安装：不提供域名证书，不把自签证书加入系统 CA。
        with patch.object(hy, "prompt", return_value="UNINSTALL"), contextlib.redirect_stdout(io.StringIO()):
            hy.uninstall()
        with patch.object(hy, "detect_public_ip", return_value="127.0.0.1"), \
             patch.object(hy, "prompt", side_effect=["1", "2", "y"]), \
             patch.object(hy, "download_core", side_effect=reuse_download), contextlib.redirect_stdout(io.StringIO()):
            hy.install()
        installed_ip = hy.load_state()
        assert "cert_sha256" in installed_ip
        connect(installed_ip)
        check_clients(hy, installed_ip)
        print("PASS: IP-only install without trusted certificate / pinned clients")
        fingerprint = installed_ip["cert_sha256"]
        hy.sync_certificate(installed_ip)
        assert hy.load_state()["cert_sha256"] == fingerprint
        changed_ip = {**installed_ip, "obfs": "selfsigned-obfs-test"}
        with patch.object(hy, "collect_state", return_value=changed_ip), contextlib.redirect_stdout(io.StringIO()):
            hy.configure()
        assert hy.load_state()["cert_sha256"] == fingerprint
        connect(hy.load_state())
        check_clients(hy, hy.load_state())
        wrong = {**hy.load_state(), "cert_sha256": "0" * 64, "cert_pem": cert.read_text()}
        connect(wrong, reject=True)
        check_clients(hy, wrong, reject=True)
        print("PASS: stable self-signed certificate / obfs / wrong certificate rejected")
        # 从自签模式切回原有证书模式，旧版配置仍应正常工作。
        with patch.object(hy, "collect_state", return_value=state), contextlib.redirect_stdout(io.StringIO()):
            hy.configure()
        connect(hy.load_state())
        print("PASS: switch IP mode back to existing certificate")
        check_upgrades(hy, state, reuse_download, connect)
    finally:
        httpd.shutdown()
