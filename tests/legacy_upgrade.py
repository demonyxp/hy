"""由隔离 systemd 测试调用，实际安装历史版本再升级。"""
import contextlib
import importlib.util
import io
from pathlib import Path
from unittest.mock import patch


def check_upgrades(hy, state, reuse_download, connect):
    sources = [Path(f"/opt/test-legacy/v{version}.py") for version in ("0.1.0", "0.2.0", "0.3.0")]
    if not all(source.is_file() for source in sources):
        print("SKIP: 历史版本实际升级（未提供 /opt/test-legacy/v0.x.0.py）")
        return
    for source in sources:
        with patch.object(hy, "prompt", return_value="UNINSTALL"), contextlib.redirect_stdout(io.StringIO()):
            hy.uninstall()
        spec = importlib.util.spec_from_file_location("legacy_hy", source)
        old = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(old)
        legacy_state = dict(state)
        if old.VERSION != "0.1.0":
            legacy_state.update(cert_mode="selfsigned", domain="hy.invalid",
                                cert_source=str(hy.ETC / "selfsigned/fullchain.pem"),
                                key_source=str(hy.ETC / "selfsigned/privkey.pem"))
        with patch.object(old, "collect_state", return_value=legacy_state), \
             patch.object(old, "download_core", side_effect=reuse_download), \
             patch.object(old, "prompt", return_value="n"), contextlib.redirect_stdout(io.StringIO()):
            old.install()
        webroot = Path("/var/www/hy-upgrade-test")
        webroot.mkdir(parents=True, exist_ok=True)
        installed = old.load_state()
        installed["publication"] = old.publication_settings(webroot, "https://vpn.example.test")
        old.atomic_write(old.STATE, old.json_text(installed))
        with patch.object(old.urllib.request, "urlopen", side_effect=OSError("local test")), contextlib.redirect_stdout(io.StringIO()):
            old.publish_files(installed)
        published = {str(p): p.read_bytes() for p in webroot.rglob("*") if p.is_file()}
        # 原版安装器产生真实配置；v0.3 同时验证监控限速配置保持不变。
        if old.VERSION == "0.3.0":
            with contextlib.redirect_stdout(io.StringIO()):
                old.set_limit("127.0.0.1", upload="100", download="100")
        for active in (True, False):
            hy.run(["systemctl", "start" if active else "stop", hy.SERVICE])
            hy.run(["systemctl", "enable" if active else "disable", hy.SERVICE])
            before = {str(p.relative_to(hy.ETC)): p.read_bytes() for p in hy.ETC.rglob("*") if p.is_file()}
            pid = hy.output(["systemctl", "show", "-p", "MainPID", "--value", hy.SERVICE])
            with contextlib.redirect_stdout(io.StringIO()):
                hy.install()
            after = {str(p.relative_to(hy.ETC)): p.read_bytes() for p in hy.ETC.rglob("*") if p.is_file()}
            assert before == after
            assert published == {str(p): p.read_bytes() for p in webroot.rglob("*") if p.is_file()}
            assert pid == hy.output(["systemctl", "show", "-p", "MainPID", "--value", hy.SERVICE])
            assert hy.service_active() == active
            assert hy.output(["systemctl", "show", "-p", "UnitFileState", "--value", hy.SERVICE]) == ("enabled" if active else "disabled")
            assert (hy.LIB / "hy.py").read_bytes() == Path(hy.__file__).read_bytes()
        hy.start()
        connect(hy.load_state())
        print(f"PASS: real {old.VERSION} install -> 0.4.0 / unchanged config, PID, startup / HY2 handshake")
