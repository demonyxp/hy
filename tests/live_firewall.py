"""仅在一次性容器验证真实 UFW/firewalld 的新增、复用与清理。"""
import importlib.util
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

if os.environ.get("HY_DISPOSABLE_TEST") != "1" or not Path("/.dockerenv").exists():
    raise SystemExit("拒绝运行：仅限 HY_DISPOSABLE_TEST=1 的一次性 Docker 容器。")

spec = importlib.util.spec_from_file_location("hy", Path(__file__).parents[1] / "hy.py")
hy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hy)


with tempfile.TemporaryDirectory(prefix="hy-firewall-") as tmp, patch.object(hy, "DATA", Path(tmp)):
    state = {"port": 24443, "firewall_mode": "auto"}
    try:
        hy.run(["systemctl", "stop", "firewalld"])
        hy.run(["ufw", "--force", "reset"])
        hy.run(["ufw", "allow", "22/tcp", "comment", "existing-ssh"])
        hy.run(["ufw", "allow", "443/tcp", "comment", "existing-web"])
        hy.run(["ufw", "allow", "24444/udp", "comment", "existing-user"])
        hy.run(["ufw", "--force", "enable"])
        assert hy.firewall_backend() == "ufw"
        hy.firewall_apply(state)
        first = hy.firewall_records()
        hy.firewall_apply(state)
        assert first == hy.firewall_records() and len(first) == 1
        hy.firewall_apply({**state, "port": 24444})
        assert hy.firewall_records() == first
        hy.firewall_prune(24444)
        rules = hy.output(["ufw", "show", "added"])
        assert "24443/udp" not in rules
        assert all(value in rules for value in ("24444/udp", "existing-user", "existing-ssh", "existing-web"))
        assert hy.firewall_records() == []
        print("PASS: real UFW / duplicate / existing-rule reuse / port migration / SSH and web rules preserved")
        hy.run(["ufw", "--force", "disable"])
        hy.run(["systemctl", "start", "dbus", "firewalld"])
        hy.run(["firewall-cmd", "--zone=public", "--add-interface=eth0"])
        hy.run(["firewall-cmd", "--zone=public", "--add-port=24444/udp"])
        hy.run(["firewall-cmd", "--zone=public", "--permanent", "--add-port=24444/udp"])
        assert hy.firewall_backend() == "firewalld"
        hy.firewall_apply(state)
        records = hy.firewall_records()
        assert len(records) == 2
        hy.firewall_apply(state)
        hy.firewall_apply({**state, "port": 24444})
        assert hy.firewall_records() == records
        hy.firewall_prune(24444)
        for flag in ([], ["--permanent"]):
            ports = hy.output(["firewall-cmd", "--zone=public", *flag, "--list-ports"])
            assert "24443/udp" not in ports and "24444/udp" in ports
        assert hy.firewall_records() == []
        print("PASS: real firewalld / runtime and permanent / duplicate / existing-rule reuse / cleanup")
    finally:
        hy.run(["ufw", "--force", "disable"])
        hy.run(["systemctl", "disable", "--now", "firewalld"])
