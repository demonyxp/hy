"""在隔离容器验证真实终端菜单及非交互输入保护；先运行 live_systemd.py。"""
import os
import json
from pathlib import Path
import pty
import subprocess

if os.environ.get("HY_DISPOSABLE_TEST") != "1" or not Path("/.dockerenv").exists():
    raise SystemExit("仅允许在一次性 Docker 测试容器中运行。")

state = Path("/etc/hy/state.json")
before = state.read_bytes()
result = subprocess.run(["hy", "configure"], input="y\n", text=True, capture_output=True, timeout=10)
assert result.returncode != 0 and "交互终端" in result.stderr
assert state.read_bytes() == before
result = subprocess.run(["hy", "status"], capture_output=True, text=True, check=True)
version = json.loads((Path(__file__).parents[1] / "release.json").read_text())["version"]
assert all(value in result.stdout for value in (f"HY {version}", "开机启动", "UDP"))
master, slave = pty.openpty()
try:
    process = subprocess.Popen(["hy"], stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.write(master, b"0\n")
    stdout, stderr = process.communicate(timeout=10)
    assert process.returncode == 0, stderr.decode()
    assert all(value in stdout.decode() for value in ("安装与配置", "连接与订阅", "服务管理", "监控与限速", "更新与维护"))
finally:
    os.close(slave)
    os.close(master)
print("PASS: real CLI status / terminal menu / noninteractive configure rejects piped confirmation without state changes")
