"""仅在一次性 systemd 容器测试 IP 订阅及不受旧暂停管理锁影响；先运行 live_systemd.py。"""
import contextlib
import http.client
import importlib.util
import io
import os
from pathlib import Path
import pty
import socket
import subprocess
import time
from unittest.mock import patch

if os.environ.get("HY_DISPOSABLE_TEST") != "1" or not Path("/.dockerenv").exists():
    raise SystemExit("仅允许在一次性 Docker 测试容器中运行。")
spec = importlib.util.spec_from_file_location("hy", Path(__file__).parents[1] / "hy.py")
hy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hy)


def cli(command, inputs):
    master, slave = pty.openpty()
    try:
        process = subprocess.Popen(["hy", command], stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        os.write(master, inputs.encode())
        stdout, stderr = process.communicate(timeout=45)
        assert process.returncode == 0, stderr.decode() + stdout.decode()
        return stdout.decode()
    finally:
        os.close(slave)
        os.close(master)


def get(publication, name, method="GET"):
    # systemctl restart 返回后，Python 进程还需要短暂时间完成监听。
    for attempt in range(20):
        conn = http.client.HTTPConnection("127.0.0.1", publication["port"], timeout=3)
        try:
            conn.request(method, f"/hy-sub-{publication['token']}/{name}")
            result = conn.getresponse()
            return result.status, result.read()
        except ConnectionRefusedError:
            if attempt == 19:
                raise
            time.sleep(0.1)
        finally:
            conn.close()


state = hy.load_state()
state.update(cert_mode="selfsigned", domain="hy.invalid",
             cert_source=str(hy.ETC / "selfsigned/fullchain.pem"), key_source=str(hy.ETC / "selfsigned/privkey.pem"))
with patch.object(hy, "collect_state", return_value=state), contextlib.redirect_stdout(io.StringIO()):
    hy.configure()
core_pid = hy.output(["systemctl", "show", "-p", "MainPID", "--value", hy.SERVICE])
stopped = subprocess.Popen(["python3", "-c", '''import fcntl,os,signal,time
lock=open('/run/lock/demonyxp-hy.lock','w')
fcntl.flock(lock,fcntl.LOCK_EX)
print('locked',flush=True)
os.kill(os.getpid(),signal.SIGSTOP)
time.sleep(300)
'''], stdout=subprocess.PIPE)
try:
    assert stopped.stdout.readline().strip() == b"locked"
    before_upgrade = hy.STATE.read_bytes()
    subprocess.run(["python3", str(Path(hy.__file__)), "install"], capture_output=True, timeout=5, check=True)
    assert hy.STATE.read_bytes() == before_upgrade
    subprocess.run(["hy", "status"], capture_output=True, timeout=5, check=True)
    with socket.socket() as port_probe:
        port_probe.bind(("127.0.0.1", 0))
        port = port_probe.getsockname()[1]
    cli("publish", f"1\n127.0.0.1\n{port}\n")
    installed = hy.load_state()
    publication = installed["publication"]
    for name in hy.SUBSCRIPTIONS:
        assert get(publication, name) == (200, hy.client_files(installed)[name].encode())
    assert get(publication, "../state.json")[0] == 404
    assert get(publication, ".hy-owner")[0] == 404
    assert get({**publication, "token": "b" * 48}, "hiddify.txt")[0] == 404
    assert get(publication, "hiddify.txt", method="HEAD") == (200, b"")
    assert hy.output(["systemctl", "show", "-p", "User", "--value", hy.SUB_SERVICE]) == hy.USER
    assert core_pid == hy.output(["systemctl", "show", "-p", "MainPID", "--value", hy.SERVICE])
    print("PASS: suspended legacy lock does not block CLI / real IP subscriptions / no VPN restart / low-privilege service")
finally:
    stopped.kill()
    stopped.wait(timeout=5)

# 模拟防火墙写入失败，刷新失败时保留旧订阅内容、状态和服务。
previous = hy.subscription_config_path().read_bytes()
changed = {**installed, "password": "replacement-test-password-123"}
with patch.object(hy, "firewall_apply", side_effect=RuntimeError("injected firewall failure")), \
     contextlib.redirect_stdout(io.StringIO()):
    try:
        hy.activate_http_subscription(changed)
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected rollback")
assert hy.subscription_config_path().read_bytes() == previous
assert hy.load_state() == installed
assert get(publication, "hiddify.txt") == (200, hy.client_files(installed)["hiddify.txt"].encode())

with patch.object(hy, "collect_state", return_value=changed), contextlib.redirect_stdout(io.StringIO()):
    hy.configure()
assert hy.load_state()["publication"] == publication
assert get(publication, "hiddify.txt") == (200, hy.client_files(hy.load_state())["hiddify.txt"].encode())
previous = hy.subscription_config_path().read_bytes()
with patch.object(hy, "collect_state", return_value=hy.load_state()), \
     patch.object(hy, "server_config", return_value={"listen": "invalid"}), contextlib.redirect_stdout(io.StringIO()):
    try:
        hy.configure()
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected invalid node config failure")
assert hy.subscription_config_path().read_bytes() == previous
assert get(publication, "hiddify.txt")[0] == 200
print("PASS: subscription refresh / activation failure rollback / node config rollback preserves subscription permissions")

subprocess.run(["hy", "unpublish"], check=True, capture_output=True)
assert "publication" not in hy.load_state()
assert not hy.subscription_config_path().exists()
try:
    get(publication, "hiddify.txt")
except OSError:
    pass
else:
    raise AssertionError("revoked listener should stop")
cli("publish", f"1\n127.0.0.1\n{port}\n")
assert hy.load_state()["publication"]["token"] != publication["token"]
cli("uninstall", "UNINSTALL\n")
assert not hy.ETC.exists()
assert not (hy.UNIT_DIR / hy.SUB_SERVICE).exists()
assert subprocess.run(["systemctl", "is-active", "--quiet", hy.SUB_SERVICE]).returncode != 0
print("PASS: unpublish closes IP listener / re-publish rotates URL / uninstall removes subscription service")
