"""一次性 systemd 容器中的真实 UDP 计数/限速测试；先运行 live_systemd.py。"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
from unittest.mock import patch

if os.environ.get("HY_DISPOSABLE_TEST") != "1" or not Path("/.dockerenv").exists():
    raise SystemExit("仅允许在一次性 Docker 测试容器中运行。")
spec = importlib.util.spec_from_file_location("hy", Path(__file__).parents[1] / "hy.py")
hy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hy)


def udp_server(host, port, family):
    sock = socket.socket(family, socket.SOCK_DGRAM)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.bind((host, port))
    sock.settimeout(0.1)
    stop = threading.Event()
    def loop():
        while not stop.is_set():
            try:
                _, peer = sock.recvfrom(4096)
                sock.sendto(b"r" * 1200, peer)
            except (TimeoutError, OSError):
                pass
    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    return sock, stop, thread


def exchange(source="127.0.0.2", port=44553, payload=1024, duration=2):
    family = socket.AF_INET6 if ":" in source else socket.AF_INET
    destination = "::1" if family == socket.AF_INET6 else "127.0.0.1"
    count = 0
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.bind((source, 0))
        client.setblocking(False)
        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            client.sendto(b"q" * payload, (destination, port))
            time.sleep(0.002)
            while True:
                try:
                    count += len(client.recvfrom(4096)[0])
                except BlockingIOError:
                    break
    return count


original = hy.load_state()
fixtures = []
try:
    # 哨兵表代表其他防火墙规则，整个测试期间必须保持不变。
    hy.run(["nft", "-f", "-"], input='add table inet hy_foreign_test { comment "unrelated"; }\n', text=True)
    foreign = hy.output(["nft", "-j", "list", "table", "inet", "hy_foreign_test"])
    for host, port, family in (("127.0.0.1", 44553, socket.AF_INET),
                               ("127.0.0.1", 44554, socket.AF_INET), ("::1", 44553, socket.AF_INET6)):
        fixtures.append(udp_server(host, port, family))
    state = {**original, "port": 44553, "traffic": {"enabled": False, "limits": {}}}
    hy.atomic_write(hy.STATE, hy.json_text(state))
    hy.ensure_monitor()
    baseline = exchange()
    assert baseline > 300000, baseline
    counters = hy.traffic_snapshot(hy.nft_table())
    assert counters["127.0.0.2"]["upload"] > 0 and counters["127.0.0.2"]["download"] > 0
    hy.set_limit("127.0.0.2", upload="0.1", download="0")
    assert hy.traffic_snapshot(hy.nft_table())["127.0.0.2"] == counters["127.0.0.2"]
    upload_limited = exchange()
    assert 0 < upload_limited < 100000, upload_limited
    assert exchange("127.0.0.3") > 300000
    assert exchange(port=44554) > 300000
    # 即使 TCP 使用同一个数字端口，也不应受 UDP 规则影响。
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 44553))
        listener.listen()
        with socket.create_connection(("127.0.0.1", 44553), timeout=2):
            connection, _ = listener.accept()
            connection.close()
    print("PASS: IPv4 upload policing / counters preserved / other IP, UDP port and TCP unaffected")
    hy.set_limit("127.0.0.2", upload="0", download="0.1")
    download_limited = exchange(payload=1)
    assert 0 < download_limited < 100000, download_limited
    hy.set_limit("::1", upload="0", download="0.1")
    ipv6_limited = exchange("::1", payload=1)
    assert 0 < ipv6_limited < 100000, ipv6_limited
    print(f"PASS: download policing IPv4={download_limited}B IPv6={ipv6_limited}B per 2s; baseline={baseline}B")
    hy.remove_limit("127.0.0.2")
    assert exchange() > 300000
    assert "::1" in hy.load_state()["traffic"]["limits"]
    print("PASS: remove limit restores throughput and preserves other IP limits")

    # 原子批次校验失败不能删除已有规则或计数。
    saved = hy.output(["nft", "-j", "list", "chain", "inet", hy.TRAFFIC_TABLE, "download_limits"])
    with patch.object(hy, "traffic_rules", return_value=f"flush chain inet {hy.TRAFFIC_TABLE} download_limits\ninvalid command\n"):
        try:
            hy.apply_traffic(hy.load_state())
        except subprocess.CalledProcessError:
            pass
        else:
            raise AssertionError("无效规则未被拒绝")
    assert hy.output(["nft", "-j", "list", "chain", "inet", hy.TRAFFIC_TABLE, "download_limits"]) == saved
    print("PASS: invalid atomic rule update preserves active limits")

    # 模拟重启丢失内核规则，验证已启用的 systemd 服务可从配置恢复。
    hy.run(["nft", "delete", "table", "inet", hy.TRAFFIC_TABLE])
    hy.run(["systemctl", "start", hy.TRAFFIC_SERVICE])
    assert hy.nft_table() is not None
    assert 0 < exchange("::1", payload=1) < 100000
    print("PASS: systemd restores persisted limits")
    with open("/tmp/hy-monitor-test.log", "w") as log:
        monitor = subprocess.Popen(["/usr/local/bin/hy", "monitor"], stdout=log, stderr=log)
        try:
            time.sleep(0.5)
            assert monitor.poll() is None
            hy.run(["/usr/local/bin/hy", "limit", "127.0.0.2", "--upload", "1", "--download", "2"])
        finally:
            monitor.terminate()
            monitor.wait(timeout=5)
    hy.run(["/usr/local/bin/hy", "monitor", "--once"])
    print("PASS: CLI monitor does not block concurrent rate-limit changes")
    # 修改监听端口后，旧端口恢复不限速，新端口使用原来的 IP 限速配置。
    hy.set_limit("127.0.0.2", upload="0", download="0.1")
    moved = {**hy.load_state(), "port": 44554}
    hy.save_traffic(moved, moved["traffic"])
    assert exchange(port=44553, payload=1) > 300000
    assert 0 < exchange(port=44554, payload=1) < 100000
    print("PASS: changing HY2 UDP port moves enforcement off the old port")
    hy.monitor_off()
    assert hy.nft_table() is None
    assert hy.output(["nft", "-j", "list", "table", "inet", "hy_foreign_test"]) == foreign
    hy.run(["nft", "-f", "-"], input=f'add table inet {hy.TRAFFIC_TABLE} {{ comment "foreign"; }}\n', text=True)
    try:
        hy.apply_traffic(hy.load_state())
    except ValueError:
        pass
    else:
        raise AssertionError("不能操作同名外部表")
    print("PASS: disable preserves unrelated firewall; foreign ownership rejected")
finally:
    for sock, stop, thread in fixtures:
        stop.set()
        thread.join(timeout=2)
        sock.close()
    subprocess.run(["nft", "delete", "table", "inet", hy.TRAFFIC_TABLE], capture_output=True)
    subprocess.run(["nft", "delete", "table", "inet", "hy_foreign_test"], capture_output=True)
    hy.atomic_write(hy.STATE, hy.json_text(original))
    hy.apply_traffic(original)
    if not original.get("traffic", {}).get("enabled"):
        hy.run(["systemctl", "disable", "--now", hy.TRAFFIC_SERVICE])
