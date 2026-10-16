"""在隔离集成测试中验证可选的真实客户端内核。"""
import json
from pathlib import Path
import subprocess
import tempfile
import time


def check_clients(hy, state):
    binaries = {"sing-box": Path("/opt/test-clients/sing-box"), "mihomo": Path("/opt/test-clients/mihomo")}
    for kind, binary in binaries.items():
        if not binary.is_file():
            print(f"SKIP: {kind}（未提供测试内核）")
            continue
        with tempfile.TemporaryDirectory(prefix=f"hy-{kind}-") as tmp:
            root = Path(tmp)
            config_path = root / "config.json"
            files = hy.client_files(state)
            config = json.loads(files["sing-box.json" if kind == "sing-box" else "clash.yaml"])
            config_path.write_text(json.dumps(config))
            if kind == "sing-box":
                check = [str(binary), "check", "-c", str(config_path)]
                command = [str(binary), "run", "-c", str(config_path)]
            else:
                check = [str(binary), "-t", "-d", tmp, "-f", str(config_path)]
                command = [str(binary), "-d", tmp, "-f", str(config_path)]
            result = subprocess.run(check, capture_output=True, timeout=120)
            assert result.returncode == 0, result.stdout.decode() + result.stderr.decode()
            # 测试目标是本机 HTTP 服务；移除局域网直连规则，确保请求真实经过 HY2。
            if kind == "sing-box":
                config["route"]["rules"] = []
                config["inbounds"][0]["listen_port"] = 18082
            else:
                config["mixed-port"] = 18082
                config["rules"] = ["MATCH,节点选择"]
            config_path.write_text(json.dumps(config))
            with (root / "client.log").open("w") as log:
                client = subprocess.Popen(command, stdout=log, stderr=log)
                try:
                    success = False
                    for _ in range(20):
                        time.sleep(0.2)
                        result = subprocess.run(
                            ["curl", "-fsS", "--noproxy", "", "--proxy", "socks5h://127.0.0.1:18082",
                             "--max-time", "3", "http://127.0.0.1:18080/"], capture_output=True)
                        if result.returncode == 0 and result.stdout == b"hy-end-to-end-ok":
                            success = True
                            break
                        if client.poll() is not None:
                            break
                    assert success, (root / "client.log").read_text()
                finally:
                    client.terminate()
                    client.wait(timeout=10)
            print(f"PASS: {kind} full config validation / real HY2 proxy / obfs={bool(state.get('obfs'))}")
