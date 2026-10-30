#!/usr/bin/env python3
"""面向 Debian / Ubuntu / Amazon Linux 2023 的 Hysteria2 单节点管理器。"""

import argparse
import base64
from decimal import Decimal, InvalidOperation
import datetime as dt
import getpass
import hashlib
import http.server
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

VERSION = "0.5.0"
MANAGER_URL = "https://raw.githubusercontent.com/demonyxp/hy"
REPO = "HyNetworks/hysteria"
ETC = Path("/etc/hy")
LIB = Path("/usr/local/lib/hy")
DATA = Path("/var/lib/hy")
UNIT_DIR = Path("/etc/systemd/system")
STATE = ETC / "state.json"
BIN = LIB / "hysteria"
SERVICE = "hy-server.service"
USER = "hyproxy"
MARKER = "demonyxp/hy"
TRAFFIC_TABLE = "hy_traffic"
TRAFFIC_SERVICE = "hy-traffic.service"
SUB_SERVICE = "hy-subscription.service"


def subscription_config_path():
    return ETC / "subscription.json"


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, **kwargs)


def output(args):
    return run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()


def atomic_write(path, content, mode=0o600, gid=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".hy-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content.encode() if isinstance(content, str) else content)
        os.chmod(temp, mode)
        if gid is not None:
            os.chown(temp, 0, gid)
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def json_text(value):
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def domain(value):
    value = value.strip().rstrip(".").lower()
    if len(value) > 253 or "." not in value or not all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in value.split(".")
    ):
        raise ValueError("请输入域名，例如 vpn.example.com，不要带 https:// 或路径。")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("证书域名不能填写 IP 地址。")


def endpoint(value):
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return domain(value)


def port_number(value):
    if not re.fullmatch(r"[0-9]{1,5}", str(value)) or not 1 <= int(value) <= 65535:
        raise ValueError("端口必须是 1～65535 的整数。")
    return int(value)


def prompt(label, default=None, secret=False):
    if not sys.stdin.isatty():
        raise ValueError("此操作需要交互终端，请登录服务器后执行 hy；SSH 请使用 ssh -t。")
    hint = f" [{default}]" if default is not None and not secret else ""
    value = (getpass.getpass if secret else input)(f"{label}{hint}: ").strip()
    return value or default or ""


def ask_valid(label, validator, default=None):
    while True:
        value = prompt(label, default)
        try:
            return validator(value)
        except ValueError as exc:
            print(exc)


def load_state():
    if not STATE.is_file():
        raise ValueError("尚未安装，请先运行 hy install。")
    state = json.loads(STATE.read_text())
    if state.get("owner") != MARKER:
        raise ValueError("配置不属于本工具，停止操作。")
    return state


def check_certificate(cert, key, hostname, self_signed=False):
    cert, key = Path(cert), Path(key)
    if not cert.is_file() or not key.is_file():
        raise ValueError("证书或私钥不存在；请先在宝塔申请域名证书，或输入已有证书路径。")
    run(["openssl", "x509", "-in", cert, "-noout", "-checkend", "86400"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    run(["openssl", "x509", "-in", cert, "-noout", "-checkhost", hostname],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    cert_pub = output(["openssl", "x509", "-in", cert, "-pubkey", "-noout"])
    key_pub = output(["openssl", "pkey", "-in", key, "-passin", "pass:", "-pubout"])
    if cert_pub != key_pub:
        raise ValueError("证书与私钥不匹配。")
    # 域名模式使用系统 CA；自签模式只信任本工具生成的证书。
    run(["openssl", "verify", "-purpose", "sslserver", "-verify_hostname", hostname,
         *(["-CAfile", cert] if self_signed else []),
         "-untrusted", cert, cert],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def ip_literal(value):
    try:
        if "%" in value:
            raise ValueError()
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError as exc:
        raise ValueError("请输入服务器 IPv4 或 IPv6 地址，不要填写域名、端口或网址。") from exc


def choice(label, values, default):
    def validate(value):
        value = value.lower()
        if value not in values:
            raise ValueError("请选择：" + "/".join(values))
        return value
    return ask_valid(label, validate, default)


def public_ip(value):
    address = ip_literal(value)
    if not ipaddress.ip_address(address).is_global:
        raise ValueError("请输入可供客户端连接的公网 IP。")
    return address


def detect_public_ip():
    # 只接受 HTTPS 返回的公网字面量；IPv4 优先，失败后尝试 IPv6。
    for family in ("-4", "-6"):
        for url in ("https://api64.ipify.org", "https://ifconfig.co/ip"):
            try:
                return public_ip(output(["curl", family, "-fsS", "--noproxy", "*",
                                         "--proto", "=https", "--connect-timeout", "3",
                                         "--max-time", "5", url]))
            except (ValueError, OSError, subprocess.SubprocessError):
                continue
    return None


def free_port():
    for port in range(24443, 24454):
        if not output(["ss", "-H", "-lun", f"sport = :{port}"]):
            return port
    return ask_valid("默认端口段已占用，请指定 UDP 端口", available_port)


def available_port(value, old=None):
    port = port_number(value)
    check_port(port, old)
    return port


def quick_state():
    print("正在识别公网 IP…")
    address = detect_public_ip()
    if not address:
        address = ask_valid("未能自动识别，请输入服务器公网 IP", public_ip)
    return {"owner": MARKER, "domain": "hy.invalid", "server": address,
            "port": free_port(), "cert_mode": "selfsigned",
            "cert_source": str(ETC / "selfsigned/fullchain.pem"),
            "key_source": str(ETC / "selfsigned/privkey.pem"),
            "password": secrets.token_urlsafe(24), "name": "我的-HY2", "obfs": ""}


def installation_state():
    mode = choice("1=快速安装（纯 IP），2=高级安装（域名或自定义）", ("1", "2"), "1")
    state = quick_state() if mode == "1" else collect_state()
    state["firewall_mode"] = "auto" if choice(
        "本机防火墙：1=自动放行，2=手动放行（云安全组均需自行设置）", ("1", "2"), "1") == "1" else "manual"
    print(f"\n连接地址：{state['server']}  UDP：{state['port']}  节点：{state['name']}")
    print("证书：" + ("自动自签并固定身份" if state["cert_mode"] == "selfsigned" else "已有域名证书"))
    print("防火墙：" + ("自动处理已启用的 UFW/firewalld" if state["firewall_mode"] == "auto" else "手动放行"))
    if choice("确认部署？y/N（地址不正确请取消后选择高级安装）", ("y", "n"), "n") != "y":
        raise ValueError("已取消安装，未写入节点配置。")
    return state


def collect_state(old=None):
    old = old or {}
    def mode_value(value):
        if value not in ("1", "2"):
            raise ValueError("请输入 1 或 2。")
        return value
    mode = ask_valid("安装模式：1=域名/已有证书，2=纯 IP/自动自签证书", mode_value,
                     "2" if old.get("cert_mode") == "selfsigned" else "1")
    self_signed = mode == "2"
    if self_signed:
        host = "hy.invalid"
        old_ip = old.get("server", "")
        try:
            old_ip = ip_literal(old_ip)
        except ValueError:
            old_ip = None
        address = ask_valid("服务器公网 IP", ip_literal, old_ip)
        cert, key = str(ETC / "selfsigned/fullchain.pem"), str(ETC / "selfsigned/privkey.pem")
        print("将自动生成并固定自签证书；不需要域名、宝塔或现成证书。")
    else:
        previous = old if old.get("cert_mode") != "selfsigned" else {}
        host = ask_valid("证书域名（需要已解析到本机）", domain, previous.get("domain"))
        address = ask_valid("客户端连接地址（域名或公网 IP）", endpoint, previous.get("server", host))
        cert_default = previous.get("cert_source", f"/www/server/panel/vhost/cert/{host}/fullchain.pem")
        key_default = previous.get("key_source", f"/www/server/panel/vhost/cert/{host}/privkey.pem")
        while True:
            cert = str(Path(prompt("证书完整路径", cert_default)).expanduser().resolve())
            key = str(Path(prompt("私钥完整路径", key_default)).expanduser().resolve())
            try:
                check_certificate(cert, key, host)
                break
            except (ValueError, subprocess.SubprocessError) as exc:
                print(f"证书检查失败，请重新输入路径：{exc}")
    port = ask_valid("Hysteria2 UDP 端口", lambda v: available_port(v, old), old.get("port", 24443))
    while True:
        password = prompt("节点密码（回车保留或自动生成）", secret=True) or old.get("password") or secrets.token_urlsafe(24)
        if len(password) >= 16 and not any(ord(c) < 32 for c in password):
            break
        print("密码至少 16 个字符，不能包含控制字符。")
    while True:
        name = prompt("节点名称", old.get("name", "我的-HY2"))
        if len(name) <= 80 and not any(ord(c) < 32 for c in name) and name not in ("DIRECT", "REJECT", "节点选择", "GLOBAL"):
            break
        print("节点名称不能超过 80 字符、包含控制字符或使用保留名称。")
    obfs = choice("启用 Salamander 混淆？y/N", ("y", "n"), "y" if old.get("obfs") else "n") == "y"
    return {**old, "owner": MARKER, "domain": host, "server": address, "port": port,
            "cert_mode": "selfsigned" if self_signed else "existing",
            "cert_source": cert, "key_source": key, "password": password, "name": name,
            "obfs": (old.get("obfs") or secrets.token_urlsafe(24)) if obfs else ""}


def server_config(state):
    cfg = {"listen": f":{state['port']}",
           "tls": {"cert": str(ETC / "tls-current/fullchain.pem"),
                   "key": str(ETC / "tls-current/privkey.pem")},
           "auth": {"type": "password", "password": state["password"]},
           "masquerade": {"type": "string", "string": {"content": "Not Found", "statusCode": 404}}}
    if state.get("obfs"):
        cfg["obfs"] = {"type": "salamander", "salamander": {"password": state["obfs"]}}
    return cfg


def client_files(state):
    host = state["server"]
    authority = f"[{host}]" if ":" in host else host
    query = {"sni": state["domain"]}
    node = {"name": state["name"], "type": "hysteria2", "server": host,
            "port": state["port"], "password": state["password"],
            "sni": state["domain"], "skip-cert-verify": False}
    native = {"server": f"{authority}:{state['port']}", "auth": state["password"],
              "tls": {"sni": state["domain"], "insecure": False},
              "socks5": {"listen": "127.0.0.1:1080"}}
    outbound = {"type": "hysteria2", "tag": "proxy", "server": host,
                "server_port": state["port"], "password": state["password"],
                "tls": {"enabled": True, "server_name": state["domain"], "insecure": False}}
    if state.get("cert_mode") == "selfsigned":
        fingerprint = state.get("cert_sha256", "")
        if not re.fullmatch(r"[0-9a-f]{64}", fingerprint) or not state.get("cert_pem"):
            raise ValueError("自签证书尚未生成，不能导出无证书校验的节点。")
        query.update({"insecure": "1", "pinSHA256": fingerprint})
        node.update({"skip-cert-verify": True, "fingerprint": fingerprint})
        native["tls"].update({"insecure": True, "pinSHA256": fingerprint})
        outbound["tls"]["certificate"] = state["cert_pem"].splitlines()
    if state.get("obfs"):
        query.update({"obfs": "salamander", "obfs-password": state["obfs"]})
        node.update({"obfs": "salamander", "obfs-password": state["obfs"]})
        native["obfs"] = {"type": "salamander", "salamander": {"password": state["obfs"]}}
        outbound["obfs"] = {"type": "salamander", "password": state["obfs"]}
    uri = (f"hysteria2://{urllib.parse.quote(state['password'], safe='')}@{authority}:{state['port']}/?"
           f"{urllib.parse.urlencode(query)}#{urllib.parse.quote(state['name'], safe='')}")
    # JSON 也是合法 YAML；用标准库序列化，避免密码、中文或特殊字符破坏配置。
    clash = {"mixed-port": 7890, "allow-lan": False, "mode": "rule", "log-level": "info",
             "proxies": [node], "proxy-groups": [{"name": "节点选择", "type": "select", "proxies": [state["name"], "DIRECT"]}],
             "rules": ["DOMAIN-SUFFIX,local,DIRECT", "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
                       "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve", "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
                       "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve", "IP-CIDR6,::1/128,DIRECT,no-resolve",
                       "IP-CIDR6,fc00::/7,DIRECT,no-resolve", "IP-CIDR6,fe80::/10,DIRECT,no-resolve",
                       "GEOIP,CN,DIRECT", "MATCH,节点选择"]}
    singbox = {"log": {"level": "info"},
               "dns": {"servers": [{"type": "local", "tag": "local"}]},
               "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 7890}],
               "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
               "route": {"rules": [{"ip_is_private": True, "action": "route", "outbound": "direct"}],
                         "final": "proxy", "default_domain_resolver": "local"}}
    subscription = base64.b64encode((uri + "\n").encode()).decode() + "\n"
    return {"node.txt": uri + "\n", "hiddify.txt": subscription, "v2rayn.txt": subscription,
            "clash.yaml": json_text(clash), "flclash.yaml": json_text(clash),
            "sing-box.json": json_text(singbox), "native.json": json_text(native)}


SUBSCRIPTIONS = {"hiddify.txt": "Hiddify", "v2rayn.txt": "v2rayN",
                 "clash.yaml": "Clash Verge Rev / Mihomo", "flclash.yaml": "FlClash",
                 "sing-box.json": "sing-box 配置"}


def export_files(state, show=True):
    target = DATA / "export"
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(target, 0o700)
    for name, content in client_files(state).items():
        atomic_write(target / name, content)
    if show:
        print("\nHiddify / 支持 HY2 的客户端可从剪贴板导入：\n" + client_files(state)["node.txt"])
        for name, label in SUBSCRIPTIONS.items():
            print(f"{label} 本地导入文件：{target / name}")
        print("这些文件含节点密码，请勿提交到 GitHub 或发给陌生人。")


def export_client():
    selected = choice("客户端：1=Hiddify，2=v2rayN，3=Clash/Mihomo/FlClash，4=sing-box，5=全部", ("1", "2", "3", "4", "5"), "1")
    state = load_state()
    export_files(state, show=selected == "5")
    if selected in ("1", "2"):
        print("复制以下链接，在客户端从剪贴板导入：\n" + client_files(state)["node.txt"])
    elif selected in ("3", "4"):
        name = "clash.yaml" if selected == "3" else "sing-box.json"
        print(f"下载后在客户端导入配置文件：{DATA / 'export' / name}")
    if selected != "5" and state.get("publication"):
        name = {"1": "hiddify.txt", "2": "v2rayn.txt", "3": "clash.yaml", "4": "sing-box.json"}[selected]
        print(f"已有订阅：{subscription_url(state['publication'], name)}")
    print("凭据只交给使用者；需要 IP / HTTPS 订阅请在连接与订阅菜单中发布。")


def release_asset(release, arch):
    name = "hysteria-linux-" + {"x86_64": "amd64", "aarch64": "arm64"}.get(arch, "")
    if name == "hysteria-linux-":
        raise ValueError("当前支持 amd64 / arm64。")
    asset = next((a for a in release.get("assets", []) if a["name"] == name), None)
    if not asset or not re.fullmatch(r"sha256:[0-9a-f]{64}", asset.get("digest") or ""):
        raise ValueError("发行版没有可校验的官方二进制，已停止安装。")
    if not asset["browser_download_url"].startswith(f"https://github.com/{REPO}/releases/download/"):
        raise ValueError("下载地址不属于官方发行版。")
    return asset


def download_core(destination):
    print("下载 Hysteria2 官方稳定版并校验 SHA-256…")
    metadata = output(["curl", "-fsSL", "--proto", "=https", "--proto-redir", "=https",
                       "--connect-timeout", "15", "--max-time", "60", "--retry", "2",
                       f"https://api.github.com/repos/{REPO}/releases/latest"])
    release = json.loads(metadata)
    if release.get("prerelease") or release.get("draft") or not re.fullmatch(r"app/v2\.\d+\.\d+", release.get("tag_name", "")):
        raise ValueError("未找到稳定的 Hysteria2 版本。")
    asset = release_asset(release, platform.machine())
    run(["curl", "-fSL", "--proto", "=https", "--proto-redir", "=https", "--connect-timeout", "15",
         "--max-time", "300", "--retry", "2", "-o", destination, asset["browser_download_url"]])
    actual = hashlib.sha256(Path(destination).read_bytes()).hexdigest()
    if actual != asset["digest"].split(":")[1]:
        raise ValueError("二进制 SHA-256 校验失败。")
    os.chmod(destination, 0o755)
    run([destination, "version"])
    return release["tag_name"]


def service_active():
    return subprocess.run(["systemctl", "is-active", "--quiet", SERVICE], check=False).returncode == 0


def restart_checked():
    run(["systemctl", "restart", SERVICE])
    for _ in range(4):
        time.sleep(0.75)
        if not service_active():
            raise RuntimeError("服务启动后退出；请运行 hy logs 查看原因。")


def check_port(port, old=None):
    if old and port == old["port"] and service_active():
        return
    if output(["ss", "-H", "-lun", f"sport = :{port}"]):
        raise ValueError(f"UDP {port} 已被占用，请换端口或手动停用旧服务。TCP 同端口不冲突。")


def group_id():
    import grp
    return grp.getgrnam(USER).gr_gid


def prepare_self_signed(state):
    cert, key = Path(state["cert_source"]), Path(state["key_source"])
    if not cert.exists() and not key.exists():
        if state.get("cert_sha256"):
            raise ValueError("原自签证书丢失，请从备份恢复，避免已导入的指纹失效。")
        cert.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="hy-cert-") as tmp:
            new_cert, new_key = Path(tmp) / "cert.pem", Path(tmp) / "key.pem"
            run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                 "-nodes", "-keyout", new_key, "-out", new_cert, "-days", "3650",
                 "-subj", "/CN=hy.invalid", "-addext", "subjectAltName=DNS:hy.invalid",
                 "-addext", "extendedKeyUsage=serverAuth", "-addext", "basicConstraints=critical,CA:TRUE"],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            atomic_write(cert, new_cert.read_bytes())
            atomic_write(key, new_key.read_bytes())
    check_certificate(cert, key, state["domain"], self_signed=True)
    der = run(["openssl", "x509", "-in", cert, "-outform", "DER"], stdout=subprocess.PIPE).stdout
    fingerprint = hashlib.sha256(der).hexdigest()
    if state.get("cert_sha256") and state["cert_sha256"] != fingerprint:
        raise ValueError("自签证书指纹发生变化，已停止同步；请恢复原证书。")
    state["cert_sha256"] = fingerprint
    state["cert_pem"] = cert.read_text()


def sync_certificate(state):
    if state.get("cert_mode") == "selfsigned":
        prepare_self_signed(state)
    else:
        check_certificate(state["cert_source"], state["key_source"], state["domain"])
    cert = Path(state["cert_source"]).read_bytes()
    key = Path(state["key_source"]).read_bytes()
    digest = hashlib.sha256(cert + key).hexdigest()
    generation = ETC / "tls" / digest
    current = ETC / "tls-current"
    if current.is_symlink() and current.resolve() == generation and generation.is_dir():
        return
    gid = group_id()
    for directory in (ETC / "tls", generation):
        directory.mkdir(exist_ok=True, mode=0o750)
        os.chown(directory, 0, gid)
        os.chmod(directory, 0o750)
    atomic_write(generation / "fullchain.pem", cert, 0o640, gid)
    atomic_write(generation / "privkey.pem", key, 0o640, gid)
    # 原子切换整对证书；旧证书保留在备份中，不改动宝塔源文件权限。
    temp_link = ETC / (".tls-link-" + secrets.token_hex(8))
    temp_link.symlink_to(generation)
    os.replace(temp_link, current)
    print("证书已同步；Hysteria2 会在新握手时读取。")


def units():
    return {SERVICE: f"""# {MARKER}
[Unit]
Description=HY managed Hysteria2 server
After=network-online.target
Wants=network-online.target
[Service]
User={USER}
Group={USER}
ExecStart={BIN} server -c {ETC}/server.json
WorkingDirectory=/var/lib/hy-runtime
StateDirectory=hy-runtime
StateDirectoryMode=0700
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
[Install]
WantedBy=multi-user.target
""", SUB_SERVICE: f"""# {MARKER}
[Unit]
Description=HY IP subscription server
After=network.target
[Service]
User={USER}
Group={USER}
ExecStart=/usr/local/bin/hy serve-subscription
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectControlGroups=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
TasksMax=48
MemoryMax=128M
[Install]
WantedBy=multi-user.target
""", "hy-cert-sync.service": f"""# {MARKER}
[Unit]
Description=HY certificate synchronization
[Service]
Type=oneshot
ExecStart=/usr/local/bin/hy sync-cert
""", "hy-cert-sync.timer": f"""# {MARKER}
[Unit]
Description=HY certificate synchronization timer
[Timer]
OnBootSec=2min
OnUnitActiveSec=1h
Persistent=true
[Install]
WantedBy=timers.target
""", TRAFFIC_SERVICE: f"""# {MARKER}
[Unit]
Description=HY client IP traffic counters and rate limits
After=network-pre.target nftables.service ufw.service
Before={SERVICE}
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/hy traffic-apply
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
"""}


def write_config(state):
    sync_certificate(state)
    atomic_write(ETC / "server.json", json_text(server_config(state)), 0o640, group_id())
    atomic_write(STATE, json_text(state))


def backup():
    target = DATA / "backups" / (dt.datetime.now().strftime("%Y%m%d-%H%M%S-") + secrets.token_hex(3))
    target.mkdir(parents=True, mode=0o700)
    shutil.copytree(ETC, target / "etc", symlinks=True)
    print(f"配置备份：{target}")
    return target


def restore_config(target):
    # 仅恢复本工具的专用目录，不触碰其他服务。
    shutil.rmtree(ETC)
    shutil.copytree(target / "etc", ETC, symlinks=True)
    # copytree 不保留所有者；恢复服务账户的只读权限。
    gid = group_id()
    os.chown(ETC, 0, gid)
    os.chown(ETC / "server.json", 0, gid)
    if subscription_config_path().exists():
        os.chown(subscription_config_path(), 0, gid)
    for path in (ETC / "tls", *(ETC / "tls").rglob("*")):
        if not path.is_symlink():
            os.chown(path, 0, gid)


def install():
    if STATE.exists():
        load_state()
        atomic_write(LIB / "hy.py", Path(__file__).read_bytes(), 0o755)
        print("已刷新管理脚本。修改参数用 hy configure，更新内核用 hy update。")
        return
    for path in (ETC, LIB, Path("/usr/local/bin/hy"), *(UNIT_DIR / n for n in units())):
        if path.exists() or path.is_symlink():
            raise ValueError(f"已有路径 {path}，无法确认归属，拒绝覆盖。")
    # 卸载保留的本工具备份和专用账户可以复用。
    retained = DATA.is_dir() and (DATA / ".hy-owner").is_file() and (DATA / ".hy-owner").read_text() == MARKER
    if DATA.exists() and not retained:
        raise ValueError(f"已有路径 {DATA}，无法确认归属，拒绝覆盖。")
    import pwd
    account_exists = False
    try:
        pwd.getpwnam(USER)
        account_exists = True
    except KeyError:
        pass
    else:
        if not retained:
            raise ValueError(f"已有系统账户 {USER}，请先确认归属。")
    state = installation_state()
    check_port(state["port"])
    with tempfile.TemporaryDirectory(prefix="hy-core-") as tmp:
        candidate = Path(tmp) / "hysteria"
        state["core_version"] = download_core(candidate)
        if not account_exists:
            run(["useradd", "--system", "--user-group", "--no-create-home", "--shell", "/usr/sbin/nologin", USER])
        for directory, mode in ((ETC, 0o750), (LIB, 0o755), (DATA, 0o700)):
            directory.mkdir(mode=mode, exist_ok=True)
            os.chmod(directory, mode)
        os.chown(ETC, 0, group_id())
        atomic_write(DATA / ".hy-owner", MARKER)
        atomic_write(BIN, candidate.read_bytes(), 0o755)
    atomic_write(LIB / "hy.py", Path(__file__).read_bytes(), 0o755)
    atomic_write("/usr/local/bin/hy", f"#!/bin/sh\n# {MARKER}\nexec /usr/bin/python3 {LIB}/hy.py \"$@\"\n", 0o755)
    write_config(state)
    for name, content in units().items():
        atomic_write(UNIT_DIR / name, content, 0o644)
    run(["systemctl", "daemon-reload"])
    try:
        restart_checked()
        firewall_apply(state)
        run(["systemctl", "enable", SERVICE, "hy-cert-sync.timer"])
        run(["systemctl", "start", "hy-cert-sync.timer"])
    except Exception:
        subprocess.run(["systemctl", "stop", SERVICE], check=False)
        firewall_prune()
        print("安装未完成，文件已保留用于排障。运行 hy doctor / hy logs；修正后 hy start。", file=sys.stderr)
        raise
    export_files(state)
    firewall_hint(state)
    print("\n安装完成。输入 hy 打开中文菜单。服务启动成功不代表公网 UDP 已放行。")
    if state.get("cert_mode") == "selfsigned":
        print("纯 IP 模式可直接导入节点链接/本地配置；运行 hy publish 可创建 IP 订阅，无需网站。")
    else:
        print("需要在线订阅时运行 hy publish，可选择 IP 订阅或已有 HTTPS 网站。")


def configure():
    old = load_state()
    new = collect_state(old)
    check_port(new["port"], old)
    saved = backup()
    was_active = service_active()
    try:
        write_config(new)
        if old.get("traffic", {}).get("enabled"):
            apply_traffic(new)
        restart_checked()
        firewall_apply(new)
    except Exception:
        restore_config(saved)
        if old.get("traffic", {}).get("enabled"):
            apply_traffic(old)
        if was_active:
            restart_checked()
        else:
            run(["systemctl", "stop", SERVICE])
        firewall_prune(old["port"])
        print("修改失败，已恢复修改前配置。", file=sys.stderr)
        raise
    firewall_prune(new["port"])
    export_files(new)
    if new.get("publication"):
        publish_files(new)
    firewall_hint(new)


def update():
    state = load_state()
    with tempfile.TemporaryDirectory(prefix="hy-update-") as tmp:
        candidate = Path(tmp) / "hysteria"
        version = download_core(candidate)
        if hashlib.sha256(candidate.read_bytes()).digest() == hashlib.sha256(BIN.read_bytes()).digest():
            print("已是当前官方稳定版。")
            return
        saved = backup()
        shutil.copy2(BIN, saved / "hysteria")
        was_active = service_active()
        atomic_write(BIN, candidate.read_bytes(), 0o755)
        try:
            if was_active:
                restart_checked()
        except Exception:
            atomic_write(BIN, (saved / "hysteria").read_bytes(), 0o755)
            if was_active:
                restart_checked()
            print("新内核未正常启动，已恢复旧内核。", file=sys.stderr)
            raise
        state["core_version"] = version
        atomic_write(STATE, json_text(state))
    print(f"内核已更新到 {version}，节点密码和端口保持不变。")


def fetch_manager(url):
    return run(["curl", "-fsSL", "--proto", "=https", "--proto-redir", "=https",
                "--connect-timeout", "10", "--max-time", "60", "--retry", "2", url],
               stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def self_update():
    load_state()
    release = json.loads(fetch_manager(f"{MANAGER_URL}/main/release.json"))
    version, digest = release.get("version", ""), release.get("sha256", "")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("管理器发布信息无效，保留旧版本。")
    if tuple(map(int, version.split("."))) < tuple(map(int, VERSION.split("."))):
        raise ValueError("发布信息版本低于当前版本，拒绝降级。")
    content = fetch_manager(f"{MANAGER_URL}/v{version}/hy.py")
    if hashlib.sha256(content).hexdigest() != digest:
        raise ValueError("管理器 SHA-256 校验失败，保留旧版本。")
    compile(content, "hy.py", "exec")
    if f'VERSION = "{version}"'.encode() not in content:
        raise ValueError("管理器版本与发布信息不匹配。")
    target = LIB / "hy.py"
    if target.read_bytes() == content:
        print("管理器已是最新版本。")
        return
    saved = backup()
    shutil.copy2(target, saved / "hy.py")
    atomic_write(target, content, 0o755)
    print(f"管理器已更新到 {version}；配置和服务状态保持不变。请重新运行 hy。")


def publication_settings(webroot, base_url, token=None):
    root = Path(webroot).resolve()
    if not root.is_dir() or not any(root != p and p in root.parents for p in (Path("/www/wwwroot"), Path("/var/www"))):
        raise ValueError("站点目录必须是 /www/wwwroot/ 或 /var/www/ 下已经存在的子目录。")
    url = urllib.parse.urlsplit(base_url)
    if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path not in ("", "/"):
        raise ValueError("请输入站点根 HTTPS 地址，例如 https://vpn.example.com。")
    token = token or secrets.token_hex(24)
    if not re.fullmatch(r"[a-f0-9]{48}", token):
        raise ValueError("订阅令牌无效。")
    return {"root": str(root), "url": base_url.rstrip("/"), "token": token}


def publication_dir(publication):
    root = Path(publication["root"]).resolve()
    target = root / ("hy-sub-" + publication["token"])
    if target.is_symlink() or target.resolve().parent != root:
        raise ValueError("订阅目录指向了站点之外，停止写入。")
    return target


def http_publication(address, port, token=None):
    address, port = ip_literal(address), port_number(port)
    token = token or secrets.token_hex(24)
    if not re.fullmatch(r"[a-f0-9]{48}", token):
        raise ValueError("订阅令牌无效。")
    return {"mode": "http", "server": address, "port": port, "token": token}


def subscription_url(publication, filename, local=False):
    if filename not in SUBSCRIPTIONS:
        raise ValueError("不支持的订阅格式。")
    if publication.get("mode") == "http":
        address = publication["server"]
        if local:
            address = "::1" if ":" in address else "127.0.0.1"
        address = f"[{address}]" if ":" in address else address
        base = f"http://{address}:{publication['port']}"
    else:
        base = publication["url"]
    return f"{base}/hy-sub-{publication['token']}/{filename}"


def check_subscription_port(value):
    port = port_number(value)
    if output(["ss", "-H", "-ltn", f"sport = :{port}"]):
        raise ValueError(f"TCP {port} 已被占用，请换一个订阅端口。")
    return port


def write_http_subscription(state):
    p = state["publication"]
    http_publication(p["server"], p["port"], p["token"])
    files = client_files(state)
    document = {"owner": MARKER, "port": p["port"], "ipv6": ":" in p["server"],
                "token": p["token"], "files": {name: files[name] for name in SUBSCRIPTIONS}}
    path = subscription_config_path()
    if path.exists() and json.loads(path.read_text(encoding="utf-8")).get("owner") != MARKER:
        raise ValueError("订阅配置归属不明，拒绝覆盖。")
    atomic_write(path, json_text(document), 0o640, group_id())


class SubscriptionHandler(http.server.BaseHTTPRequestHandler):
    server_version = "HY-Subscription"
    sys_version = ""

    def setup(self):
        self.request.settimeout(5)
        super().setup()

    def log_message(self, *_):
        # 不把带有订阅密钥的请求路径写入日志。
        pass

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        try:
            data = json.loads(self.server.config_path.read_text(encoding="utf-8"))
            parts = urllib.parse.urlsplit(self.path)
            prefix, separator, filename = parts.path.rpartition("/")
            valid = (data.get("owner") == MARKER and separator and filename in SUBSCRIPTIONS
                     and secrets.compare_digest(prefix.encode(), ("/hy-sub-" + data["token"]).encode()))
            body = data["files"][filename].encode() if valid else b"Not Found\n"
            status = 200 if valid else 404
        except (OSError, ValueError, KeyError, TypeError):
            status, body = 503, b"Unavailable\n"
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


class SubscriptionServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, config_path, ipv6=False):
        self.address_family = socket.AF_INET6 if ipv6 else socket.AF_INET
        self.config_path = Path(config_path)
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(address, SubscriptionHandler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def serve_subscription():
    path = subscription_config_path()
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("owner") != MARKER or not re.fullmatch(r"[a-f0-9]{48}", data.get("token", "")):
        raise ValueError("订阅配置无效。")
    with SubscriptionServer(("::" if data["ipv6"] else "0.0.0.0", port_number(data["port"])),
                            path, ipv6=data["ipv6"]) as server:
        server.serve_forever()


def activate_http_subscription(state):
    path = subscription_config_path()
    previous = path.read_bytes() if path.exists() else None
    if previous is not None and json.loads(previous).get("owner") != MARKER:
        raise ValueError("订阅配置归属不明，拒绝覆盖。")
    unit = UNIT_DIR / SUB_SERVICE
    if unit.exists() and MARKER not in unit.read_text():
        raise ValueError("同名订阅服务不属于本工具，拒绝覆盖。")
    was_active = subprocess.run(["systemctl", "is-active", "--quiet", SUB_SERVICE],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    was_enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", SUB_SERVICE],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    previous_rules = firewall_records()
    try:
        write_http_subscription(state)
        atomic_write(unit, units()[SUB_SERVICE], 0o644)
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "restart", SUB_SERVICE])
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        last_error = None
        for _ in range(20):
            try:
                with opener.open(subscription_url(state["publication"], "hiddify.txt", local=True), timeout=1) as response:
                    if response.read() != client_files(state)["hiddify.txt"].encode():
                        raise ValueError("订阅内容检查失败。")
                last_error = None
                break
            except (OSError, ValueError) as exc:
                last_error = exc
                time.sleep(0.25)
        if last_error:
            raise ValueError("订阅服务启动失败，请查看 journalctl -u hy-subscription。") from last_error
        run(["systemctl", "is-active", "--quiet", SUB_SERVICE])
        firewall_apply({**state, "port": state["publication"]["port"]}, protocol="tcp")
        run(["systemctl", "enable", SUB_SERVICE])
        atomic_write(STATE, json_text(state))
    except Exception:
        if previous is not None:
            atomic_write(path, previous, 0o640, group_id())
            run(["systemctl", "restart" if was_active else "stop", SUB_SERVICE])
            run(["systemctl", "enable" if was_enabled else "disable", SUB_SERVICE])
        else:
            run(["systemctl", "disable", "--now", SUB_SERVICE])
            path.unlink(missing_ok=True)
        firewall_prune(only=[r for r in firewall_records() if r not in previous_rules], protocol="tcp")
        raise
    print("本机订阅获取验证通过；外网访问还需要放行云安全组和本机防火墙。")
    print(f"订阅使用 TCP {state['publication']['port']}；VPN 数据仍使用 UDP {state['port']}。")


def publish_files(state):
    p = state["publication"]
    if p.get("mode") == "http":
        write_http_subscription(state)
        for name, label in SUBSCRIPTIONS.items():
            print(f"{label} 订阅：{subscription_url(p, name)}")
        return
    publication_settings(p["root"], p["url"], p["token"])
    target = publication_dir(p)
    if target.exists() and (not (target / ".hy-owner").is_file() or (target / ".hy-owner").read_text() != MARKER):
        raise ValueError("订阅目录不属于本工具，拒绝覆盖。")
    target.mkdir(mode=0o755, exist_ok=True)
    atomic_write(target / ".hy-owner", MARKER, 0o600)
    files = client_files(state)
    for name in SUBSCRIPTIONS:
        atomic_write(target / name, files[name], 0o644)
    atomic_write(target / "index.html", "Not Found\n", 0o644)
    for name, label in SUBSCRIPTIONS.items():
        url = subscription_url(p, name)
        print(f"{label} 订阅：{url}")
        try:
            request = urllib.request.Request(url, headers={"Cache-Control": "no-cache"})
            with urllib.request.urlopen(request, timeout=15) as response:
                if response.status != 200 or response.read(1024 * 1024) != files[name].encode():
                    raise ValueError("返回内容与生成文件不同")
            print("  HTTPS 获取与内容核对通过。")
        except Exception as exc:
            print(f"  尚未验证可用：{exc}。检查站点根目录/访问规则；本工具不会自动改 Nginx。")


def publish():
    state = load_state()
    old = state.get("publication")
    if old:
        print("刷新当前订阅文件。要换发布位置，请先运行 hy unpublish。")
    else:
        mode = choice("订阅方式：1=IP 直连 HTTP（无需域名），2=已有 HTTPS 网站", ("1", "2"), "1")
        if mode == "1":
            print("HTTP 订阅包含节点凭据，传输未加密；随机路径就是订阅密钥，请勿分享。")
            try:
                default_ip = ip_literal(state["server"])
            except ValueError:
                default_ip = detect_public_ip()
            address = ask_valid("订阅服务器 IP", ip_literal, default_ip)
            port = ask_valid("订阅 TCP 端口", check_subscription_port, 24444)
            state["publication"] = http_publication(address, port)
        else:
            print("文件包含节点凭据，随机路径就是订阅密钥；使用你自己的现有 HTTPS 网站。")
            self_signed = state.get("cert_mode") == "selfsigned"
            state["publication"] = publication_settings(
                prompt("已有网站根目录", None if self_signed else f"/www/wwwroot/{state['domain']}"),
                prompt("站点 HTTPS 根地址", None if self_signed else f"https://{state['domain']}"))
    if state["publication"].get("mode") == "http":
        activate_http_subscription(state)
        publish_files(state)
        return
    # 先保存归属信息，网络验证失败时仍可撤销发布。
    atomic_write(STATE, json_text(state))
    publish_files(state)


def unpublish():
    state = load_state()
    p = state.get("publication")
    if not p:
        print("没有发布订阅。")
        return
    if p.get("mode") == "http":
        unit = UNIT_DIR / SUB_SERVICE
        if unit.exists() and MARKER not in unit.read_text():
            raise ValueError("同名订阅服务不属于本工具，拒绝停用。")
        if subscription_config_path().exists() and json.loads(subscription_config_path().read_text(encoding="utf-8")).get("owner") != MARKER:
            raise ValueError("订阅配置归属不明，拒绝删除。")
        if unit.exists():
            run(["systemctl", "disable", "--now", SUB_SERVICE])
        subscription_config_path().unlink(missing_ok=True)
        firewall_prune(protocol="tcp")
        del state["publication"]
        atomic_write(STATE, json_text(state))
        print("已关闭 IP 订阅服务并撤销链接；已经导入的节点仍可连接。")
        return
    target = publication_dir(p)
    if target.exists():
        if not (target / ".hy-owner").is_file() or (target / ".hy-owner").read_text() != MARKER:
            raise ValueError("订阅目录归属不符，拒绝删除。")
        for name in (*SUBSCRIPTIONS, "index.html", ".hy-owner"):
            (target / name).unlink(missing_ok=True)
        if not any(target.iterdir()):
            target.rmdir()
    del state["publication"]
    atomic_write(STATE, json_text(state))
    print("已撤销订阅发布；已经导入的节点仍可连接，撤销节点访问请修改密码。")


def rate_mbps(value):
    try:
        if not re.fullmatch(r"[0-9]{1,5}(?:\.[0-9]{1,3})?", str(value)):
            raise ValueError()
        rate = Decimal(str(value))
        if rate < 0 or rate > 10000:
            raise ValueError()
        return format(rate.normalize(), "f") if rate else "0"
    except (ValueError, InvalidOperation) as exc:
        raise ValueError("速率请输入 0～10000 Mbps，最多 3 位小数；0 表示不限速。") from exc


def nft_table():
    if not shutil.which("nft"):
        raise ValueError("需要 nftables：Debian/Ubuntu 执行 apt-get install -y nftables；Amazon Linux 2023 执行 dnf install -y nftables，或重新运行安装器补齐依赖。")
    tables = json.loads(output(["nft", "-j", "list", "tables"]))["nftables"]
    if not any(item.get("table", {}).get("name") == TRAFFIC_TABLE and
               item["table"].get("family") == "inet" for item in tables):
        return None
    table = json.loads(output(["nft", "-j", "list", "table", "inet", TRAFFIC_TABLE]))
    metadata = next((item["table"] for item in table["nftables"] if
                     item.get("table", {}).get("name") == TRAFFIC_TABLE and
                     item["table"].get("family") == "inet"), {})
    owned = metadata.get("comment") == MARKER
    if metadata and "comment" not in metadata:
        # Amazon Linux 的 nft 1.0.4 不在 JSON 中返回表注释，严格检查文本表头。
        # 只接受表级归属注释，不能把规则或链里的同名注释当作所有权证明。
        header = output(["nft", "--terse", "list", "table", "inet", TRAFFIC_TABLE])
        pattern = (r'\Atable inet ' + re.escape(TRAFFIC_TABLE) + r' \{\s*\n[ \t]*comment '
                   + re.escape(json.dumps(MARKER)) + r'[ \t]*;?[ \t]*(?:\n|$)')
        owned = re.match(pattern, header) is not None
    if not owned:
        raise ValueError("同名 nftables 表不属于本工具，拒绝操作。")
    return table


def traffic_rules(state, exists):
    port = port_number(state["port"])
    table = f"inet {TRAFFIC_TABLE}"
    rules = []
    if not exists:
        rules.append(f'add table {table} {{ comment "{MARKER}"; }}')
        for direction in ("up", "down"):
            for version in (4, 6):
                rules.append(f"add set {table} {direction}{version} {{ type ipv{version}_addr; "
                             "flags dynamic,timeout; timeout 24h; size 65536; }")
        for chain, hook in (("incoming", "input"), ("outgoing", "output")):
            rules.append(f"add chain {table} {chain} {{ type filter hook {hook} priority 10; policy accept; }}")
        for chain in ("upload_limits", "download_limits"):
            rules.append(f"add chain {table} {chain}")
    else:
        # 只刷新自己的规则链，保留计数集合，不清空系统防火墙。
        for chain in ("incoming", "outgoing", "upload_limits", "download_limits"):
            rules.append(f"flush chain {table} {chain}")
    for direction, chain, field, address_field in (("upload", "incoming", "dport", "saddr"),
                                                   ("download", "outgoing", "sport", "daddr")):
        rules.append(f"add rule {table} {chain} udp {field} {port} jump {direction}_limits")
        for version in (4, 6):
            protocol = "ip" if version == 4 else "ip6"
            counter = ("up" if direction == "upload" else "down") + str(version)
            rules.append(f"add rule {table} {chain} udp {field} {port} update @{counter} {{ {protocol} {address_field} counter }}")
        for address, limit in sorted(state.get("traffic", {}).get("limits", {}).items()):
            address = ip_literal(address)
            rate = Decimal(rate_mbps(limit.get(direction, "0")))
            if not rate:
                continue
            byte_rate = int(rate * 125000)
            protocol = "ip6" if ":" in address else "ip"
            burst = max(1500, min(byte_rate // 10, 1048576))
            rules.append(f"add rule {table} {direction}_limits {protocol} {address_field} {address} "
                         f"limit rate over {byte_rate} bytes/second burst {burst} bytes counter drop "
                         f'comment "{direction} {address}"')
    return "\n".join(rules) + "\n"


def apply_traffic(state):
    existing = nft_table()
    if not state.get("traffic", {}).get("enabled"):
        if existing:
            run(["nft", "delete", "table", "inet", TRAFFIC_TABLE])
        return
    script = traffic_rules(state, bool(existing))
    # 先验证再原子提交整批规则；语法或内核能力不足时不会留下半套限速规则。
    run(["nft", "--check", "-f", "-"], input=script, text=True)
    run(["nft", "-f", "-"], input=script, text=True)


def save_traffic(state, config):
    unit = UNIT_DIR / TRAFFIC_SERVICE
    if unit.exists() and MARKER not in unit.read_text():
        raise ValueError("同名监控服务不属于本工具，拒绝覆盖。")
    nft_table()
    new = {**state, "traffic": config}
    try:
        apply_traffic(new)
        atomic_write(STATE, json_text(new))
        atomic_write(unit, units()[TRAFFIC_SERVICE], 0o644)
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", TRAFFIC_SERVICE] if config["enabled"] else
            ["systemctl", "disable", "--now", TRAFFIC_SERVICE])
    except Exception:
        apply_traffic(state)
        atomic_write(STATE, json_text(state))
        raise
    return new


def ensure_monitor():
    state = load_state()
    if not state.get("traffic", {}).get("enabled") or nft_table() is None:
        state = save_traffic(state, {**state.get("traffic", {}), "enabled": True})
        print("已启用 HY2 客户端 IP 监控；配置会在开机时恢复。")
    return state


def traffic_snapshot(table):
    result = {}
    for item in (table or {}).get("nftables", []):
        collection = item.get("set", {})
        name = collection.get("name", "")
        if name not in ("up4", "up6", "down4", "down6"):
            continue
        direction = "upload" if name.startswith("up") else "download"
        for entry in collection.get("elem", []):
            element = entry.get("elem", {})
            address = element.get("val")
            if isinstance(address, str):
                result.setdefault(address, {"upload": 0, "download": 0})[direction] = element.get("counter", {}).get("bytes", 0)
    return result


def monitor(once=False, interval=2):
    print("只统计 HY2 UDP 端口放行的流量（含协议开销），方向以客户端为准。")
    print("累计值自启用/计数重建起；IP 单方向空闲 24 小时后清零。Ctrl+C 退出显示，监控与限速继续。")
    previous = traffic_snapshot(nft_table())
    last = time.monotonic()
    while True:
        time.sleep(interval)
        table = nft_table()
        if table is None:
            raise ValueError("监控规则已被移除；需要时重新运行 hy monitor。")
        now = time.monotonic()
        current = traffic_snapshot(table)
        limits = load_state().get("traffic", {}).get("limits", {})
        if sys.stdout.isatty() and not once:
            print("\033[2J\033[H", end="")
        print(f"\nHY2 客户端 IP 流量 {dt.datetime.now():%H:%M:%S}（↑客户端上传 ↓客户端下载；1 MB/s = 8 Mbps）")
        print(f"{'客户端 IP':<40} {'↑ Mbps':>10} {'↓ Mbps':>10} {'↑ MB/s':>10} {'↓ MB/s':>10} {'↑ MiB':>10} {'↓ MiB':>10}  限速↑/↓ Mbps")
        for address, values in sorted(current.items(), key=lambda item: sum(item[1].values()), reverse=True):
            before = previous.get(address, {"upload": 0, "download": 0})
            rates = [max(0, values[d] - before[d]) * 8 / (now - last) / 1000000 for d in ("upload", "download")]
            limit = limits.get(address, {})
            label = "/".join(str(limit.get(d, "0")) if Decimal(str(limit.get(d, "0"))) else "不限" for d in ("upload", "download"))
            print(f"{address:<40} {rates[0]:10.3f} {rates[1]:10.3f} {rates[0]/8:10.3f} {rates[1]/8:10.3f} {values['upload']/1048576:10.2f} {values['download']/1048576:10.2f}  {label}")
        if not current:
            print("暂无流量，请连接节点并访问网站。")
        if once:
            return
        previous, last = current, now


def set_limit(address=None, upload=None, download=None):
    state = load_state()
    address = ip_literal(address) if address else ask_valid("客户端公网 IP", ip_literal)
    config = {**state.get("traffic", {}), "enabled": True,
              "limits": dict(state.get("traffic", {}).get("limits", {}))}
    old = config["limits"].get(address, {"upload": "0", "download": "0"})
    if upload is None and download is None:
        upload = ask_valid("客户端上传上限 Mbps（0 不限）", rate_mbps, old["upload"])
        download = ask_valid("客户端下载上限 Mbps（0 不限）", rate_mbps, old["download"])
    new = {"upload": rate_mbps(upload if upload is not None else old["upload"]),
           "download": rate_mbps(download if download is not None else old["download"])}
    if new == {"upload": "0", "download": "0"}:
        config["limits"].pop(address, None)
    else:
        config["limits"][address] = new
    save_traffic(state, config)
    print(f"已保存 {address}：上传 {new['upload']} Mbps，下载 {new['download']} Mbps（0 不限）。")
    print("限速采用内核令牌桶丢弃超额包，允许短时突发，实际应用速度可能低于上限。")


def remove_limit(address=None):
    state = load_state()
    address = ip_literal(address) if address else ask_valid("要取消限速的客户端公网 IP", ip_literal)
    config = {"enabled": False, **state.get("traffic", {}),
              "limits": dict(state.get("traffic", {}).get("limits", {}))}
    config["limits"].pop(address, None)
    save_traffic(state, config)
    print(f"已取消 {address} 的限速。")


def show_limits():
    config = load_state().get("traffic", {})
    active = bool(config.get("enabled") and nft_table())
    print("监控和限速：" + ("已启用" if active else "未启用或规则已被移除"))
    for address, limit in config.get("limits", {}).items():
        print(f"{address}  上传 {limit['upload']} Mbps / 下载 {limit['download']} Mbps（0 不限）")
    if not config.get("limits"):
        print("没有配置 IP 限速。")


def monitor_off():
    state = load_state()
    save_traffic(state, {**state.get("traffic", {}), "enabled": False})
    print("已关闭监控和限速。配置保留，下次 hy monitor 会恢复；取消单个 IP 限速用 hy unlimit IP。")


def firewall_backend():
    active = []
    try:
        if shutil.which("ufw") and "Status: active" in output(["env", "LC_ALL=C", "ufw", "status"]):
            active.append("ufw")
        if shutil.which("firewall-cmd") and subprocess.run(
                ["firewall-cmd", "--state"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            active.append("firewalld")
    except (OSError, subprocess.SubprocessError):
        return None
    return active[0] if len(active) == 1 else None


def firewall_records():
    path = DATA / "firewall.json"
    if not path.exists():
        return []
    value = json.loads(path.read_text())
    if value.get("owner") != MARKER:
        raise ValueError("防火墙记录归属不明，拒绝修改。")
    return value["rules"]


def save_firewall(records):
    atomic_write(DATA / "firewall.json", json_text({"owner": MARKER, "rules": records}))


def firewall_command(record, action):
    port = port_number(record["port"])
    protocol = record.get("protocol", "udp")
    if protocol not in ("tcp", "udp"):
        raise ValueError("无效的防火墙协议。")
    if record["backend"] == "ufw":
        return ["ufw", *(["--force", "delete"] if action == "remove" else []),
                "allow", f"{port}/{protocol}", "comment", record["comment"]]
    return ["firewall-cmd", *(["--permanent"] if record["permanent"] else []),
            f"--zone={record['zone']}", f"--{action}-port={port}/{protocol}"]


def firewall_prune(keep_port=None, only=None, protocol="udp"):
    records = firewall_records()
    for record in records[:]:
        if protocol is not None and record.get("protocol", "udp") != protocol:
            continue
        if record["port"] == keep_port or (only is not None and record not in only):
            continue
        try:
            if record["backend"] == "ufw":
                # 注释已变化说明用户接管了规则，不再删除。
                present = record["comment"] in output(["ufw", "show", "added"])
            else:
                query = firewall_command(record, "query")
                result = subprocess.run(query, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                if result.returncode not in (0, 1):
                    raise ValueError("firewalld 查询失败")
                present = result.returncode == 0
            if present:
                run(firewall_command(record, "remove"), stdout=subprocess.DEVNULL)
            records.remove(record)
            save_firewall(records)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            print(f"未能清理自建 {record.get('protocol', 'udp').upper()} {record['port']} 规则，记录已保留：{exc}")
    return records


def firewall_apply(state, protocol="udp"):
    if protocol not in ("udp", "tcp"):
        raise ValueError("无效的防火墙协议。")
    if state.get("firewall_mode") != "auto":
        return
    backend = firewall_backend()
    if backend is None:
        print("未识别到唯一启用的 UFW/firewalld，未修改防火墙，请手动放行。")
        return
    records = firewall_records()
    port = state["port"]
    extra = {"protocol": "tcp"} if protocol == "tcp" else {}
    candidates = []
    if backend == "ufw":
        added = output(["ufw", "show", "added"])
        if any(shlex.split(line)[:3] == ["ufw", "allow", f"{port}/{protocol}"] for line in added.splitlines()):
            print(f"UFW 已有 {protocol.upper()} {port} 放行规则，复用现有规则。")
            return
        candidates.append({"backend": backend, "port": port, "comment": "hy-" + secrets.token_hex(8), **extra})
    else:
        active = output(["firewall-cmd", "--get-active-zones"])
        # 新版 firewalld 会在区域名后附加 "(default)"。
        zones = [line.split()[0] for line in active.splitlines() if line and not line[0].isspace()]
        if len(zones) != 1:
            print("firewalld 活跃区域不唯一，请手动选择区域放行，未修改规则。")
            return
        for permanent in (False, True):
            record = {"backend": backend, "port": port, "zone": zones[0], "permanent": permanent, **extra}
            result = subprocess.run(firewall_command(record, "query"), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode not in (0, 1):
                raise ValueError("firewalld 查询失败，未添加规则。")
            if result.returncode == 1:
                candidates.append(record)
    previous = records[:]
    try:
        for record in candidates:
            # 先保存新增意图，意外退出后也能找到本工具负责的规则。
            if record not in records:
                records.append(record)
            save_firewall(records)
            run(firewall_command(record, "add"), stdout=subprocess.DEVNULL)
    except Exception:
        firewall_prune(only=[record for record in records if record not in previous], protocol=protocol)
        raise
    print(f"已处理本机 {backend} 的 {protocol.upper()} {port} 放行；云安全组仍需自行设置。")


def firewall_setup():
    state = load_state()
    mode = choice("1=自动放行，2=手动放行并清理脚本自建规则", ("1", "2"), "1")
    state["firewall_mode"] = "auto" if mode == "1" else "manual"
    firewall_apply(state)
    firewall_prune(state["port"] if mode == "1" else None)
    if state.get("publication", {}).get("mode") == "http":
        port = state["publication"]["port"]
        firewall_apply({**state, "port": port}, protocol="tcp")
        firewall_prune(port if mode == "1" else None, protocol="tcp")
    atomic_write(STATE, json_text(state))
    firewall_hint(state)


def firewall_hint(state):
    print(f"\n请在云安全组和宝塔防火墙放行 UDP {state['port']}。")
    print(f"若正在使用 UFW，可执行：ufw allow {state['port']}/udp")
    if state.get("publication", {}).get("mode") == "http":
        print(f"IP 订阅另需放行 TCP {state['publication']['port']}。")
    else:
        print("使用已有 HTTPS 网站无需新增订阅端口；创建 IP 订阅时另行提示 TCP 端口。")


def start():
    load_state()
    restart_checked()
    run(["systemctl", "enable", "--now", "hy-cert-sync.timer"])
    run(["systemctl", "enable", SERVICE])


def status():
    print(f"\nHY {VERSION} — Hysteria2 中文管理")
    if not STATE.exists():
        print("尚未安装；选择快速安装即可开始。")
        return
    state = load_state()
    active = "运行中" if service_active() else "已停止"
    enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", SERVICE],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
    print(f"服务：{active} | 开机启动：{'开启' if enabled else '关闭'} | 内核：{state.get('core_version', '未知')}")
    mode = "纯 IP / 自签证书" if state.get("cert_mode") == "selfsigned" else "域名 / 已有证书"
    print(f"模式：{mode} | 连接：{state['server']} UDP {state['port']}")
    if state.get("publication", {}).get("mode") == "http":
        active = subprocess.run(["systemctl", "is-active", "--quiet", SUB_SERVICE],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        print(f"IP 订阅：{'运行中' if active else '已停止'} | TCP {state['publication']['port']}")


def autostart(enabled):
    load_state()
    run(["systemctl", "enable" if enabled else "disable", SERVICE])
    print("开机启动已" + ("开启" if enabled else "关闭") + "，当前运行状态不变。")


def doctor():
    state = load_state()
    def certificate():
        signed = state.get("cert_mode") == "selfsigned"
        check_certificate(state["cert_source"], state["key_source"], state["domain"], signed)
        if signed:
            der = run(["openssl", "x509", "-in", state["cert_source"], "-outform", "DER"], stdout=subprocess.PIPE).stdout
            if hashlib.sha256(der).hexdigest() != state.get("cert_sha256"):
                raise ValueError("自签证书指纹不匹配，请恢复原证书。")
        return "证书和私钥检查通过"
    def firewall():
        backend = firewall_backend()
        if not backend:
            return "WARN: 未识别到唯一启用的 UFW/firewalld；需人工检查本机规则"
        command = ["ufw", "status"] if backend == "ufw" else ["firewall-cmd", "--list-all-zones"]
        return backend + "（请确认所用区域包含 UDP 端口）\n" + output(command)
    checks = [("服务", lambda: service_active()),
              (f"UDP {state['port']} 监听", lambda: bool(output(["ss", "-H", "-lun", f"sport = :{state['port']}"]))),
              ("证书", certificate),
              ("证书同步定时器启用", lambda: output(["systemctl", "is-enabled", "hy-cert-sync.timer"])),
              ("证书同步定时器运行", lambda: output(["systemctl", "is-active", "hy-cert-sync.timer"])),
              ("DNS / 连接地址", lambda: ", ".join(sorted({x[4][0] for x in socket.getaddrinfo(state["server"], state["port"])}))),
              ("本机防火墙", firewall)]
    print(f"管理器 {VERSION} / 内核 {state.get('core_version', '未知')}")
    for label, check in checks:
        try:
            result = check()
            level = "FAIL" if result is False else ("WARN" if str(result).startswith("WARN:") else "PASS")
            print(f"[{level}] {label}：{result}")
        except Exception as exc:
            print(f"[FAIL] {label}：{exc}")
    firewall_hint(state)
    print("本机诊断不能证明公网 UDP、客户端握手或实际速度；请用导出的配置连接验证。")


def uninstall():
    state = load_state()
    if prompt("将停用并删除本工具的服务和配置，输入 UNINSTALL 确认") != "UNINSTALL":
        print("已取消。")
        return
    saved = backup()
    if firewall_prune(protocol=None):
        raise ValueError("自建防火墙规则尚未清理完，已保留安装。请修复防火墙后重新运行 hy uninstall。")
    if state.get("traffic"):
        save_traffic(state, {**state["traffic"], "enabled": False})
    unpublish()
    subscription_unit = UNIT_DIR / SUB_SERVICE
    if subscription_unit.exists() and MARKER in subscription_unit.read_text():
        run(["systemctl", "disable", "--now", SUB_SERVICE])
    run(["systemctl", "disable", "--now", "hy-cert-sync.timer", SERVICE])
    subprocess.run(["systemctl", "stop", "hy-cert-sync.service"], check=False)
    for name in units():
        path = UNIT_DIR / name
        if path.exists() and MARKER in path.read_text():
            path.unlink()
    run(["systemctl", "daemon-reload"])
    for path in (ETC, LIB, DATA / "export"):
        if path.exists():
            shutil.rmtree(path)
    launcher = Path("/usr/local/bin/hy")
    if launcher.exists() and MARKER in launcher.read_text():
        launcher.unlink()
    print(f"已卸载。备份保留在 {saved}；系统账户和运行目录保留，避免误删用户数据。")


def main():
    parser = argparse.ArgumentParser(description="HY：中文 Hysteria2 单节点管理工具")
    parser.add_argument("command", nargs="?", default="menu", choices=["menu", "install", "configure", "update", "self-update", "status", "firewall", "enable", "disable", "export", "publish", "unpublish", "sync-cert", "doctor", "logs", "start", "stop", "restart", "backup", "uninstall", "monitor", "limit", "unlimit", "limits", "monitor-off", "traffic-apply", "serve-subscription"])
    parser.add_argument("ip", nargs="?", help="需要限速的客户端公网 IP")
    parser.add_argument("--upload", type=rate_mbps, help="客户端上传上限 Mbps，0 不限")
    parser.add_argument("--download", type=rate_mbps, help="客户端下载上限 Mbps，0 不限")
    parser.add_argument("--once", action="store_true", help="监控只采样一次")
    args = parser.parse_args()
    if (args.ip and args.command not in ("limit", "unlimit")) or (args.once and args.command != "monitor") or \
       ((args.upload is not None or args.download is not None) and args.command != "limit"):
        parser.error("IP 仅用于 limit/unlimit；速率仅用于 limit；--once 仅用于 monitor。")
    if args.command == "serve-subscription":
        serve_subscription()
        return
    if platform.system() != "Linux" or os.geteuid() != 0 or not Path("/run/systemd/system").is_dir():
        raise ValueError("请在使用 systemd 的 Linux 服务器上以 root 运行。")
    actions = {"install": install, "configure": configure, "update": update, "self-update": self_update,
               "status": status, "firewall": firewall_setup, "enable": lambda: autostart(True),
               "disable": lambda: autostart(False), "export-client": export_client,
               "export": lambda: export_files(load_state()), "publish": publish, "unpublish": unpublish,
               "sync-cert": lambda: sync_certificate(load_state()), "doctor": doctor,
               "logs": lambda: run(["journalctl", "-u", SERVICE, "-n", "60", "--no-pager"]),
               "start": start, "restart": restart_checked,
               "stop": lambda: run(["systemctl", "stop", SERVICE]), "backup": lambda: (load_state(), backup()),
               "uninstall": uninstall, "limit": lambda: set_limit(args.ip, args.upload, args.download),
               "unlimit": lambda: remove_limit(args.ip), "limits": show_limits,
               "monitor-off": monitor_off, "traffic-apply": lambda: apply_traffic(load_state())}
    def dispatch(command):
        if command == "monitor":
            ensure_monitor()
        else:
            actions[command]()
        if command == "monitor":
            try:
                monitor(once=args.once)
            except KeyboardInterrupt:
                print("\n已退出显示，监控和限速仍在后台生效。")
    if args.command != "menu":
        dispatch(args.command)
        return
    groups = [
        ("安装与配置", [("快速 / 高级安装（已安装时刷新管理器）", "install"), ("修改节点配置", "configure"), ("设置端口放行", "firewall")]),
        ("连接与订阅", [("按客户端导入", "export-client"), ("查看全部导出", "export"), ("发布 / 刷新 IP 或 HTTPS 订阅", "publish"), ("撤销订阅", "unpublish")]),
        ("服务管理", [("启动并开启开机启动", "start"), ("停止（不改变开机启动）", "stop"), ("重启", "restart"), ("开启开机启动", "enable"), ("关闭开机启动（不停止服务）", "disable")]),
        ("监控与限速", [("客户端 IP 实时流量", "monitor"), ("设置 IP 上下行限速", "limit"), ("取消 IP 限速", "unlimit"), ("查看限速配置", "limits"), ("关闭监控和限速", "monitor-off")]),
        ("更新与维护", [("更新管理脚本", "self-update"), ("更新官方内核", "update"), ("诊断", "doctor"), ("查看日志", "logs"), ("备份配置", "backup"), ("卸载", "uninstall")])]
    while True:
        status()
        for i, (label, _) in enumerate(groups, 1):
            print(f"{i:2}. {label}")
        selection = prompt("选择菜单，0 退出", "0")
        if selection == "0":
            return
        if selection.isdigit() and 1 <= int(selection) <= len(groups):
            options = groups[int(selection) - 1][1]
            for i, (label, _) in enumerate(options, 1):
                print(f"{i:2}. {label}")
            selection = prompt("选择操作，0 返回", "0")
            if selection == "0":
                continue
            if not selection.isdigit() or not 1 <= int(selection) <= len(options):
                print("无效选项。")
                continue
            try:
                dispatch(options[int(selection) - 1][1])
                if options[int(selection) - 1][1] == "self-update":
                    return
            except Exception as exc:
                print(f"操作失败：{exc}", file=sys.stderr)
        else:
            print("无效选项。")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\n已取消。", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        print(f"错误：{exc}", file=sys.stderr)
        sys.exit(1)
