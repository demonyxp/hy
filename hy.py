#!/usr/bin/env python3
"""面向 Debian / Ubuntu 的 Hysteria2 单节点管理器。"""

import argparse
import base64
import datetime as dt
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

VERSION = "0.2.0"
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
    hint = f" [{default}]" if default is not None and not secret else ""
    value = (getpass.getpass if secret else input)(f"{label}{hint}: ").strip()
    return value or default or ""


def ask_valid(label, validator, default=None):
    while True:
        try:
            return validator(prompt(label, default))
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
         *(["-CAfile", cert] if self_signed else ["-CApath", "/etc/ssl/certs"]),
         "-untrusted", cert, cert],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def ip_literal(value):
    try:
        if "%" in value:
            raise ValueError()
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError as exc:
        raise ValueError("请输入服务器 IPv4 或 IPv6 地址，不要填写域名、端口或网址。") from exc


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
        cert = str(Path(prompt("证书完整路径", cert_default)).expanduser().resolve())
        key = str(Path(prompt("私钥完整路径", key_default)).expanduser().resolve())
        check_certificate(cert, key, host)
    port = ask_valid("Hysteria2 UDP 端口", port_number, old.get("port", 24443))
    password = prompt("节点密码（回车保留或自动生成）", secret=True) or old.get("password") or secrets.token_urlsafe(24)
    if len(password) < 16 or any(ord(c) < 32 for c in password):
        raise ValueError("密码至少 16 个字符，不能包含控制字符。")
    name = prompt("节点名称", old.get("name", "我的-HY2"))
    if len(name) > 80 or any(ord(c) < 32 for c in name) or name in ("DIRECT", "REJECT", "节点选择", "GLOBAL"):
        raise ValueError("节点名称不能超过 80 字符、包含控制字符或使用保留名称。")
    obfs = prompt("启用 Salamander 混淆？y/N", "y" if old.get("obfs") else "n").lower() == "y"
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
    state = collect_state()
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
        run(["systemctl", "enable", SERVICE, "hy-cert-sync.timer"])
        run(["systemctl", "start", "hy-cert-sync.timer"])
    except Exception:
        subprocess.run(["systemctl", "stop", SERVICE], check=False)
        print("安装未完成，文件已保留用于排障。运行 hy doctor / hy logs；修正后 hy start。", file=sys.stderr)
        raise
    export_files(state)
    firewall_hint(state)
    print("\n安装完成。输入 hy 打开中文菜单。服务启动成功不代表公网 UDP 已放行。")
    if state.get("cert_mode") == "selfsigned":
        print("纯 IP 模式可直接导入节点链接/本地配置，无需网站。已有 HTTPS 网站时可另运行 hy publish。")
    elif prompt("是否发布订阅到已有 HTTPS 网站？y/N", "n").lower() == "y":
        publish()


def configure():
    old = load_state()
    new = collect_state(old)
    check_port(new["port"], old)
    saved = backup()
    was_active = service_active()
    try:
        write_config(new)
        restart_checked()
    except Exception:
        restore_config(saved)
        if was_active:
            restart_checked()
        else:
            run(["systemctl", "stop", SERVICE])
        print("修改失败，已恢复修改前配置。", file=sys.stderr)
        raise
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


def publish_files(state):
    p = state["publication"]
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
        url = f"{p['url']}/{target.name}/{name}"
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
        print("文件包含节点凭据，随机路径就是订阅密钥；使用你自己的现有 HTTPS 网站。")
        self_signed = state.get("cert_mode") == "selfsigned"
        state["publication"] = publication_settings(
            prompt("已有网站根目录", None if self_signed else f"/www/wwwroot/{state['domain']}"),
            prompt("站点 HTTPS 根地址", None if self_signed else f"https://{state['domain']}"))
    # 先保存归属信息，网络验证失败时仍可撤销发布。
    atomic_write(STATE, json_text(state))
    publish_files(state)


def unpublish():
    state = load_state()
    p = state.get("publication")
    if not p:
        print("没有发布订阅。")
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


def firewall_hint(state):
    print(f"\n请在云安全组和宝塔防火墙放行 UDP {state['port']}。")
    print(f"若正在使用 UFW，可执行：ufw allow {state['port']}/udp")
    print("不需要新增 TCP 订阅端口；HTTPS 订阅使用现有网站。")


def start():
    load_state()
    restart_checked()
    run(["systemctl", "enable", "--now", "hy-cert-sync.timer"])
    run(["systemctl", "enable", SERVICE])


def doctor():
    state = load_state()
    print(f"管理器 {VERSION} / 内核 {state.get('core_version', '未知')}")
    print("服务：" + ("运行中" if service_active() else "未运行"))
    print(f"UDP {state['port']} 监听：" + ("存在" if output(["ss", "-H", "-lun", f"sport = :{state['port']}"]) else "不存在"))
    if state.get("cert_mode") == "selfsigned":
        prepare_self_signed(state)
        print("自签证书：有效期、私钥匹配、固定指纹校验通过（不依赖公共 CA）")
    else:
        check_certificate(state["cert_source"], state["key_source"], state["domain"])
        print("源证书：域名、有效期、私钥匹配、系统 CA 校验通过")
    print(output(["systemctl", "is-enabled", "hy-cert-sync.timer"]))
    try:
        addresses = sorted({x[4][0] for x in socket.getaddrinfo(state["server"], state["port"])})
        print("连接地址解析：" + ", ".join(addresses))
    except OSError as exc:
        print(f"DNS 解析失败：{exc}")
    firewall_hint(state)
    print("本机诊断不能证明公网 UDP、客户端握手或实际速度；请用导出的配置连接验证。")


def uninstall():
    load_state()
    if prompt("将停用并删除本工具的服务和配置，输入 UNINSTALL 确认") != "UNINSTALL":
        print("已取消。")
        return
    saved = backup()
    unpublish()
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
    parser.add_argument("command", nargs="?", default="menu", choices=["menu", "install", "configure", "update", "export", "publish", "unpublish", "sync-cert", "doctor", "logs", "start", "stop", "restart", "backup", "uninstall"])
    args = parser.parse_args()
    if platform.system() != "Linux" or os.geteuid() != 0 or not Path("/run/systemd/system").is_dir():
        raise ValueError("请在使用 systemd 的 Linux 服务器上以 root 运行。")
    import fcntl
    lock = open("/run/lock/demonyxp-hy.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise ValueError("另一个 hy 操作正在运行，请稍后重试。") from exc
    if not sys.stdin.isatty() and Path("/dev/tty").exists():
        try:
            sys.stdin = open("/dev/tty", encoding="utf-8")
        except OSError:
            pass
    actions = {"install": install, "configure": configure, "update": update,
               "export": lambda: export_files(load_state()), "publish": publish, "unpublish": unpublish,
               "sync-cert": lambda: sync_certificate(load_state()), "doctor": doctor,
               "logs": lambda: run(["journalctl", "-u", SERVICE, "-n", "60", "--no-pager"]),
               "start": start, "restart": restart_checked,
               "stop": lambda: run(["systemctl", "stop", SERVICE]), "backup": lambda: (load_state(), backup()),
               "uninstall": uninstall}
    if args.command != "menu":
        actions[args.command]()
        return
    options = [("安装", "install"), ("查看节点 / 导出配置", "export"), ("修改配置", "configure"),
               ("发布 / 刷新 HTTPS 订阅", "publish"), ("撤销订阅", "unpublish"), ("诊断", "doctor"),
               ("查看日志", "logs"), ("重启", "restart"), ("停止", "stop"),
               ("更新官方内核", "update"), ("备份配置", "backup"), ("卸载", "uninstall")]
    while True:
        print(f"\nHY {VERSION} — Hysteria2 中文管理")
        for i, (label, _) in enumerate(options, 1):
            print(f"{i:2}. {label}")
        selection = prompt("选择菜单，0 退出", "0")
        if selection == "0":
            return
        if selection.isdigit() and 1 <= int(selection) <= len(options):
            try:
                actions[options[int(selection) - 1][1]]()
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
