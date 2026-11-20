#!/usr/bin/env python3
"""HY 可选面板：只监听回环地址，交给已有 HTTPS 网站反代。"""
import collections
import hashlib
import hmac
import http.client
import http.cookies
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import threading
import time
import urllib.parse

import hy

CONFIG = Path('/etc/hy-web/config.json')
SERVICE = 'hy-web.service'
PREFIX = '/hy/'
FILES = {'node.txt', 'hy2.txt', 'vless.txt', 'hiddify.txt', 'v2rayn.txt', 'clash.yaml', 'flclash.yaml', 'sing-box.json'}


class OperationError(RuntimeError):
    pass


def read_config():
    return json.loads(CONFIG.read_text())


def password_hash(password, salt):
    return hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()


def command(args, timeout=15, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise OperationError((result.stderr or result.stdout or '操作失败')[-600:])
    return result


def site_settings(root, origin, port):
    p = urllib.parse.urlsplit(origin)
    if p.scheme != 'https' or not p.hostname or p.username or p.password or p.query or p.fragment or p.path not in ('', '/'):
        raise ValueError('面板地址必须是已有网站的 HTTPS 源地址，例如 https://panel.example.com')
    hy.domain(p.hostname)
    if p.port not in (None, 443):
        raise ValueError('面板复用网站的 HTTPS 443 端口。')
    root = Path(root)
    if not root.is_absolute() or not root.is_dir() or any(x in str(root) for x in (' ', '\n', ';', '"', '{', '}')):
        raise ValueError('请输入存在且不含空格或 Nginx 特殊字符的网站根目录。')
    return {'root': str(root.resolve()), 'origin': 'https://' + p.hostname.lower(), 'port': hy.port_number(port)}


def nginx_config(config):
    # 静态文件只包含界面；配置、登录凭据均不在网站目录。
    return f'''# {hy.MARKER} optional web panel
location = /hy {{ return 301 /hy/; }}
location ^~ /hy/api/ {{
    if ($scheme != https) {{ return 403; }}
    proxy_pass http://127.0.0.1:{config['port']}/api/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_connect_timeout 5s;
    proxy_read_timeout 60s;
    proxy_buffering off;
    client_max_body_size 8k;
}}
location ^~ /hy/ {{
    if ($scheme != https) {{ return 301 https://$host$request_uri; }}
    alias {config['root']}/hy/;
    index index.html;
    autoindex off;
    add_header Cache-Control "no-store" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer always;
    add_header Content-Security-Policy "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'" always;
}}
'''


def install(root=None, origin=None, port=None):
    hy.load_state()
    old = read_config() if CONFIG.exists() else None
    config = site_settings(root or (old or {}).get('root') or hy.prompt('已有 HTTPS 网站根目录'),
                           origin or (old or {}).get('origin') or hy.prompt('已有 HTTPS 网站地址'),
                           port or (old or {}).get('port', 31244))
    if old and any(config[k] != old[k] for k in ('root', 'origin', 'port')):
        raise ValueError('面板已安装；迁移地址请先 web-uninstall，再重新安装。')
    target = Path(config['root']) / 'hy'
    target_existed = target.exists()
    config_dir_existed = CONFIG.parent.exists()
    marker = target / '.hy-web-owner'
    if target.exists() and (target.is_symlink() or not marker.is_file() or marker.read_text() != hy.MARKER):
        raise ValueError('网站中已有非本工具的 hy 路径，拒绝覆盖。')
    unit = hy.UNIT_DIR / SERVICE
    if unit.exists() and hy.MARKER not in unit.read_text():
        raise ValueError('已有同名服务不属于本工具。')
    if not old:
        with socket.socket() as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('127.0.0.1', config['port']))
    manifest = json.loads(hy.fetch_manager(f'{hy.MANAGER_URL}/v{hy.VERSION}/release.json'))
    html = hy.fetch_manager(f'{hy.MANAGER_URL}/v{hy.VERSION}/web/index.html')
    if manifest.get('version') != hy.VERSION or hashlib.sha256(html).hexdigest() != manifest.get('web_html_sha256'):
        raise ValueError('面板页面 SHA-256 校验失败。')
    password = None
    if old:
        config = old
    else:
        password = secrets.token_urlsafe(24)
        config.update(salt=secrets.token_hex(16))
        config['password_hash'] = password_hash(password, config['salt'])
    unit_text = f'''# {hy.MARKER}
[Unit]
Description=HY optional web management
After=network.target
[Service]
ExecStart=/usr/bin/python3 {hy.LIB}/hy_web.py serve
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/etc/hy /etc/systemd/system /var/lib/hy
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
TasksMax=48
MemoryMax=192M
[Install]
WantedBy=multi-user.target
'''
    paths = [CONFIG, unit, target / 'index.html', marker, CONFIG.parent / 'nginx.conf']
    saved = {p: p.read_bytes() if p.exists() else None for p in paths}
    active = command(['systemctl', 'is-active', SERVICE], check=False).returncode == 0
    enabled = command(['systemctl', 'is-enabled', SERVICE], check=False).returncode == 0
    try:
        CONFIG.parent.mkdir(mode=0o700, exist_ok=True)
        os.chmod(CONFIG.parent, 0o700)
        target.mkdir(mode=0o755, exist_ok=True)
        hy.atomic_write(CONFIG, hy.json_text(config))
        hy.atomic_write(target / 'index.html', html, 0o644)
        hy.atomic_write(marker, hy.MARKER, 0o600)
        hy.atomic_write(CONFIG.parent / 'nginx.conf', nginx_config(config))
        hy.atomic_write(unit, unit_text, 0o644)
        command(['systemctl', 'daemon-reload'])
        command(['systemctl', 'enable', '--now', SERVICE])
        command(['systemctl', 'restart', SERVICE])
        if command(['systemctl', 'is-active', SERVICE], check=False).returncode:
            raise ValueError('面板服务启动失败。')
        probe(config)
    except Exception:
        command(['systemctl', 'stop', SERVICE], check=False)
        if not enabled:
            command(['systemctl', 'disable', SERVICE], check=False)
        for p, data in saved.items():
            if data is None:
                p.unlink(missing_ok=True)
            else:
                hy.atomic_write(p, data, 0o644 if p in (unit, target / 'index.html') else 0o600)
        command(['systemctl', 'daemon-reload'], check=False)
        if active:
            command(['systemctl', 'start', SERVICE], check=False)
        for directory, existed in ((target, target_existed), (CONFIG.parent, config_dir_existed)):
            if not existed and directory.is_dir() and not any(directory.iterdir()):
                directory.rmdir()
        raise
    print('面板已安装：' + config['origin'] + PREFIX)
    print('将 /etc/hy-web/nginx.conf 的内容加入该网站 server 块，检查 Nginx 配置后重载。')
    if password:
        # 凭据只显示给当前 SSH 操作者，不写入网站或日志。
        print('用户名：admin\n初始密码：' + password)
    else:
        print('已保留原有登录密码。')


def probe(config):
    for _ in range(20):
        connection = http.client.HTTPConnection('127.0.0.1', config['port'], timeout=1)
        try:
            connection.request('GET', '/api/session', headers={
                'Host': urllib.parse.urlsplit(config['origin']).netloc, 'X-Forwarded-Proto': 'https'})
            response = connection.getresponse()
            if response.status == 401 and json.loads(response.read()).get('error') == '请先登录。':
                return
        except (OSError, ValueError, http.client.HTTPException):
            pass
        finally:
            connection.close()
        time.sleep(0.2)
    raise ValueError('面板 HTTP 健康检查失败，已回滚安装。')


def uninstall(confirm=True):
    if not CONFIG.exists():
        print('尚未安装可视化面板。')
        return
    config = read_config()
    if confirm and hy.prompt('只卸载面板，保留 VPN；输入 REMOVE 确认') != 'REMOVE':
        return
    unit = hy.UNIT_DIR / SERVICE
    if unit.exists() and hy.MARKER not in unit.read_text():
        raise ValueError('同名服务归属不符，拒绝卸载。')
    target = Path(config['root']) / 'hy'
    marker = target / '.hy-web-owner'
    if target.is_symlink() or not marker.exists() or marker.read_text() != hy.MARKER:
        raise ValueError('面板目录归属不符，拒绝删除。')
    command(['systemctl', 'disable', '--now', SERVICE])
    unit.unlink(missing_ok=True)
    command(['systemctl', 'daemon-reload'])
    # 只删除已知文件，用户自己放入的文件保留。
    (target / 'index.html').unlink(missing_ok=True)
    marker.unlink(missing_ok=True)
    if not any(target.iterdir()):
        target.rmdir()
    CONFIG.unlink()
    # 已被网站 include 的片段保留为空，避免卸载导致 Nginx 无法重载。
    hy.atomic_write(CONFIG.parent / 'nginx.conf', '# HY web uninstalled\n')
    print('面板已卸载，VPN 配置未改变。可移除网站中的 HY 反代片段。')


def reset_password():
    config = read_config()
    password = hy.prompt('新面板密码（至少 12 位）', secret=True)
    if len(password) < 12 or len(password) > 128:
        raise ValueError('密码长度需要 12～128 位。')
    config['salt'] = secrets.token_hex(16)
    config['password_hash'] = password_hash(password, config['salt'])
    hy.atomic_write(CONFIG, hy.json_text(config))
    command(['systemctl', 'restart', SERVICE])
    print('密码已更新，原登录会话已失效。')


def status_data():
    state = hy.load_state()
    active = command(['systemctl', 'is-active', hy.SERVICE], check=False).stdout.strip()
    enabled = command(['systemctl', 'is-enabled', hy.SERVICE], check=False).stdout.strip()
    mem = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    total = int(mem['MemTotal'].split()[0])
    available = int(mem['MemAvailable'].split()[0])
    disk = shutil.disk_usage('/')
    vless = None
    if state.get('vless'):
        vless = {key: state['vless'][key] for key in ('name', 'server', 'port', 'sni', 'core_version')}
        vless['service'] = command(['systemctl', 'is-active', hy.VLESS_SERVICE], check=False).stdout.strip()
        vless['autostart'] = command(['systemctl', 'is-enabled', hy.VLESS_SERVICE], check=False).returncode == 0
    return dict(version=hy.VERSION, core=state.get('core_version', ''), name=state['name'], vless=vless,
                server=state['server'], port=state['port'], mode=state.get('cert_mode', 'existing'),
                service=active, autostart=enabled == 'enabled', load=os.getloadavg()[0],
                memory_percent=round((total - available) / total * 100, 1),
                disk_percent=round(disk.used / disk.total * 100, 1),
                uptime=int(float(Path('/proc/uptime').read_text().split()[0])))


class Monitor:
    def __init__(self):
        self.lock = threading.Lock()
        self.data = {'ready': False, 'clients': [], 'error': None}
        self.previous = {}
        self.previous_time = None

    def sample(self):
        state = hy.load_state()
        # 只读 nft；打开网页不会自动启用统计或重建规则。
        result = command(['nft', '-j', 'list', 'table', 'inet', hy.TRAFFIC_TABLE], timeout=4, check=False)
        if result.returncode:
            if 'No such file' not in result.stderr:
                raise ValueError('无法读取 HY2 计数器，请检查 nftables。')
            table = None
        else:
            table = json.loads(result.stdout)
        current = hy.traffic_snapshot(table)
        now = time.monotonic()
        elapsed = now - self.previous_time if self.previous_time else None
        limits = state.get('traffic', {}).get('limits', {})
        rows = []
        for address in current.keys() | limits.keys():
            counts = current.get(address, {'upload': 0, 'download': 0})
            before = self.previous.get(address, counts)
            rates = {d: max(0, counts[d] - before[d]) * 8 / elapsed / 1e6 if elapsed else 0
                     for d in ('upload', 'download')}
            rows.append(dict(ip=address, **counts, upload_mbps=rates['upload'], download_mbps=rates['download'],
                             limits=limits.get(address, {'upload': '0', 'download': '0'})))
        rows.sort(key=lambda r: r['upload_mbps'] + r['download_mbps'], reverse=True)
        data = dict(ready=True, enabled=bool(table and state.get('traffic', {}).get('enabled')),
                    scope='HY2 + VLESS' if state.get('vless') else 'HY2',
                    clients=rows[:200], count=len(rows),
                    upload_mbps=sum(r['upload_mbps'] for r in rows), download_mbps=sum(r['download_mbps'] for r in rows),
                    upload=sum(r['upload'] for r in rows), download=sum(r['download'] for r in rows),
                    updated=time.time(), error=None)
        self.previous, self.previous_time = current, now
        with self.lock:
            self.data = data

    def loop(self):
        while True:
            try:
                self.sample()
            except Exception:
                with self.lock:
                    self.data = {**self.data, 'error': '统计读取失败，正在重试。'}
            time.sleep(3)


class PanelServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, config):
        self.config = config
        self.sessions = {}
        self.attempts = collections.deque(maxlen=500)
        self.guard = threading.Lock()
        self.mutation = threading.Lock()
        self.slots = threading.BoundedSemaphore(16)
        self.monitor = Monitor()
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(False):
            request.close()
            return
        request.settimeout(10)
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


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'HY-Web'

    def log_message(self, *args):
        pass

    def reply(self, code, data, cookie=None):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(body)

    def cookie(self, token, age=28800):
        return f'hy_session={token}; Path={PREFIX}; Max-Age={age}; Secure; HttpOnly; SameSite=Strict'

    def session(self):
        cookies = http.cookies.SimpleCookie()
        try:
            cookies.load(self.headers.get('Cookie', ''))
        except http.cookies.CookieError:
            return None, None
        token = cookies.get('hy_session')
        token = token.value if token else ''
        with self.server.guard:
            session = self.server.sessions.get(token)
            if session and session['expires'] > time.time():
                return token, session
            self.server.sessions.pop(token, None)
        return None, None

    def do_GET(self):
        self.dispatch(False)

    def do_POST(self):
        self.dispatch(True)

    def dispatch(self, mutation):
        try:
            config = self.server.config
            expected_host = urllib.parse.urlsplit(config['origin']).netloc
            if self.headers.get('Host') != expected_host or self.headers.get('X-Forwarded-Proto') != 'https':
                self.reply(403, {'error': '请通过配置的 HTTPS 网站访问。'})
                return
            url = urllib.parse.urlsplit(self.path)
            payload = {}
            if mutation:
                if self.headers.get('Origin') != config['origin']:
                    self.reply(403, {'error': '请求来源不匹配。'})
                    return
                if self.headers.get('Transfer-Encoding') or self.headers.get_content_type() != 'application/json':
                    self.reply(400, {'error': '仅接受 JSON 请求。'})
                    return
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 8192:
                    self.reply(413, {'error': '请求大小无效。'})
                    return
                payload = json.loads(self.rfile.read(size))
                if not isinstance(payload, dict):
                    raise ValueError('请求格式无效。')
            if url.path == '/api/login' and mutation:
                self.login(payload)
                return
            token, session = self.session()
            if not session:
                self.reply(401, {'error': '请先登录。'})
                return
            if mutation and not hmac.compare_digest(self.headers.get('X-CSRF-Token', ''), session['csrf']):
                self.reply(403, {'error': '会话校验失败，请刷新后重试。'})
                return
            if url.path == '/api/session' and not mutation:
                self.reply(200, {'csrf': session['csrf']})
            elif url.path == '/api/logout' and mutation:
                with self.server.guard:
                    self.server.sessions.pop(token, None)
                self.reply(200, {'ok': True}, self.cookie('', 0))
            elif url.path == '/api/status' and not mutation:
                self.reply(200, status_data())
            elif url.path == '/api/traffic' and not mutation:
                with self.server.monitor.lock:
                    data = dict(self.server.monitor.data)
                self.reply(200, data)
            elif url.path == '/api/export' and not mutation:
                name = urllib.parse.parse_qs(url.query).get('format', ['node.txt'])[0]
                if name not in FILES:
                    raise ValueError('不支持的导出格式。')
                state = hy.load_state()
                if name == 'vless.txt' and not state.get('vless'):
                    raise ValueError('尚未安装 VLESS。')
                publication = state.get('publication')
                self.reply(200, {'filename': name, 'content': hy.client_files(state)[name],
                                 'subscription': hy.subscription_url(publication, name) if publication and name in hy.SUBSCRIPTIONS else None})
            elif url.path == '/api/action' and mutation:
                self.action(payload)
            else:
                self.reply(404, {'error': '接口不存在。'})
        except OperationError as exc:
            self.reply(503, {'error': '系统操作失败：' + str(exc)})
        except (ValueError, TypeError, KeyError):
            self.reply(400, {'error': '输入无效，请检查 IP、限速数值和操作名称。'})
        except subprocess.TimeoutExpired:
            self.reply(504, {'error': '系统操作超时，请刷新状态后确认结果。'})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            self.reply(500, {'error': '服务器处理失败，请通过 SSH 检查面板日志和 HY 状态。'})

    def login(self, payload):
        password = payload.get('password', '')
        if not isinstance(password, str) or len(password) > 128:
            raise ValueError('密码格式无效。')
        peer = self.headers.get('X-Real-IP', self.client_address[0])
        now = time.time()
        with self.server.guard:
            while self.server.attempts and self.server.attempts[0][0] < now - 60:
                self.server.attempts.popleft()
            if sum(ip == peer for _, ip in self.server.attempts) >= 5 or len(self.server.attempts) >= 60:
                self.reply(429, {'error': '尝试过于频繁，请 60 秒后重试。'})
                return
            self.server.attempts.append((now, peer))
        config = self.server.config
        good = hmac.compare_digest(password_hash(password, config['salt']), config['password_hash'])
        if payload.get('username') != 'admin' or not good:
            self.reply(401, {'error': '用户名或密码错误。'})
            return
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        with self.server.guard:
            self.server.sessions = {k: v for k, v in self.server.sessions.items() if v['expires'] > now}
            if len(self.server.sessions) >= 32:
                self.server.sessions.pop(next(iter(self.server.sessions)))
            self.server.sessions[token] = {'expires': now + 28800, 'csrf': csrf}
        self.reply(200, {'csrf': csrf}, self.cookie(token))

    def action(self, payload):
        name = payload.get('action')
        protocol = payload.get('protocol', 'hy2')
        if protocol not in ('hy2', 'vless'):
            raise ValueError('无效协议。')
        if protocol == 'vless' and not hy.load_state().get('vless'):
            raise ValueError('尚未安装 VLESS。')
        service = hy.VLESS_SERVICE if protocol == 'vless' else hy.SERVICE
        commands = {a: ['systemctl', a, service] for a in ('start', 'stop', 'restart', 'enable', 'disable')}
        commands['monitor-on'] = ['/usr/local/bin/hy', 'monitor', '--once']
        if name == 'limit':
            address = hy.ip_literal(payload.get('ip', ''))
            up, down = (hy.rate_mbps(str(payload.get(k, ''))) for k in ('upload', 'download'))
            cmd = ['/usr/local/bin/hy', 'limit', address, '--upload', up, '--download', down]
        elif name == 'unlimit':
            cmd = ['/usr/local/bin/hy', 'unlimit', hy.ip_literal(payload.get('ip', ''))]
        elif name in commands:
            cmd = commands[name]
        else:
            raise ValueError('未知操作。')
        # 仅序列化同一面板内的写操作，不占用管理器跨进程锁。
        if not self.server.mutation.acquire(False):
            self.reply(409, {'error': '面板正在执行上一项操作，请稍后重试。'})
            return
        try:
            command(cmd, timeout=45)
            self.reply(200, {'ok': True})
        finally:
            self.server.mutation.release()


def serve():
    config = read_config()
    server = PanelServer(('127.0.0.1', config['port']), config)
    threading.Thread(target=server.monitor.loop, daemon=True).start()
    server.serve_forever()


if __name__ == '__main__':
    import sys
    if sys.argv[1:] == ['serve']:
        serve()
