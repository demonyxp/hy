"""仅在一次性 systemd Docker 中验证真实面板权限、监控、限速和服务生命周期。"""
import contextlib
import http.client
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

if os.environ.get('HY_DISPOSABLE_TEST') != '1' or not Path('/.dockerenv').exists():
    raise SystemExit('仅允许在一次性测试容器中运行。')
root = Path(__file__).parents[1]
sys.path.insert(0, str(root))
import hy
import hy_web as web

for p in (hy.ETC, hy.LIB, hy.DATA, Path('/srv/web-fixture')):
    p.mkdir(parents=True, exist_ok=True)
for name in ('hy.py', 'hy_web.py'):
    shutil.copy2(root / name, hy.LIB / name)
hy.atomic_write('/usr/local/bin/hy', '#!/bin/sh\nexec /usr/bin/python3 /usr/local/lib/hy/hy.py "$@"\n', 0o755)
state = {'owner': hy.MARKER, 'name': '集成测试', 'server': '203.0.113.1', 'domain': 'vpn.example.com',
         'port': 24443, 'password': 'test-only-node-password', 'traffic': {'enabled': False}}
hy.atomic_write(hy.STATE, hy.json_text(state))
hy.atomic_write(hy.UNIT_DIR / hy.SERVICE, '[Unit]\nDescription=Disposable VPN lifecycle fixture\n[Service]\nExecStart=/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n', 0o644)
web.command(['systemctl', 'daemon-reload'])
web.command(['systemctl', 'start', hy.SERVICE])
hy.fetch_manager = lambda url: (root / ('release.json' if url.endswith('/release.json') else 'web/index.html')).read_bytes()
output = io.StringIO()
with contextlib.redirect_stdout(output):
    web.install('/srv/web-fixture', 'https://panel.example.com', 31244)
password = output.getvalue().split('初始密码：')[1].splitlines()[0]


def request(path, payload=None, cookie='', csrf=''):
    con = http.client.HTTPConnection('127.0.0.1', 31244, timeout=55)
    con.request('POST' if payload is not None else 'GET', '/api/' + path,
                json.dumps(payload) if payload is not None else None,
                {'Host': 'panel.example.com', 'Origin': 'https://panel.example.com',
                 'X-Forwarded-Proto': 'https', 'Content-Type': 'application/json',
                 'Cookie': cookie, 'X-CSRF-Token': csrf})
    resp = con.getresponse()
    result = resp.status, dict(resp.getheaders()), json.loads(resp.read())
    con.close()
    return result


assert request('status')[0] == 401
code, headers, data = request('login', {'username': 'admin', 'password': password})
assert code == 200, data
cookie, csrf = headers['Set-Cookie'].split(';')[0], data['csrf']
assert request('status', cookie=cookie)[2]['service'] == 'active'
for action in ({'action': 'monitor-on'}, {'action': 'limit', 'ip': '203.0.113.2', 'upload': '10', 'download': '20'}):
    response = request('action', action, cookie, csrf)
    assert response[0] == 200, response
assert hy.load_state()['traffic']['limits']['203.0.113.2']['download'] == '20'
assert '203.0.113.2' in web.command(['nft', 'list', 'table', 'inet', 'hy_traffic']).stdout
assert request('action', {'action': 'unlimit', 'ip': '203.0.113.2'}, cookie, csrf)[0] == 200
assert not hy.load_state()['traffic']['limits']
for action, expected in [('stop', 'inactive'), ('start', 'active'), ('restart', 'active')]:
    result = request('action', {'action': action}, cookie, csrf)
    assert result[0] == 200, result
    assert request('status', cookie=cookie)[2]['service'] == expected
assert request('action', {'action': 'enable'}, cookie, csrf)[0] == 200
assert request('status', cookie=cookie)[2]['autostart']
assert request('action', {'action': 'disable'}, cookie, csrf)[0] == 200
assert not request('status', cookie=cookie)[2]['autostart']
assert request('export?format=node.txt', cookie=cookie)[2]['content'].startswith('hysteria2://')
time.sleep(3)
assert request('traffic', cookie=cookie)[2]['enabled']
with contextlib.redirect_stdout(io.StringIO()):
    web.uninstall(confirm=False)
assert web.command(['systemctl', 'is-active', hy.SERVICE], check=False).returncode == 0
assert hy.load_state()['password'] == state['password']
assert not web.CONFIG.exists()
print('LIVE_WEB_OK: systemd sandbox, auth, real nft monitor/limit/unlimit, service controls, export, uninstall')
