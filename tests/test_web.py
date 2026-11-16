import hashlib
import http.client
import json
from pathlib import Path
import tempfile
import socket
import threading
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import hy
import hy_web as web


class WebTests(unittest.TestCase):
    def setUp(self):
        salt = 'ab' * 16
        self.config = {'origin': 'https://panel.example.com', 'salt': salt,
                       'password_hash': web.password_hash('test-panel-password', salt)}
        self.server = web.PanelServer(('127.0.0.1', 0), self.config)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, path, body=None, cookie='', csrf='', headers=None):
        h = {'Host': 'panel.example.com', 'X-Forwarded-Proto': 'https',
             'Origin': self.config['origin'], 'Content-Type': 'application/json',
             'Cookie': cookie, 'X-CSRF-Token': csrf}
        h.update(headers or {})
        con = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=4)
        con.request('POST' if body is not None else 'GET', path,
                    json.dumps(body) if body is not None else None, h)
        resp = con.getresponse()
        result = resp.status, dict(resp.getheaders()), json.loads(resp.read())
        con.close()
        return result

    def login(self):
        status, headers, data = self.request('/api/login', {'username': 'admin', 'password': 'test-panel-password'})
        self.assertEqual(status, 200)
        cookie = headers['Set-Cookie']
        for flag in ('Secure', 'HttpOnly', 'SameSite=Strict', 'Path=/hy/'):
            self.assertIn(flag, cookie)
        return cookie.split(';')[0], data['csrf']

    def test_authentication_origin_and_csrf(self):
        for route in ('status', 'traffic', 'export', 'session'):
            self.assertEqual(self.request('/api/' + route)[0], 401)
        self.assertEqual(self.request('/api/login', {}, headers={'Origin': 'https://evil.example'})[0], 403)
        self.assertEqual(self.request('/api/status', headers={'Host': 'evil.example'})[0], 403)
        self.assertEqual(self.request('/api/status', headers={'X-Forwarded-Proto': 'http'})[0], 403)
        cookie, csrf = self.login()
        with patch.object(web, 'command') as command:
            self.assertEqual(self.request('/api/action', {'action': 'stop'}, cookie)[0], 403)
            command.assert_not_called()
        self.assertEqual(self.request('/api/logout', {}, cookie, csrf)[0], 200)
        self.assertEqual(self.request('/api/session', cookie=cookie)[0], 401)

    def test_rate_limit_and_session_expiry(self):
        for _ in range(5):
            self.assertEqual(self.request('/api/login', {'username': 'admin', 'password': 'wrong'})[0], 401)
        self.assertEqual(self.request('/api/login', {'username': 'admin', 'password': 'wrong'})[0], 429)
        self.server.attempts.clear()
        cookie, csrf = self.login()
        self.server.sessions[cookie.split('=', 1)[1]]['expires'] = time.time() - 1
        self.assertEqual(self.request('/api/session', cookie=cookie)[0], 401)

    def test_actions_are_allowlisted_and_validate_input(self):
        cookie, csrf = self.login()
        with patch.object(web, 'command') as command:
            for payload in ({'action': 'shell', 'command': 'id'}, {'action': 'stop;id'},
                            {'action': 'limit', 'ip': '1.1.1.1;id', 'upload': 1, 'download': 1},
                            {'action': 'limit', 'ip': '1.1.1.1', 'upload': -1, 'download': 1}):
                self.assertEqual(self.request('/api/action', payload, cookie, csrf)[0], 400)
            command.assert_not_called()
            self.assertEqual(self.request('/api/action', {'action': 'stop'}, cookie, csrf)[0], 200)
            command.assert_called_once_with(['systemctl', 'stop', 'hy-server.service'], timeout=45)
        with patch.object(web, 'command') as command:
            self.assertEqual(self.request('/api/action', {'action': 'limit', 'ip': '203.0.113.1',
                            'upload': '10', 'download': '50'}, cookie, csrf)[0], 200)
            self.assertEqual(command.call_args.args[0][-4:], ['--upload', '10', '--download', '50'])

    def test_export_has_no_path_traversal_and_requires_login(self):
        cookie, csrf = self.login()
        with patch.object(hy, 'load_state', return_value={'publication': None}), \
             patch.object(hy, 'client_files', return_value={'node.txt': 'hysteria2://test'}) as files:
            self.assertEqual(self.request('/api/export?format=../../etc/passwd', cookie=cookie)[0], 400)
            files.assert_not_called()
            status, headers, body = self.request('/api/export?format=node.txt', cookie=cookie)
            self.assertEqual(status, 200)
            self.assertEqual(body['content'], 'hysteria2://test')
            self.assertEqual(headers['Cache-Control'], 'no-store')

    def test_monitor_rates_do_not_invent_startup_spikes(self):
        monitor = web.Monitor()
        counts = {'203.0.113.1': {'upload': 1000000000, 'download': 2000000000}}
        with patch.object(hy, 'load_state', return_value={'traffic': {'enabled': True}}), \
             patch.object(web, 'command') as cmd, patch.object(hy, 'traffic_snapshot', return_value=counts), \
             patch.object(web.time, 'monotonic', side_effect=[10, 12, 14]):
            cmd.return_value.returncode = 0
            cmd.return_value.stdout = '{"nftables":[]}'
            monitor.sample()
            self.assertEqual(monitor.data['upload_mbps'], 0)
            counts['203.0.113.1']['upload'] += 250000
            # 模拟每次读取独立的 nft JSON 对象。
            monitor.previous = {'203.0.113.1': {'upload': 1000000000, 'download': 2000000000}}
            monitor.sample()
            self.assertEqual(monitor.data['upload_mbps'], 1)
            counts['203.0.113.1']['upload'] = 0
            monitor.sample()
            self.assertEqual(monitor.data['upload_mbps'], 0)

    def test_install_validates_site_and_protects_existing_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for origin in ('http://panel.example.com', 'https://u:p@panel.example.com', 'https://panel.example.com/path'):
                with self.assertRaises(ValueError):
                    web.site_settings(root, origin, 31244)
            (root / 'hy').mkdir()
            (root / 'hy/index.html').write_text('unrelated website')
            with patch.object(web, 'CONFIG', root / 'private/config.json'), patch.object(hy, 'load_state'):
                with self.assertRaises(ValueError):
                    web.install(str(root), 'https://panel.example.com', 31244)
            self.assertEqual((root / 'hy/index.html').read_text(), 'unrelated website')

    def test_optional_assets_are_verified(self):
        root = Path(__file__).parents[1]
        release = json.loads((root / 'release.json').read_text())
        self.assertEqual(release['web_sha256'], hashlib.sha256((root / 'hy_web.py').read_bytes()).hexdigest())
        self.assertEqual(release['web_html_sha256'], hashlib.sha256((root / 'web/index.html').read_bytes()).hexdigest())
        with patch.object(hy, 'fetch_manager', side_effect=[json.dumps({'version': hy.VERSION}).encode(), b'bad']), \
             patch.object(hy, 'atomic_write') as write:
            with self.assertRaises(ValueError):
                hy.web_module(download=True)
            write.assert_not_called()

    def test_failed_install_can_retry_and_uninstall_preserves_site(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            site = root / 'site'
            site.mkdir()
            (site / 'index.html').write_text('existing website')
            units = root / 'units'
            units.mkdir()
            config = root / 'private/config.json'
            html = b'<html>test</html>'
            meta = json.dumps({'version': hy.VERSION, 'web_html_sha256': hashlib.sha256(html).hexdigest()}).encode()
            def run(args, **kwargs):
                return SimpleNamespace(returncode=1 if args[1] == 'is-enabled' else 0, stdout='', stderr='')
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            with patch.object(web, 'CONFIG', config), patch.object(hy, 'UNIT_DIR', units), \
                 patch.object(hy, 'load_state'), patch.object(web, 'command', side_effect=run), \
                 patch.object(hy, 'fetch_manager', side_effect=[meta, html, meta, html]), \
                 patch.object(web, 'probe', side_effect=[ValueError('probe failed'), None]):
                with self.assertRaisesRegex(ValueError, 'probe failed'):
                    web.install(str(site), 'https://panel.example.com', port)
                self.assertFalse((site / 'hy').exists())
                self.assertFalse(config.exists())
                web.install(str(site), 'https://panel.example.com', port)
                self.assertTrue(config.exists())
                self.assertNotIn('password_hash', (site / 'hy/index.html').read_text())
                (site / 'hy/user-note.txt').write_text('keep')
                web.uninstall(confirm=False)
                self.assertEqual((site / 'index.html').read_text(), 'existing website')
                self.assertEqual((site / 'hy/user-note.txt').read_text(), 'keep')
                self.assertFalse(config.exists())
                self.assertFalse((units / web.SERVICE).exists())
                self.assertEqual((config.parent / 'nginx.conf').read_text(), '# HY web uninstalled\n')


if __name__ == '__main__':
    unittest.main()
