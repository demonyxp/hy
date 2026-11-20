"""一次性 Docker/systemd 内的 REALITY 握手、双客户端、升级回滚和协议隔离测试。"""
import base64
import contextlib
import copy
import http.server
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid

if os.environ.get('HY_DISPOSABLE_TEST') != '1' or not Path('/.dockerenv').exists():
    raise SystemExit('仅限一次性测试容器；先运行 live_systemd.py。')
root = Path(__file__).parents[1]
sys.path.insert(0, str(root))
import hy


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, capture_output=True, **kwargs)


class Site(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'vless-real-connection-ok')

    def log_message(self, *args):
        pass


def connect(kind, state, reject=False):
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        binary = Path('/opt/test-clients') / kind
        files = hy.client_files(state)
        config = json.loads(files['clash.yaml' if kind == 'mihomo' else 'sing-box.json'])
        if kind == 'mihomo':
            config['mixed-port'] = 18082
            config['rules'] = ['MATCH,' + config['proxies'][1]['name']]
            validate = [binary, '-t', '-d', tmp, '-f', tmp/'config.json']
            command = [binary, '-d', tmp, '-f', tmp/'config.json']
        else:
            config['inbounds'][0]['listen_port'] = 18082
            config['route']['rules'] = []
            config['outbounds'][0]['default'] = 'vless'
            validate = [binary, 'check', '-c', tmp/'config.json']
            command = [binary, 'run', '-c', tmp/'config.json']
        (tmp/'config.json').write_text(json.dumps(config))
        run(validate)
        with (tmp/'client.log').open('w') as log:
            p = subprocess.Popen([str(a) for a in command], stdout=log, stderr=log)
            try:
                ok = False
                for _ in range(2 if reject else 10):
                    time.sleep(.3)
                    r = subprocess.run(['curl', '-fsS', '--noproxy', '', '--proxy', 'socks5h://127.0.0.1:18082',
                                        '--max-time', '3', 'http://127.0.0.1:18080/'], capture_output=True)
                    if r.returncode == 0 and r.stdout == b'vless-real-connection-ok':
                        ok = True
                        break
                    if p.poll() is not None:
                        break
                assert ok != reject, (tmp/'client.log').read_text()
            finally:
                p.terminate()
                p.wait(timeout=10)


initial = hy.load_state()
hy2_config = (hy.ETC/'server.json').read_bytes()
hy2_pid = hy.output(['systemctl', 'show', hy.SERVICE, '-p', 'MainPID', '--value'])
initial['publication'] = hy.http_publication('127.0.0.1', 18084)
hy.write_http_subscription(initial)
subscription = hy.SubscriptionServer(('127.0.0.1', 18084), hy.subscription_config_path())
threading.Thread(target=subscription.serve_forever, daemon=True).start()
subscription_url = hy.subscription_url(initial['publication'], 'hiddify.txt')
original_uri = hy.client_files(initial)['hy2.txt'].strip()

def check_subscription(count):
    result = run(['curl', '-fsS', '--noproxy', '*', subscription_url]).stdout
    nodes = base64.b64decode(result).decode().splitlines()
    assert len(nodes) == count and nodes[0] == original_uri
    assert hy.load_state()['publication'] == initial['publication']

httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 18080), Site)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    core = tmp/'sing-box'
    shutil.copy2('/opt/test-clients/sing-box', core)
    core.chmod(0o755)
    for name in ('mihomo', 'sing-box'):
        dest = Path('/opt/test-clients')/name
        assert dest.is_file(), '请先提供 /opt/test-clients/' + name
    run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', tmp/'key.pem',
         '-out', tmp/'cert.pem', '-days', '2', '-subj', '/CN=reality.example.test',
         '-addext', 'subjectAltName=DNS:reality.example.test'])
    with (tmp/'target.log').open('w') as log:
        target = subprocess.Popen(['openssl', 's_server', '-accept', '127.0.0.1:18443', '-cert', str(tmp/'cert.pem'),
                                   '-key', str(tmp/'key.pem'), '-tls1_3', '-alpn', 'h2', '-groups', 'X25519', '-quiet', '-www'],
                                  stdout=log, stderr=log)
        try:
            private, public = hy.reality_keys(core)
            v = {'server': '127.0.0.1', 'port': 24445, 'uuid': str(uuid.uuid4()), 'private_key': private,
                 'public_key': public, 'short_id': '12ab34cd56ef7890', 'target': '127.0.0.1:18443',
                 'sni': 'reality.example.test', 'name': 'VLESS test', 'core_version': hy.VLESS_CORE_VERSION}
            if os.environ.get('HY_REALITY_TEST_TARGET'):
                v['target'] = os.environ['HY_REALITY_TEST_TARGET']
                v['sni'] = v['target'].rsplit(':', 1)[0]
            with contextlib.redirect_stdout(io.StringIO()):
                hy.vless_commit(initial, v, core)
                hy.ensure_monitor()
            state = hy.load_state()
            check_subscription(2)
            for kind in ('mihomo', 'sing-box'):
                connect(kind, state)
                wrong = copy.deepcopy(state)
                wrong['vless']['uuid'] = str(uuid.uuid4())
                connect(kind, wrong, reject=True)
                print('PASS real VLESS/REALITY + UUID rejection:', kind)
            ipv6 = copy.deepcopy(state)
            ipv6['vless']['server'] = '::1'
            connect('mihomo', ipv6)
            print('PASS dual-stack VLESS listener')
            assert hy.traffic_snapshot(hy.nft_table())['127.0.0.1']['download'] > 0
            assert hy2_config == (hy.ETC/'server.json').read_bytes()
            assert hy2_pid == hy.output(['systemctl', 'show', hy.SERVICE, '-p', 'MainPID', '--value'])
            print('PASS shared counters and unchanged HY2 process/config')
            broken = tmp/'bad-core'
            broken.write_text('#!/bin/sh\nif [ "$1" = "check" ]; then exit 0; fi\nexit 1\n')
            broken.chmod(0o755)
            with contextlib.redirect_stdout(io.StringIO()):
                try:
                    hy.vless_commit(state, v, broken)
                except ValueError:
                    pass
                else:
                    raise AssertionError('broken core accepted')
            connect('mihomo', hy.load_state())
            print('PASS failed core activation rollback')
            hy.vless_control('stop')
            with contextlib.redirect_stdout(io.StringIO()):
                hy.vless_commit(hy.load_state(), {**v, 'port': 24446})
            assert not hy.vless_active()
            assert hy.load_state()['vless']['uuid'] == v['uuid']
            hy.vless_control('start')
            connect('sing-box', hy.load_state())
            with contextlib.redirect_stdout(io.StringIO()):
                hy.vless_remove(confirm=False)
            assert 'vless' not in hy.load_state()
            assert hy2_pid == hy.output(['systemctl', 'show', hy.SERVICE, '-p', 'MainPID', '--value'])
            assert hy.service_active()
            assert not (hy.DATA/'export/vless.txt').exists()
            assert 'tcp' not in hy.output(['nft', 'list', 'table', 'inet', hy.TRAFFIC_TABLE])
            check_subscription(1)
            print('PASS stopped-state preservation, port change, VLESS-only removal, unchanged subscription URL')
        finally:
            target.terminate()
            target.wait(timeout=5)
            httpd.shutdown()
            subscription.shutdown()
print('LIVE_VLESS_OK')
