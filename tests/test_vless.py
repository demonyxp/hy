import base64
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit, parse_qs
from types import SimpleNamespace

from test_hy import hy, fixture


def vless_fixture():
    return {'server': '203.0.113.10', 'port': 24445, 'uuid': 'b52c9278-e961-4764-8f37-ce41fdf36440',
            'private_key': 'a' * 43, 'public_key': 'b' * 43, 'short_id': '0123456789abcdef',
            'target': 'www.microsoft.com:443', 'sni': 'www.microsoft.com', 'core_version': hy.VLESS_CORE_VERSION,
            'name': '备用 VLESS'}


class VlessTests(unittest.TestCase):
    def test_multi_exports_preserve_hy2_and_hide_private_key(self):
        old = fixture()
        before = hy.client_files(old)
        new = {**old, 'vless': vless_fixture()}
        files = hy.client_files(new)
        self.assertEqual(files['hy2.txt'], before['node.txt'])
        self.assertEqual(files['native.json'], before['native.json'])
        for fmt in ('hiddify.txt', 'v2rayn.txt'):
            uris = base64.b64decode(files[fmt]).decode().splitlines()
            self.assertEqual(len(uris), 2)
            self.assertEqual(uris[0], before['node.txt'].strip())
            q = parse_qs(urlsplit(uris[1]).query)
            self.assertEqual(q['pbk'], [new['vless']['public_key']])
            self.assertEqual(q['flow'], ['xtls-rprx-vision'])
        for fmt in files:
            self.assertNotIn(new['vless']['private_key'], files[fmt])
        clash = json.loads(files['clash.yaml'])
        self.assertEqual(clash['proxies'][1]['type'], 'vless')
        self.assertEqual(clash['proxy-groups'][0]['proxies'][0], old['name'])
        sing = json.loads(files['sing-box.json'])
        self.assertEqual(sing['outbounds'][0]['default'], 'hy2')
        self.assertEqual(sing['outbounds'][2]['tls']['reality']['public_key'], 'b'*43)
        self.assertEqual(hy.client_files(old), before)

    def test_vless_remains_optional_and_uses_separate_tcp_service(self):
        self.assertNotIn(hy.VLESS_SERVICE, hy.units())
        config = hy.vless_config(vless_fixture())
        self.assertEqual(config['inbounds'][0]['listen_port'], 24445)
        self.assertTrue(config['inbounds'][0]['tls']['reality']['enabled'])
        self.assertEqual(config['inbounds'][0]['users'][0]['flow'], 'xtls-rprx-vision')
        self.assertIn('User=hyproxy', hy.vless_unit())
        self.assertNotIn('hy-server.service', hy.vless_unit())

    def test_aggregate_rules_include_only_selected_protocol_ports(self):
        state = {**fixture(), 'vless': vless_fixture(), 'traffic': {'enabled': True,
                 'limits': {'203.0.113.7': {'upload': '10', 'download': '50'}}}}
        rules = hy.traffic_rules(state, True)
        self.assertIn('udp dport 24443 jump upload_limits', rules)
        self.assertIn('tcp dport 24445 jump upload_limits', rules)
        self.assertIn('tcp sport 24445 update @down4', rules)
        self.assertEqual(rules.count('ip saddr 203.0.113.7 limit rate over'), 1)
        self.assertNotIn('24444', rules)
        self.assertNotIn('flush set', rules)

    def test_target_validation_and_noninteractive_install(self):
        for target in ('example.com:80', 'example.com:443;id', 'https://example.com:443', '127.0.0.1:443'):
            with self.assertRaises(ValueError):
                hy.reality_target(target)
        with patch.object(hy.socket, 'getaddrinfo', return_value=[(2, 1, 6, '', ('127.0.0.1', 443))]):
            with self.assertRaises(ValueError):
                hy.check_reality_target('www.example.com:443', 'www.example.com')
        with patch.object(hy, 'load_state', return_value=fixture()), patch.object(hy.sys.stdin, 'isatty', return_value=False), \
             patch.object(hy, 'download_vless_core') as download:
            with self.assertRaises(ValueError):
                hy.vless_install()
            download.assert_not_called()

    def test_key_parser_current_and_legacy(self):
        for name in ('Password (PublicKey)', 'Password', 'Public key'):
            with patch.object(hy, 'output', return_value='Private key: '+ 'a'*43+'\n'+name+': '+'b'*43):
                self.assertEqual(hy.reality_keys('sing-box-vless'), ('a'*43, 'b'*43))
        with patch.object(hy, 'output', return_value='invalid output'):
            with self.assertRaises(ValueError):
                hy.reality_keys('sing-box-vless')

    def test_tcp_port_reservations_do_not_depend_on_running_services(self):
        with patch.object(hy, 'load_state', return_value={**fixture(), 'publication': {'mode': 'http', 'port': 24444}}):
            with self.assertRaises(ValueError):
                hy.check_vless_port(24444)
        with tempfile.TemporaryDirectory() as tmp:
            statefile = Path(tmp)/'state.json'
            statefile.write_text('{}')
            with patch.object(hy, 'STATE', statefile), patch.object(hy, 'load_state', return_value={'vless': {'port': 24445}}):
                with self.assertRaises(ValueError):
                    hy.check_subscription_port(24445)

    def test_commit_rolls_back_failed_start_without_touching_hy2(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            etc, lib, units = (root/x for x in ('etc', 'lib', 'units'))
            for p in (etc, lib, units):p.mkdir()
            state = fixture()
            statefile = etc/'state.json'
            statefile.write_text(json.dumps(state))
            (etc/'server.json').write_text('HY2 sentinel')
            candidate = root/'candidate'
            candidate.write_bytes(b'fake binary')
            with patch.object(hy, 'STATE', statefile), patch.object(hy, 'ETC', etc), \
                 patch.object(hy, 'LIB', lib), patch.object(hy, 'UNIT_DIR', units), \
                 patch.object(hy, 'group_id', return_value=None), patch.object(hy, 'backup'), \
                 patch.object(hy, 'vless_active', return_value=False), patch.object(hy, 'firewall_records', return_value=[]), \
                 patch.object(hy, 'firewall_apply'), patch.object(hy, 'firewall_prune'), \
                 patch.object(hy.subprocess, 'run'), patch.object(hy, 'run') as run, \
                 patch.object(hy.time, 'sleep'), patch.object(hy, 'export_files'):
                with self.assertRaises(ValueError):
                    hy.vless_commit(state, vless_fixture(), candidate)
                self.assertEqual(json.loads(statefile.read_text(encoding="utf-8")), state)
                self.assertEqual((etc/'server.json').read_text(), 'HY2 sentinel')
                self.assertFalse((lib/'sing-box-vless').exists())
                self.assertFalse((etc/'vless.json').exists())
                self.assertFalse((units/hy.VLESS_SERVICE).exists())
                for call in run.call_args_list:
                    self.assertNotIn(hy.SERVICE, [str(x) for x in call.args[0]])

    def test_remove_restores_partially_deleted_firewall_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = {**fixture(), 'vless': vless_fixture()}
            records = [{'backend': 'firewalld', 'port': 24445, 'protocol': 'tcp', 'zone': 'public', 'permanent': p}
                       for p in (False, True)]
            remaining = records[1:]
            statefile = root/'state.json'
            statefile.write_text(json.dumps(state))
            with patch.object(hy, 'load_state', return_value=state), patch.object(hy, 'STATE', statefile), \
                 patch.object(hy, 'ETC', root), patch.object(hy, 'LIB', root), patch.object(hy, 'UNIT_DIR', root), \
                 patch.object(hy, 'backup'), patch.object(hy, 'vless_active', return_value=True), \
                 patch.object(hy, 'firewall_records', side_effect=[records, remaining, remaining, remaining, remaining]), \
                 patch.object(hy, 'firewall_prune', return_value=remaining), patch.object(hy, 'save_firewall') as save, \
                 patch.object(hy, 'export_files'), patch.object(hy.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), \
                 patch.object(hy, 'run') as run:
                with self.assertRaisesRegex(ValueError, '回滚'):
                    hy.vless_remove(confirm=False)
                run.assert_any_call(hy.firewall_command(records[0], 'add'), stdout=hy.subprocess.DEVNULL)
                self.assertCountEqual(save.call_args.args[0], records)
                self.assertEqual(json.loads(statefile.read_text(encoding="utf-8")), state)

    def test_no_automatic_core_downgrade(self):
        with patch.object(hy, 'load_state', return_value={'vless': {'core_version': 'v99.1.1'}}), \
             patch.object(hy, 'download_vless_core') as download:
            with self.assertRaises(ValueError):
                hy.vless_update()
            download.assert_not_called()


if __name__ == '__main__':
    unittest.main()
