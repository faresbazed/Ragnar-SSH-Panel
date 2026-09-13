#!/usr/bin/env python3
"""Run: python3 -B -m unittest -v test_xray
For real traffic tests also set XRAY_TEST_BINARY to an Xray executable.
All generated files and certificates stay inside this checkout.
"""
import base64
import contextlib
import copy
import datetime as dt
import io
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlsplit

import ragnar_xray as rx

HERE = Path(__file__).resolve().parent
BINARY = os.environ.get('XRAY_TEST_BINARY')
NOW = dt.datetime(2026, 9, 13, tzinfo=rx.UTC)


def state_fixture():
    return {'version': 1, 'domain': 'vpn.example.com', 'certificate': '/test/fullchain.pem',
            'key': '/test/privkey.pem', 'listeners': [rx.listener(*entry) for entry in rx.DEFAULTS],
            'users': [{'name': protocol + '-user', 'protocol': protocol, 'enabled': True,
                       'expires_at': '2099-01-01T00:00:00+00:00',
                       'credential': '38e29a5b-68c5-4354-a462-a859dc28dcf2' if protocol != 'trojan'
                       else 'test-only-trojan-secret'} for protocol in ('vless', 'vmess', 'trojan')]}


class ConfigurationTests(unittest.TestCase):
    def test_all_supported_combinations(self):
        state = state_fixture()
        config = rx.render(state, NOW)
        self.assertEqual(len(config['inbounds']), 10)
        self.assertEqual(len({item['port'] for item in config['inbounds']}), 10)
        for item, inbound in zip(state['listeners'], config['inbounds']):
            self.assertEqual(inbound['protocol'], item['protocol'])
            self.assertEqual(inbound['streamSettings']['network'], item['transport'])
            self.assertEqual(inbound['streamSettings']['security'], 'tls' if item['tls'] else 'none')
            self.assertEqual(len(inbound['settings']['clients']), 1)
            if item['tls']:
                self.assertEqual(inbound['streamSettings']['tlsSettings']['certificates'][0]['keyFile'], state['key'])
            else:
                self.assertNotIn('tlsSettings', inbound['streamSettings'])

    def test_expiry_boundary_and_disabled_clients(self):
        state = state_fixture()
        state['users'][0]['expires_at'] = rx.expiry('2026-09-13')
        cutoff = dt.datetime(2026, 9, 14, tzinfo=rx.UTC)
        self.assertTrue(rx.active(state['users'][0], cutoff - dt.timedelta(microseconds=1)))
        self.assertFalse(rx.active(state['users'][0], cutoff))
        state['users'][1]['enabled'] = False
        for item in rx.render(state, cutoff)['inbounds']:
            self.assertEqual(len(item['settings']['clients']), 1 if item['protocol'] == 'trojan' else 0)

    def test_bad_inputs(self):
        for args in [('trojan', 'tcp', 2052, False), ('vless', 'ws', 80, True),
                     ('vmess', 'tcp', 443, False), ('vmess', 'ws', 8443, False),
                     ('vless', 'ws', 2053, False), ('vless', 'ws', 22, False),
                     ('vless', 'ws', 0, False), ('vless', 'ws', 65536, True),
                     ('bad', 'tcp', 1234, False), ('vless', 'grpc', 1234, False)]:
            with self.subTest(args=args), self.assertRaises(ValueError):
                rx.listener(*args)
        for host in ['../example.com', 'example.com\nfoo', '-bad.example.com', 'https://example.com', 'a..com']:
            with self.assertRaises(ValueError):
                rx.hostname(host)
        self.assertEqual(rx.hostname('VPN.Example.COM'), 'vpn.example.com')
        with self.assertRaises(ValueError):
            rx.listener('vless', 'ws', 1234, False, '/vless?injected=true')
        with self.assertRaises(ValueError):
            rx.expiry('2026-02-30')

    def test_uri_fields_match_every_listener(self):
        state = state_fixture()
        for item in state['listeners']:
            user = next(user for user in state['users'] if user['protocol'] == item['protocol'])
            link = rx.uri(state, user, item)
            if item['protocol'] == 'vmess':
                data = json.loads(base64.b64decode(link[len('vmess://'):]))
                self.assertEqual(data['id'], user['credential'])
                self.assertEqual(data['aid'], '0')
                self.assertEqual(data['net'], item['transport'])
                self.assertEqual(data['tls'], 'tls' if item['tls'] else '')
                self.assertEqual(int(data['port']), item['port'])
            else:
                parts = urlsplit(link)
                query = parse_qs(parts.query)
                self.assertEqual(unquote(parts.username), user['credential'])
                self.assertEqual(parts.port, item['port'])
                self.assertEqual(query['type'], [item['transport']])
                self.assertEqual(query['security'], ['tls' if item['tls'] else 'none'])
                if item['transport'] == 'ws':
                    self.assertEqual(query['path'], [item['path']])
                if item['tls']:
                    self.assertEqual(query['sni'], [state['domain']])
                self.assertNotIn('allowInsecure', query)

    def test_occupied_port(self):
        with socket.socket() as sock:
            sock.bind(('0.0.0.0', 0))
            with self.assertRaises(ValueError):
                rx.check_port(sock.getsockname()[1])


class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='.ragnar-tests-', dir=HERE)
        self.addCleanup(self.temp.cleanup)
        self.manager = rx.Manager(Path(self.temp.name))
        self.state = state_fixture()
        self.validate = patch.object(self.manager, 'validate').start()
        self.restart = patch.object(self.manager, 'restart').start()
        self.stop = patch.object(self.manager, 'stop').start()
        self.addCleanup(patch.stopall)
        self.manager.apply(self.state, initialize=True)
        self.validate.reset_mock()

    def run_command(self, *args):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            rx.execute(rx.parser().parse_args(args), self.manager)
        return output.getvalue()

    def test_create_renew_disable_enable_delete(self):
        for protocol in ('vless', 'vmess', 'trojan'):
            with self.subTest(protocol=protocol):
                text = self.run_command('add-user', 'alice-' + protocol, protocol, '--expires', '2098-01-01')
                self.assertIn(protocol + '://', text)
                self.run_command('disable-user', 'alice-' + protocol)
                self.assertFalse(rx.find_user(self.manager.load(), 'alice-' + protocol)['enabled'])
                with self.assertRaises(ValueError):
                    self.run_command('uri', 'alice-' + protocol)
                self.run_command('renew-user', 'alice-' + protocol, '--expires', '2098-02-01')
                self.run_command('enable-user', 'alice-' + protocol)
                self.assertIn(protocol + '://', self.run_command('uri', 'alice-' + protocol))
                self.run_command('delete-user', 'alice-' + protocol)
                with self.assertRaises(ValueError):
                    rx.find_user(self.manager.load(), 'alice-' + protocol)

    def test_no_plaintext_credentials_in_user_list(self):
        text = self.run_command('users')
        for user in self.state['users']:
            self.assertNotIn(user['credential'], text)

    def test_duplicate_name_and_past_expiry_rejected(self):
        for args in [('add-user', 'vless-user', 'vless', '--expires', '2098-01-01'),
                     ('add-user', 'bad/name', 'vless', '--expires', '2098-01-01'),
                     ('add-user', 'old', 'vless', '--expires', '2000-01-01')]:
            with self.assertRaises(ValueError):
                self.run_command(*args)
        self.restart.assert_not_called()

    def test_conflicting_listener_rejected_before_service_change(self):
        with self.assertRaises(ValueError):
            self.run_command('add-listener', 'trojan', 'tcp', '443', '--tls')
        self.restart.assert_not_called()
        with patch.object(rx, 'check_port'):
            self.run_command('add-listener', 'vmess', 'tcp', '12345', '--tls')
        self.assertTrue(any(item['port'] == 12345 for item in self.manager.load()['listeners']))
        self.run_command('delete-listener', 'vmess-tcp-12345')
        self.assertFalse(any(item['port'] == 12345 for item in self.manager.load()['listeners']))

    def test_private_atomic_files(self):
        for path in (self.manager.state_path, self.manager.config_path):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertFalse(any(path.name.startswith('.') for path in self.manager.root.iterdir()))

    def test_validation_failure_restores_previous_state(self):
        self.validate.side_effect = ValueError('bad config')
        old = self.manager.state_path.read_bytes()
        state = copy.deepcopy(self.state)
        state['users'] = []
        with self.assertRaises(ValueError):
            self.manager.apply(state)
        self.assertEqual(self.manager.state_path.read_bytes(), old)

    def test_restart_failure_rolls_back(self):
        self.restart.side_effect = [subprocess.CalledProcessError(1, 'systemctl'), None]
        old = self.manager.state_path.read_bytes()
        state = copy.deepcopy(self.state)
        state['users'] = []
        with self.assertRaises(subprocess.CalledProcessError):
            self.manager.apply(state)
        self.assertEqual(self.manager.state_path.read_bytes(), old)
        self.assertEqual(len(json.loads(self.manager.config_path.read_text())['inbounds'][0]['settings']['clients']), 1)
        self.stop.assert_not_called()

    def test_expiry_changes_config_once_and_preserves_users(self):
        state = copy.deepcopy(self.state)
        for user in state['users']:
            user['expires_at'] = '2000-01-01T00:00:00+00:00'
        rx.atomic(self.manager.state_path, rx.encoded(state))
        self.run_command('sync')
        self.restart.assert_called_once()
        self.run_command('sync')
        self.restart.assert_called_once()
        self.assertEqual(len(self.manager.load()['users']), 3)
        self.assertTrue(all(not item['settings']['clients'] for item in json.loads(self.manager.config_path.read_text())['inbounds']))

    def test_expiry_failure_stops_service_instead_of_restoring_credentials(self):
        state = copy.deepcopy(self.state)
        state['users'] = []
        self.restart.side_effect = subprocess.CalledProcessError(1, 'systemctl')
        with self.assertRaises(subprocess.CalledProcessError):
            self.manager.apply(state, revoke=True)
        self.stop.assert_called_once()
        self.assertTrue(all(not item['settings']['clients'] for item in json.loads(self.manager.config_path.read_text())['inbounds']))

    def test_boot_removes_expired_credentials_before_start(self):
        state = copy.deepcopy(self.state)
        for user in state['users']:
            user['expires_at'] = '2000-01-01T00:00:00+00:00'
        rx.atomic(self.manager.state_path, rx.encoded(state))
        self.manager.boot()
        self.assertTrue(all(not item['settings']['clients'] for item in json.loads(self.manager.config_path.read_text())['inbounds']))


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            while True:
                chunk = self.request.recv(16384)
                if not chunk:
                    return
                self.request.sendall(chunk)
        except (OSError, TimeoutError):
            pass


class EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def receive(sock, size):
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError('Connection closed')
        data += chunk
    return data


def connect_socks(port, target):
    sock = socket.create_connection(('127.0.0.1', port), timeout=3)
    try:
        sock.sendall(b'\x05\x01\x00')
        if receive(sock, 2) != b'\x05\x00':
            raise OSError('SOCKS auth failed')
        sock.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', target))
        header = receive(sock, 4)
        if header[1] != 0:
            raise OSError('SOCKS connect failed')
        receive(sock, 6 if header[3] == 1 else 18)
        return sock
    except Exception:
        sock.close()
        raise


def outbound_from_uri(link, certificate):
    """Decode exported URIs to client config, so traffic tests cover URI correctness too."""
    if link.startswith('vmess://'):
        data = json.loads(base64.b64decode(link[8:]))
        protocol, port, transport = 'vmess', int(data['port']), data['net']
        credential, tls, host, path = data['id'], data['tls'] == 'tls', data['sni'], data['path']
    else:
        parts = urlsplit(link)
        query = parse_qs(parts.query)
        protocol, port, transport = parts.scheme, parts.port, query['type'][0]
        credential, tls = unquote(parts.username), query['security'] == ['tls']
        host, path = query.get('sni', [''])[0], query.get('path', [''])[0]
    stream = {'network': transport, 'security': 'tls' if tls else 'none'}
    if transport == 'ws':
        stream['wsSettings'] = {'path': path, 'headers': {'Host': 'vpn.example.com'}}
    if tls:
        stream['tlsSettings'] = {'serverName': host, 'allowInsecure': False, 'alpn': ['http/1.1'],
                                 'disableSystemRoot': True,
                                 'certificates': [{'certificateFile': str(certificate), 'usage': 'verify'}]}
    if protocol == 'trojan':
        settings = {'servers': [{'address': '127.0.0.1', 'port': port, 'password': credential}]}
    else:
        user = {'id': credential, 'encryption': 'none'} if protocol == 'vless' else {'id': credential, 'alterId': 0, 'security': 'auto'}
        settings = {'vnext': [{'address': '127.0.0.1', 'port': port, 'users': [user]}]}
    return {'protocol': protocol, 'settings': settings, 'streamSettings': stream}


@unittest.skipUnless(BINARY, 'Set XRAY_TEST_BINARY to run real Xray traffic tests')
class XrayTrafficTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='.ragnar-tests-', dir=HERE)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.processes = []
        self.addCleanup(self.stop_processes)
        self.state = state_fixture()
        certificate, key = self.root / 'cert.pem', self.root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-keyout', str(key), '-out', str(certificate), '-subj', '/CN=vpn.example.com',
                        '-addext', 'subjectAltName=DNS:vpn.example.com',
                        '-addext', 'basicConstraints=critical,CA:TRUE'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        self.state.update(certificate=str(certificate), key=str(key))
        # Validate the exact production defaults, then remap to unprivileged local ports.
        rx.Manager(self.root, BINARY).validate(rx.render(self.state))
        used = set()
        for item in self.state['listeners']:
            port = free_port()
            while port in used:
                port = free_port()
            used.add(port)
            item['port'] = port
        self.server = self.start_process('server', rx.render(self.state), self.state['listeners'][0]['port'])
        self.echo = EchoServer(('127.0.0.1', 0), Echo)
        self.addCleanup(self.echo.server_close)
        self.addCleanup(self.echo.shutdown)
        threading.Thread(target=self.echo.serve_forever, daemon=True).start()
        self.target = self.echo.server_address[1]

    def stop_processes(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    def start_process(self, name, config, port):
        path = self.root / (name + '.json')
        rx.atomic(path, rx.encoded(config))
        rx.Manager(self.root, BINARY).validate(config)
        with (self.root / (name + '.log')).open('ab') as log:
            process = subprocess.Popen([BINARY, 'run', '-config', str(path)], stdout=log, stderr=log)
        self.processes.append(process)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if process.poll() is not None:
                self.fail((self.root / (name + '.log')).read_text())
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.1):
                    return process
            except OSError:
                time.sleep(.05)
        self.fail('Xray failed to open listener: ' + name)

    def client(self, item, bad_credential=False):
        user = copy.deepcopy(next(user for user in self.state['users'] if user['protocol'] == item['protocol']))
        if bad_credential:
            user['credential'] = 'wrong-secret' if item['protocol'] == 'trojan' else '3c50921b-b7db-4270-b283-5804486b2b33'
        outbound = outbound_from_uri(rx.uri(self.state, user, item), self.state['certificate'])
        port = free_port()
        config = {'log': {'loglevel': 'warning'}, 'inbounds': [
            {'listen': '127.0.0.1', 'port': port, 'protocol': 'socks', 'settings': {'auth': 'noauth'}}],
                  'outbounds': [outbound]}
        process = self.start_process('client-' + str(port), config, port)
        return process, port

    def assert_traffic(self, port):
        with connect_socks(port, self.target) as sock:
            data = b'Ragnar authenticated traffic\x00\xff' * 128
            sock.sendall(data)
            self.assertEqual(receive(sock, len(data)), data)

    def assert_denied(self, port):
        with self.assertRaises((OSError, TimeoutError)):
            self.assert_traffic(port)

    def test_uri_roundtrip_traffic_and_rejected_credentials_all_ten_profiles(self):
        for item in self.state['listeners']:
            with self.subTest(profile=item['id']):
                process, port = self.client(item)
                self.assert_traffic(port)
                process.terminate()
                process.wait(timeout=5)
                process, port = self.client(item, bad_credential=True)
                self.assert_denied(port)
                process.terminate()
                process.wait(timeout=5)

    def test_expiry_revokes_existing_and_new_sessions_then_renewal_restores(self):
        item = self.state['listeners'][1]  # primary VLESS TLS WS profile
        _, port = self.client(item)
        self.assert_traffic(port)
        live = connect_socks(port, self.target)
        self.addCleanup(live.close)
        live.sendall(b'before expiry')
        self.assertEqual(receive(live, 13), b'before expiry')
        self.server.terminate()
        self.server.wait(timeout=5)
        self.state['users'][0]['expires_at'] = '2000-01-01T00:00:00+00:00'
        self.server = self.start_process('expired-server', rx.render(self.state), item['port'])
        with self.assertRaises(OSError):
            receive(live, 1)
        self.assert_denied(port)
        self.server.terminate()
        self.server.wait(timeout=5)
        self.state['users'][0]['expires_at'] = '2099-01-01T00:00:00+00:00'
        self.server = self.start_process('renewed-server', rx.render(self.state), item['port'])
        self.assert_traffic(port)


if __name__ == '__main__':
    unittest.main()
