#!/usr/bin/env python3
"""Root-only Xray account/listener manager. No third-party Python dependencies."""
import argparse
import base64
import copy
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote, urlencode
import uuid

ROOT = Path('/etc/ragnar/xray')
XRAY = '/usr/local/lib/ragnar-xray/xray'
SERVICE = 'ragnar-xray.service'
RENEWAL_MARKER = Path('/run/ragnar-cert-renew/services')
UTC = dt.timezone.utc
RESERVED = {22, 53, 444, 7300, 8080}
DEFAULTS = [
    ('vless', 'ws', 80, False), ('vless', 'ws', 443, True),
    ('vmess', 'ws', 8081, False), ('vmess', 'ws', 8443, True),
    ('trojan', 'ws', 2053, True),
    ('vless', 'tcp', 2082, False), ('vless', 'tcp', 2443, True),
    ('vmess', 'tcp', 2086, False), ('vmess', 'tcp', 2444, True),
    ('trojan', 'tcp', 2445, True),
]


def now_utc():
    return dt.datetime.now(UTC)


def hostname(value):
    value = value.lower()
    if len(value) > 253 or '.' not in value or any(
        not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
        for part in value.split('.')
    ):
        raise ValueError('Enter a valid DNS hostname (not a URL or IP address).')
    # Numeric IP literals should not pass DNS/certificate validation.
    if re.fullmatch(r'[0-9.]+', value):
        raise ValueError('Use a DNS hostname, not an IP address.')
    return value


def expiry(value):
    """An account is valid through the selected date, in UTC."""
    day = dt.date.fromisoformat(value)
    if value != day.isoformat():
        raise ValueError('Expiry must be YYYY-MM-DD.')
    return dt.datetime.combine(day + dt.timedelta(days=1), dt.time(), UTC).isoformat()


def active(user, now):
    return user['enabled'] and dt.datetime.fromisoformat(user['expires_at']) > now


def listener(protocol, transport, port, tls, path=None):
    if protocol not in ('vless', 'vmess', 'trojan') or transport not in ('ws', 'tcp'):
        raise ValueError('Supported protocols: vless/vmess/trojan; transports: ws/tcp.')
    if not 1 <= port <= 65535 or port in RESERVED:
        raise ValueError('Invalid port or reserved SSH/DNS/UDP gateway port.')
    if port == 80 and tls:
        raise ValueError('Port 80 is reserved for non-TLS.')
    if port in (443, 8443, 2053) and not tls:
        raise ValueError('Ports 443, 8443 and 2053 require TLS.')
    if protocol == 'trojan' and not tls:
        raise ValueError('Trojan requires TLS. Use VLESS/VMess for non-TLS.')
    path = path or '/' + protocol
    if not re.fullmatch(r'/[a-zA-Z0-9/_-]{1,100}', path):
        raise ValueError('WS path must start with / and contain letters, numbers, /, _ or -.')
    return {'id': '{}-{}-{}'.format(protocol, transport, port), 'protocol': protocol,
            'transport': transport, 'port': port, 'tls': tls, 'path': path}


def render(state, now=None):
    now = now or now_utc()
    inbounds = []
    for item in state['listeners']:
        protocol = item['protocol']
        clients = []
        for user in state['users']:
            if user['protocol'] != protocol or not active(user, now):
                continue
            client = {'email': user['name'] + '@ragnar.invalid'}
            if protocol == 'trojan':
                client['password'] = user['credential']
            else:
                client['id'] = user['credential']
                if protocol == 'vmess':
                    client['alterId'] = 0
            clients.append(client)
        settings = {'clients': clients}
        if protocol == 'vless':
            settings['decryption'] = 'none'
        stream = {'network': item['transport'], 'security': 'tls' if item['tls'] else 'none'}
        if item['transport'] == 'ws':
            stream['wsSettings'] = {'path': item['path']}
        if item['tls']:
            stream['tlsSettings'] = {
                'minVersion': '1.2', 'alpn': ['http/1.1'],
                'certificates': [{'certificateFile': state['certificate'], 'keyFile': state['key']}]}
        inbounds.append({'tag': item['id'], 'listen': '0.0.0.0', 'port': item['port'],
                         'protocol': protocol, 'settings': settings, 'streamSettings': stream})
    return {'log': {'loglevel': 'warning'}, 'inbounds': inbounds,
            'outbounds': [{'protocol': 'freedom', 'tag': 'direct'}]}


def uri(state, user, item):
    host = state['domain']
    label = '{}-{}'.format(user['name'], item['id'])
    security = 'tls' if item['tls'] else 'none'
    if user['protocol'] == 'vmess':
        data = {'v': '2', 'ps': label, 'add': host, 'port': str(item['port']),
                'id': user['credential'], 'aid': '0', 'scy': 'auto',
                'net': item['transport'], 'type': 'none',
                'host': host if item['transport'] == 'ws' else '',
                'path': item['path'] if item['transport'] == 'ws' else '',
                'tls': 'tls' if item['tls'] else '', 'sni': host if item['tls'] else '',
                'alpn': 'http/1.1' if item['tls'] else ''}
        return 'vmess://' + base64.b64encode(json.dumps(data).encode()).decode()
    query = {'security': security, 'type': item['transport']}
    if user['protocol'] == 'vless':
        query['encryption'] = 'none'
    if item['tls']:
        query.update(sni=host, alpn='http/1.1')
    if item['transport'] == 'ws':
        query.update(host=host, path=item['path'])
    else:
        query['headerType'] = 'none'
    return '{}://{}@{}:{}?{}#{}'.format(user['protocol'], quote(user['credential'], safe=''),
                                       host, item['port'], urlencode(query), quote(label, safe=''))


def encoded(data):
    return (json.dumps(data, indent=2, sort_keys=True) + '\n').encode()


def atomic(path, data):
    """Durable, owner-only replacement; never expose credentials in a partial file."""
    fd, name = tempfile.mkstemp(prefix='.' + path.name, dir=str(path.parent))
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, path)
        directory = os.open(str(path.parent), os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def check_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(('0.0.0.0', port))
        except OSError as exc:
            raise ValueError('Port {} is already in use; no services were changed.'.format(port)) from exc


class Manager:
    def __init__(self, root=ROOT, binary=XRAY):
        self.root = root
        self.binary = binary
        self.state_path = root / 'state.json'
        self.config_path = root / 'config.json'

    def load(self):
        if not self.state_path.exists():
            raise ValueError('Xray is not configured. Run the Xray setup option first.')
        return json.loads(self.state_path.read_text())

    def validate(self, config):
        fd, name = tempfile.mkstemp(prefix='.validate-', suffix='.json', dir=str(self.root))
        try:
            with os.fdopen(fd, 'wb') as handle:
                handle.write(encoded(config))
            # Do not include generated configuration/credentials in error messages.
            result = subprocess.run([self.binary, 'run', '-test', '-config', name],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
            if result.returncode:
                raise ValueError('Xray rejected the configuration. Check certificate paths and Xray version.')
        finally:
            os.unlink(name)

    def restart(self):
        subprocess.run(['systemctl', 'restart', SERVICE], check=True, timeout=45)
        time.sleep(1)
        subprocess.run(['systemctl', 'is-active', '--quiet', SERVICE], check=True, timeout=10)

    def stop(self):
        subprocess.run(['systemctl', 'stop', SERVICE], check=True, timeout=45)

    def apply(self, state, revoke=False, initialize=False):
        config = render(state)
        config_bytes = encoded(config)
        previous_state = self.state_path.read_bytes() if self.state_path.exists() else None
        previous_config = self.config_path.read_bytes() if self.config_path.exists() else None
        if revoke and config_bytes == previous_config:
            return False
        try:
            self.validate(config)
            # ExecStartPre renders from this atomic state, including boot-time expiry.
            atomic(self.state_path, encoded(state))
            atomic(self.config_path, config_bytes)
            if not initialize:
                self.restart()
        except Exception:
            if revoke:
                # Never roll expired credentials back into a running server.
                self.stop()
            else:
                if previous_state is not None:
                    atomic(self.state_path, previous_state)
                    # The rollback itself must not restore now-expired accounts.
                    atomic(self.config_path, encoded(render(json.loads(previous_state))))
                    try:
                        if not initialize:
                            self.restart()
                    except Exception:
                        self.stop()
                else:
                    self.state_path.unlink(missing_ok=True)
                    self.config_path.unlink(missing_ok=True)
            raise
        return True

    def boot(self):
        # Internal ExecStartPre path: do NOT take the caller's management lock.
        # systemctl restart is synchronous while apply() holds that lock.
        config = render(self.load())
        self.validate(config)
        atomic(self.config_path, encoded(config))


def find_user(state, name):
    for user in state['users']:
        if user['name'] == name:
            return user
    raise ValueError('User not found.')


def show_uris(state, user):
    if not active(user, now_utc()):
        raise ValueError('User is disabled or expired; renew/enable before exporting a URI.')
    matches = [item for item in state['listeners'] if item['protocol'] == user['protocol']]
    if not matches:
        raise ValueError('No listeners for this user protocol. Add a listener first.')
    for item in matches:
        print(uri(state, user, item))


def parser():
    ap = argparse.ArgumentParser(description=__doc__)
    commands = ap.add_subparsers(dest='command', required=True)
    setup = commands.add_parser('init', help='Initialize after SSH ports have been migrated')
    setup.add_argument('--domain', required=True)
    setup.add_argument('--certificate', required=True)
    setup.add_argument('--key', required=True)
    for command in ('users', 'listeners', 'sync', 'render-boot'):
        commands.add_parser(command)
    add = commands.add_parser('add-user')
    add.add_argument('name')
    add.add_argument('protocol', choices=['vless', 'vmess', 'trojan'])
    add.add_argument('--expires', required=True, help='Valid through YYYY-MM-DD (UTC)')
    for command in ('delete-user', 'enable-user', 'disable-user', 'uri', 'renew-user'):
        cmd = commands.add_parser(command)
        cmd.add_argument('name')
        if command == 'renew-user':
            cmd.add_argument('--expires', required=True)
    add = commands.add_parser('add-listener')
    add.add_argument('protocol', choices=['vless', 'vmess', 'trojan'])
    add.add_argument('transport', choices=['ws', 'tcp'])
    add.add_argument('port', type=int)
    add.add_argument('--tls', action='store_true')
    add.add_argument('--path')
    remove = commands.add_parser('delete-listener')
    remove.add_argument('id')
    return ap


def execute(args, manager):
    # Certbot standalone owns port 80 while the pre/post hooks hold this marker.
    # Those hooks take the same management lock, so a timer/account change cannot
    # restart Xray between the stop and the ACME challenge. Boot rendering remains
    # available to the post hook and still filters expired accounts before start.
    if RENEWAL_MARKER.exists() and args.command not in ('users', 'listeners', 'uri'):
        if args.command == 'sync':
            return
        raise ValueError('Certificate renewal is in progress. Retry after it completes.')
    if args.command == 'init':
        if manager.state_path.exists():
            raise ValueError('Already configured; existing users will not be overwritten.')
        domain = hostname(args.domain)
        for path in (args.certificate, args.key):
            if not Path(path).is_absolute() or not Path(path).is_file():
                raise ValueError('Certificate/key must be existing absolute file paths.')
        state = {'version': 1, 'domain': domain, 'certificate': args.certificate,
                 'key': args.key, 'users': [], 'listeners': [listener(*item) for item in DEFAULTS]}
        for item in state['listeners']:
            check_port(item['port'])
        manager.apply(state, initialize=True)
        return
    state = manager.load()
    if args.command == 'sync':
        manager.apply(state, revoke=True)
        return
    if args.command == 'listeners':
        print('ID                        PROTOCOL TRANSPORT PORT  SECURITY PATH')
        for item in state['listeners']:
            print('{id:25} {protocol:8} {transport:9} {port:<5} {security:8} {path}'.format(
                **dict(item, security='TLS' if item['tls'] else 'none',
                       path=item['path'] if item['transport'] == 'ws' else '-')))
        return
    if args.command == 'users':
        print('NAME                     PROTOCOL VALID THROUGH (UTC) STATUS')
        for user in state['users']:
            valid_through = (dt.datetime.fromisoformat(user['expires_at']) - dt.timedelta(days=1)).date()
            status = 'active' if active(user, now_utc()) else ('disabled' if not user['enabled'] else 'expired')
            print('{:24} {:8} {}          {}'.format(user['name'], user['protocol'], valid_through, status))
        return
    if args.command == 'uri':
        show_uris(state, find_user(state, args.name))
        return
    state = copy.deepcopy(state)
    if args.command == 'add-user':
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}', args.name):
            raise ValueError('Name must be 1-32 letters, digits, underscores or hyphens.')
        if any(user['name'] == args.name for user in state['users']):
            raise ValueError('User already exists.')
        if not any(item['protocol'] == args.protocol for item in state['listeners']):
            raise ValueError('Add a listener for this protocol first.')
        credential = secrets.token_urlsafe(32) if args.protocol == 'trojan' else str(uuid.uuid4())
        user = {'name': args.name, 'protocol': args.protocol, 'credential': credential,
                'expires_at': expiry(args.expires), 'enabled': True}
        if not active(user, now_utc()):
            raise ValueError('Expiry must be today or later (UTC).')
        state['users'].append(user)
    elif args.command in ('delete-user', 'renew-user', 'enable-user', 'disable-user'):
        user = find_user(state, args.name)
        if args.command == 'delete-user':
            state['users'].remove(user)
        elif args.command == 'renew-user':
            value = expiry(args.expires)
            if dt.datetime.fromisoformat(value) <= now_utc():
                raise ValueError('Expiry must be today or later (UTC).')
            user['expires_at'] = value
        else:
            user['enabled'] = args.command == 'enable-user'
    elif args.command == 'add-listener':
        item = listener(args.protocol, args.transport, args.port, args.tls, args.path)
        if any(existing['port'] == args.port for existing in state['listeners']):
            raise ValueError('This port already has a listener. Each listener needs a unique port.')
        check_port(args.port)
        state['listeners'].append(item)
    elif args.command == 'delete-listener':
        if not any(item['id'] == args.id for item in state['listeners']):
            raise ValueError('Listener not found.')
        if len(state['listeners']) == 1:
            raise ValueError('Keep at least one listener.')
        state['listeners'] = [item for item in state['listeners'] if item['id'] != args.id]
    manager.apply(state)
    print('Saved and applied. Xray sessions were restarted.')
    if args.command == 'add-user':
        show_uris(state, user)
    if args.command == 'add-listener':
        print('Open TCP port {} in your VPS/provider firewall (e.g. ufw allow {}/tcp).'.format(args.port, args.port))


def main():
    args = parser().parse_args()
    if os.geteuid() != 0:
        print('Run as root (sudo ragnar-xray ...).', file=sys.stderr)
        return 1
    os.umask(0o077)
    manager = Manager()
    try:
        ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
        ROOT.chmod(0o700)
        if args.command == 'render-boot':
            manager.boot()
        else:
            with (ROOT / '.lock').open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                execute(args, manager)
    except (ValueError, OSError, subprocess.SubprocessError, OverflowError, KeyError, TypeError) as exc:
        if args.command == 'sync':
            # Malformed/unreadable state must fail closed too.
            try:
                manager.stop()
            except Exception:
                pass
        print('Xray operation failed: {}'.format(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
