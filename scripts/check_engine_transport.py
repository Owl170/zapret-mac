#!/usr/bin/env python3
"""Exercise every TCP strategy with real HTTP/TLS through SOCKS or transparent PF."""
import argparse
import contextlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import zapret as z
from discord_udp import TEST4

BODY = b'ZAPRETMAC_TRANSPORT_OK'
ANCHOR = 'com.apple/zapret-macos-tcp-check'


@contextlib.contextmanager
def local_pf_fixture():
    """Route only reserved TCP probes locally, preserving SOCKS local-IP guards."""
    z.require_mac(True)
    if z.ROOT.exists() and z.is_running():
        raise z.Error('Stop ZapretMac before running the native transport check.')
    if z.pf('-a', ANCHOR, '-sr').stdout.strip() or z.pf('-a', ANCHOR, '-sn').stdout.strip():
        raise z.Error('Native TCP test anchor is already occupied.')
    z.ensure_pf_hooks()
    enabled = z.pf('-E')
    token = re.search(r'Token\s*:\s*(\d+)', enabled.stdout + enabled.stderr)
    if not token:
        raise z.Error('PF enable token missing.')
    failure = None
    try:
        yield
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            z.cleanup_steps(lambda: z.pf('-a', ANCHOR, '-f', '-', input=''),
                            lambda: z.pf('-X', token.group(1)))
        except BaseException as error:
            if failure is None:
                raise
            print('Additional TCP fixture cleanup error: ' + str(error), file=sys.stderr)


def route_endpoint(endpoint, transparent_root=None, secure=False):
    # The official SOCKS engine rejects local destination addresses. Send to a
    # reserved non-local address and let PF translate it to the local server.
    # Keep state only at rdr, so reverse NAT returns the correct peer address.
    rules = (f'rdr pass on lo0 inet proto tcp from !127.0.0.0/8 to {TEST4} '
             f'port {endpoint} -> 127.0.0.1 port {endpoint}\n'
             f'pass out route-to (lo0 127.0.0.1) inet proto tcp from !127.0.0.0/8 '
             f'to {TEST4} port {endpoint} no state label "zmac-tcp-probe"\n')
    if transparent_root is not None:
        # Apply the production generator with its existing state policy.
        # The exclusion table restricts it to TEST4; only the root engine's
        # source-bound backend connection uses this additional test mapping.
        target_port = 443 if secure else 80
        generated = z.pf_rules(dict(z.DEFAULTS, ipv6=False), transparent_root).splitlines()
        tables = [line for line in generated if line.startswith('table ')]
        production = [line for line in generated if not line.startswith('table ')]
        fixture = (f'rdr pass on lo0 inet proto tcp from 127.0.0.1 to {TEST4} '
                   f'port {target_port} -> 127.0.0.1 port {endpoint}')
        backend = (f'pass out route-to (lo0 127.0.0.1) inet proto tcp from 127.0.0.1 '
                   f'to {TEST4} port {target_port} user root no state label "zmac-tcp-backend"')
        rules = '\n'.join(tables + [fixture] + production + [backend]) + '\n'
    z.pf('-n', '-a', ANCHOR, '-f', '-', input=rules)
    z.pf('-a', ANCHOR, '-f', '-', input=rules)


def receive_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise RuntimeError('Unexpected EOF in SOCKS handshake')
        data.extend(chunk)
    return bytes(data)


def exchange_http(client, secure, certificate):
    stream = client
    if secure:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.load_verify_locations(cafile=str(certificate))
        stream = context.wrap_socket(client, server_hostname='www.example.invalid')
    with stream:
        stream.sendall(b'GET /probe HTTP/1.1\r\nHost: www.example.invalid\r\nConnection: close\r\n\r\n')
        received = bytearray()
        while len(received) < 16384:
            chunk = stream.recv(4096)
            if not chunk:
                break
            received.extend(chunk)
        if not bytes(received).endswith(b'\r\n\r\n' + BODY):
            raise RuntimeError('Response did not arrive intact')


def check_case(binary, strategy, options, secure, certificate, key, transparent_root=None):
    errors = []
    with socket.socket() as listener, tempfile.TemporaryFile() as log:
        listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(8)
        endpoint = listener.getsockname()[1]
        route_endpoint(endpoint, transparent_root, secure)
        with socket.socket() as reserved:
            # Previous accepted connections may still be in TIME_WAIT.
            # Match the engine's SO_REUSEADDR while refusing live listeners.
            reserved.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            reserved.bind(('127.0.0.1', 988 if transparent_root else 0))
            proxy_port = reserved.getsockname()[1]

        def server():
            try:
                with listener.accept()[0] as accepted:
                    accepted.settimeout(8)
                    stream = accepted
                    if secure:
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                        context.load_cert_chain(str(certificate), str(key))
                        stream = context.wrap_socket(accepted, server_side=True)
                    with stream:
                        data = bytearray()
                        while b'\r\n\r\n' not in data and len(data) < 16384:
                            chunk = stream.recv(4096)
                            if not chunk:
                                raise RuntimeError('EOF before HTTP request')
                            data.extend(chunk)
                        normalized = bytes(data).lstrip(b'\r\n').lower()
                        if not normalized.startswith(b'get /probe http/1.1\r\n'):
                            raise RuntimeError('HTTP request changed unexpectedly')
                        if b'host: www.example.invalid\r\n' not in normalized:
                            raise RuntimeError('HTTP Host missing')
                        stream.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: ' +
                                       str(len(BODY)).encode() + b'\r\nConnection: close\r\n\r\n' + BODY)
            except BaseException as error:
                errors.append(error)

        worker = threading.Thread(target=server, daemon=True)
        environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                           UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        child = None
        failure = None
        try:
            command = [str(binary), '--socks', '--no-resolve', '--user=root',
                       '--bind-addr=127.0.0.1', '--port=' + str(proxy_port), '--maxconn=32', *options]
            if transparent_root is not None:
                cfg = dict(z.DEFAULTS, strategy=strategy, ipv6=False)
                command = [str(binary)] + z.engine_args(cfg, transparent_root)[1:]
                command += ['--connect-bind-addr=127.0.0.1', '--debug=2']
            child = subprocess.Popen(command, stdout=log, stderr=log, env=environment)
            worker.start()
            if transparent_root is not None:
                z.wait_ready(child)
                command = ['/usr/bin/sudo', '-u', '#' + str(z.original_user().pw_uid), '--',
                           sys.executable, str(Path(__file__).resolve()), '--probe-client',
                           '--certificate', str(certificate)]
                if secure:
                    command.append('--tls')
                result = subprocess.run(command, capture_output=True, text=True, timeout=12)
                if result.returncode:
                    raise RuntimeError('Non-root transparent client failed: ' + (result.stdout + result.stderr)[:8000])
            else:
                check_socks(child, proxy_port, endpoint, secure, certificate)
        except BaseException as error:
            failure = error
        finally:
            diagnostics = ''
            if child is not None:
                try:
                    if child.poll() is None:
                        try:
                            child.terminate()
                        except ProcessLookupError:
                            pass
                    try:
                        child.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        try:
                            child.kill()
                        except ProcessLookupError:
                            pass
                        child.wait(timeout=3)
                except BaseException as error:
                    errors.append(error)
                finally:
                    try:
                        log.seek(0)
                        diagnostics = log.read(65536).decode('utf-8', 'replace')
                    except BaseException as error:
                        errors.append(error)
            try:
                listener.close()
            except BaseException as error:
                errors.append(error)
            if worker.ident is not None:
                worker.join(timeout=9)
        if failure or errors or worker.is_alive() or 'Sanitizer' in diagnostics or 'runtime error:' in diagnostics:
            raise RuntimeError(f'{strategy} {"TLS" if secure else "HTTP"} failed: '
                               f'{failure or errors or "worker/sanitizer failure"}\n{diagnostics}')


def check_socks(child, proxy_port, endpoint, secure, certificate):
    end = time.monotonic() + 8
    while True:
        if child.poll() is not None:
            raise RuntimeError('Engine exited before accepting connections')
        try:
            client = socket.create_connection(('127.0.0.1', proxy_port), timeout=4)
            break
        except ConnectionRefusedError:
            if time.monotonic() >= end:
                raise
            time.sleep(0.05)
    with client:
        client.sendall(b'\x05\x01\x00')
        if receive_exact(client, 2) != b'\x05\x00':
            raise RuntimeError('SOCKS authentication failed')
        client.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(TEST4) + struct.pack('!H', endpoint))
        response = receive_exact(client, 4)
        if response[:3] != b'\x05\x00\x00' or response[3] not in (1, 4):
            raise RuntimeError('SOCKS connection failed: ' + repr(response))
        receive_exact(client, 6 if response[3] == 1 else 18)
        exchange_http(client, secure, certificate)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path, nargs='?')
    parser.add_argument('--transparent', action='store_true', help='Verify non-root PF redirect through the transparent engine.')
    parser.add_argument('--probe-client', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--certificate', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--tls', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if sys.platform != 'darwin':
        raise SystemExit('Run the compiled native-engine check on macOS.')
    if args.probe_client:
        if os.geteuid() == 0 or not args.certificate:
            raise SystemExit('The transparent probe needs a non-root client and a test certificate.')
        with socket.create_connection((TEST4, 443 if args.tls else 80), timeout=5) as client:
            exchange_http(client, args.tls, args.certificate)
        return
    if not args.binary:
        parser.error('binary is required')
    profiles = json.loads((ROOT / 'strategies.json').read_text(encoding='utf-8'))
    with local_pf_fixture(), tempfile.TemporaryDirectory(prefix='zmac-tcp-transport-') as temp:
        certificate, key = Path(temp) / 'cert.pem', Path(temp) / 'key.pem'
        root = Path(temp)
        root.chmod(0o755)
        transparent_root = None
        if args.transparent:
            transparent_root = root
            shutil.copytree(ROOT / 'lists', root / 'lists')
            shutil.copy2(ROOT / 'strategies.json', root / 'strategies.json')
            (root / 'lists/list-general-user.txt').write_text('www.example.invalid\n', encoding='utf-8')
            z.prepare_lists(root)
            # Restrict the unmodified production PF generator to one reserved
            # address. Other traffic and all default exclusions remain outside.
            excluded = ipaddress.ip_network('0.0.0.0/0').address_exclude(ipaddress.ip_network(TEST4 + '/32'))
            (root / 'runtime/excluded4.txt').write_text(''.join(str(n) + '\n' for n in excluded), encoding='utf-8')
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256',
                        '-nodes', '-days', '1', '-keyout', str(key), '-out', str(certificate),
                        '-subj', '/CN=www.example.invalid'], check=True, capture_output=True, timeout=30)
        certificate.chmod(0o644)
        key.chmod(0o600)
        for name, value in profiles.items():
            for secure in (False, True):
                check_case(args.binary.resolve(), name, value['args'], secure, certificate, key, transparent_root)
                print(f'PASS: {name} {"TLS" if secure else "HTTP"} {"transparent PF" if args.transparent else "SOCKS"} transport', flush=True)
    print(f'PASS: {len(profiles) * 2} native {"transparent PF" if args.transparent else "SOCKS"} TCP transport cases')


if __name__ == '__main__':
    main()
