#!/usr/bin/env python3
"""Exercise every TCP strategy with real HTTP and TLS through a local SOCKS proxy."""
import argparse
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BODY = b'ZAPRETMAC_TRANSPORT_OK'


def receive_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise RuntimeError('Unexpected EOF in SOCKS handshake')
        data.extend(chunk)
    return bytes(data)


def check_case(binary, strategy, options, secure, certificate, key):
    errors = []
    with socket.socket() as listener, tempfile.TemporaryFile() as log:
        listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(8)
        endpoint = listener.getsockname()[1]
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
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
        worker.start()
        environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=0:abort_on_error=1',
                           UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        child = None
        failure = None
        try:
            child = subprocess.Popen([str(binary), '--socks', '--no-resolve',
                                      '--bind-addr=127.0.0.1', '--port=' + str(proxy_port),
                                      '--maxconn=32', *options], stdout=log, stderr=log, env=environment)
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
                client.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + struct.pack('!H', endpoint))
                response = receive_exact(client, 4)
                if response[:3] != b'\x05\x00\x00' or response[3] not in (1, 4):
                    raise RuntimeError('SOCKS connection failed: ' + repr(response))
                receive_exact(client, 6 if response[3] == 1 else 18)
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
            worker.join(timeout=9)
        if failure or errors or worker.is_alive() or 'Sanitizer' in diagnostics or 'runtime error:' in diagnostics:
            raise RuntimeError(f'{strategy} {"TLS" if secure else "HTTP"} failed: '
                               f'{failure or errors or "worker/sanitizer failure"}\n{diagnostics}')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    args = parser.parse_args(argv)
    if sys.platform != 'darwin':
        raise SystemExit('Run the compiled native-engine check on macOS.')
    profiles = json.loads((ROOT / 'strategies.json').read_text(encoding='utf-8'))
    with tempfile.TemporaryDirectory(prefix='zmac-tcp-transport-') as temp:
        certificate, key = Path(temp) / 'cert.pem', Path(temp) / 'key.pem'
        subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256',
                        '-nodes', '-days', '1', '-keyout', str(key), '-out', str(certificate),
                        '-subj', '/CN=www.example.invalid'], check=True, capture_output=True, timeout=30)
        for name, value in profiles.items():
            for secure in (False, True):
                check_case(args.binary.resolve(), name, value['args'], secure, certificate, key)
                print(f'PASS: {name} {"TLS" if secure else "HTTP"} local transport', flush=True)
    print(f'PASS: {len(profiles) * 2} native TCP transport cases')


if __name__ == '__main__':
    main()
