import base64
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import struct
import subprocess
import threading
import time
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import discord_probe as d
import zapret as z

KEY = 'dGhlIHNhbXBsZSBub25jZQ=='
HEADER = (b'HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n'
          b'Connection: keep-alive, Upgrade\r\n'
          b'Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n')
HELLO = b'{"op":10,"d":{"heartbeat_interval":45000}}'


def frame(payload, opcode=1, final=True):
    size = len(payload)
    head = bytes(((0x80 if final else 0) | opcode,))
    if size < 126:
        return head + bytes((size,)) + payload
    return head + b'\x7e' + struct.pack('!H', size) + payload


class SocketFixture:
    def __init__(self, data, chunk=4096):
        self.stream = io.BytesIO(data)
        self.chunk = chunk
        self.sent = bytearray()
    def settimeout(self, value):
        self.timeout = value
    def recv(self, size):
        return self.stream.read(min(size, self.chunk))
    def sendall(self, data):
        self.sent.extend(data)


class GatewayTests(unittest.TestCase):
    def check(self, data, chunk=4096):
        sock = SocketFixture(data, chunk)
        d.gateway_hello(sock, KEY, time.monotonic() + 5)
        return sock

    def test_valid_handshake_and_hello_in_one_read(self):
        self.check(HEADER + frame(HELLO))

    def test_split_tcp_reads_and_fragmented_hello(self):
        self.check(HEADER + frame(HELLO[:20], final=False) + frame(HELLO[20:], opcode=0), chunk=3)

    def test_ping_between_fragments_gets_masked_pong(self):
        sock = self.check(HEADER + frame(HELLO[:20], final=False) + frame(b'ping', opcode=9)
                          + frame(HELLO[20:], opcode=0))
        self.assertEqual(sock.sent[:2], b'\x8a\x84')
        mask = sock.sent[2:6]
        self.assertEqual(bytes(v ^ mask[i % 4] for i, v in enumerate(sock.sent[6:])), b'ping')

    def test_http_404_or_wrong_accept_cannot_confirm_gateway(self):
        for header in (HEADER.replace(b'101', b'404'), HEADER.replace(b's3pPL', b'wrong'),
                       HEADER.replace(b'\r\n\r\n', b'\r\nSec-WebSocket-Accept: duplicate\r\n\r\n')):
            with self.subTest(header=header), self.assertRaises(d.ProbeError):
                self.check(header + frame(HELLO))

    def test_invalid_frames_refuse_before_allocating_large_payload(self):
        for data in (b'\x81\xff' + struct.pack('!Q', 2**40), b'\xc1\x00', b'\x81\x80',
                     frame(b'', opcode=0), frame(b'x', opcode=9, final=False)):
            with self.subTest(data=data), self.assertRaises(d.ProbeError):
                self.check(HEADER + data)

    def test_wrong_event_or_heartbeat_cannot_confirm_hello(self):
        for value in ([10], {'op': 11}, {'op': 10, 'd': {'heartbeat_interval': 0}},
                      {'op': 10, 'd': {'heartbeat_interval': True}}):
            with self.subTest(value=value), self.assertRaises(d.ProbeError):
                self.check(HEADER + frame(json.dumps(value).encode()))

    def test_truncated_or_closed_gateway_fails(self):
        for data in (HEADER + frame(HELLO)[:-3], HEADER + frame(b'\x03\xe8', opcode=8)):
            with self.subTest(data=data), self.assertRaises(d.ProbeError):
                self.check(data)

    def test_expired_deadline_fails_even_with_buffered_data(self):
        with self.assertRaises(TimeoutError):
            d.gateway_hello(SocketFixture(HEADER + frame(HELLO)), KEY, time.monotonic() - 1)

    def test_header_and_frame_count_are_bounded(self):
        for data in (b'A' * 20000, HEADER + frame(b'x', opcode=9) * 17):
            with self.subTest(size=len(data)), self.assertRaises(d.ProbeError):
                self.check(data)


class HttpTests(unittest.TestCase):
    def setUp(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.server.requests.append((self.path, self.headers.get('Range')))
                status = 200
                binary = self.path.endswith(('Discord.zip', 'full.distro'))
                if self.path.startswith('/api/updates/stable'):
                    body = json.dumps(self.server.legacy).encode()
                    kind = 'application/json'
                elif self.path.startswith('/distributions/app/manifests/latest'):
                    body = json.dumps(self.server.modern).encode()
                    kind = 'application/json'
                elif binary:
                    body = b'X' * (512 if self.server.mode == 'short-range' else 1024)
                    kind = 'text/html' if self.server.mode == 'binary-html' else 'application/octet-stream'
                    status = 200 if self.server.mode == 'ignore-range' else 206
                elif self.path == '/api/v10/gateway':
                    body = json.dumps({'url': self.server.gateway}).encode()
                    kind = 'application/json'
                elif self.path.endswith('.js'):
                    body = b'window.test = 1;'
                    kind = 'text/html' if self.server.mode == 'bad-script' else 'application/javascript'
                else:
                    body = b'<html><script src="/assets/test.js"></script></html>'
                    kind = 'text/html'
                self.send_response(status)
                self.send_header('Content-Type', kind)
                length = len(body) + (100 if self.server.mode == 'partial' else 0)
                if binary:
                    length = 1024
                    self.send_header('Content-Range', 'bytes 1-1024/9999' if self.server.mode == 'wrong-range'
                                     else 'bytes 0-1023/9999')
                self.send_header('Content-Length', str(length))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *args):
                pass
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.mode = 'good'
        self.server.gateway = 'wss://gateway.discord.gg/'
        self.server.requests = []
        self.server.legacy = dict(name='0.0.1', url=f'https://{d.UPDATE_HOST}/apps/osx/0.0.1/Discord.zip')
        self.server.modern = dict(full=dict(host_version=[0, 0, 1], package_sha256='a' * 64,
                                          url=f'https://{d.UPDATE_HOST}/distro/app/stable/osx/universal/0.0.1/full.distro'))
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True)
        self.thread.start()
        self.addCleanup(self.close)
        self.patch = patch.object(d.http.client, 'HTTPSConnection', side_effect=lambda *a, **k:
                                 http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=1))
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def test_app_and_script_require_completed_real_http_transfers(self):
        self.assertTrue(all(r['application_ok'] for r in d.app_checks()))
        self.server.mode = 'partial'
        self.assertFalse(d.app_checks()[0]['application_ok'])

    def test_html_instead_of_script_is_rejected(self):
        self.server.mode = 'bad-script'
        self.assertFalse(d.app_checks()[1]['application_ok'])

    def test_response_size_is_bounded(self):
        with self.assertRaises(d.ProbeError):
            d.fetch(d.APP, 10)

    def test_api_validates_public_gateway_url(self):
        d.api_check()
        self.server.gateway = 'wss://outside.invalid/private'
        with self.assertRaises(d.ProbeError):
            d.api_check()

    def test_assets_and_requests_cannot_follow_external_urls(self):
        parser = d.Scripts()
        parser.feed('<script src="https://outside.invalid/test.js"></script><script src>'
                    '<script src="/assets/../private.js"></script><script src="/assets/test.js"></script>')
        self.assertEqual(parser.urls, ['https://discord.com/assets/test.js'])
        with self.assertRaises(d.ProbeError):
            d.fetch('https://outside.invalid', 10)

    def test_real_update_metadata_and_both_range_downloads_pass(self):
        rows = d.update_checks()
        self.assertTrue(all(r['application_ok'] for r in rows))
        self.assertEqual(rows[-1]['http'], '206')
        binary = [r for r in self.server.requests if r[0].endswith(('Discord.zip', 'full.distro'))]
        self.assertEqual(len(binary), 2)
        self.assertTrue(all(r[1] == 'bytes=0-1023' for r in binary))

    def test_missing_or_bad_update_metadata_prevents_download(self):
        for value in ([], {'name': '0.0.1'}, {'name': '../private', 'url': 'https://outside.invalid'}):
            with self.subTest(value=value):
                self.server.legacy = value
                rows = d.update_checks()
                self.assertFalse(rows[0]['application_ok'])
                self.assertFalse(rows[-1]['application_ok'])
        self.assertFalse(any(r[1] for r in self.server.requests))

    def test_update_urls_cannot_redirect_to_arbitrary_hosts_or_paths(self):
        original = self.server.legacy['url']
        for url in ('http://' + d.UPDATE_HOST + '/apps/osx/0.0.1/Discord.zip',
                    original + '?token=anything', original.replace(d.UPDATE_HOST, 'outside.invalid'),
                    original.replace('/0.0.1/', '/0.0.2/'), original.replace('Discord.zip', '../private')):
            with self.subTest(url=url):
                self.server.legacy['url'] = url
                self.assertFalse(d.update_checks()[0]['application_ok'])
        self.server.legacy['url'] = original
        self.server.modern['full']['url'] = 'https://127.0.0.1/private'
        self.assertFalse(d.update_checks()[1]['application_ok'])
        self.assertFalse(any(r[1] for r in self.server.requests))

    def test_update_manifest_requires_bounded_numeric_version_and_sha256(self):
        original = self.server.modern['full'].copy()
        for version, digest in (([0, 0, True], 'a' * 64), ([0, 0, -1], 'a' * 64),
                                ([0, 0, 1000001], 'a' * 64), ('0.0.1', 'a' * 64),
                                ([0, 0, 1], 'invalid')):
            with self.subTest(version=version, digest=digest):
                self.server.modern['full'] = dict(original, host_version=version, package_sha256=digest)
                self.assertFalse(d.update_checks()[1]['application_ok'])

    def test_update_download_rejects_truncation_wrong_range_html_or_ignored_range(self):
        for mode in ('short-range', 'wrong-range', 'binary-html', 'ignore-range'):
            with self.subTest(mode=mode):
                self.server.mode = mode
                rows = d.update_checks()
                self.assertTrue(all(r['application_ok'] for r in rows[:2]))
                self.assertFalse(rows[-1]['application_ok'])

    def test_binary_host_is_not_permitted_for_unbounded_metadata_requests(self):
        with self.assertRaises(d.ProbeError):
            d.fetch(self.server.legacy['url'], 1024)


class ControllerProbeTests(unittest.TestCase):
    def test_family_diagnostics_use_user_requests_and_preserve_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            hosts = root / 'hosts'
            original = '127.0.0.1 localhost\n203.0.113.5 discord.com updates.discord.com\n'
            hosts.write_text(original)
            rows = [dict(name='DiscordMain', url=d.APP, tls_reached=False, error='timeout')]
            with patch.object(z, 'HOSTS', hosts), patch.object(z.os, 'geteuid', return_value=0, create=True), \
                    patch.object(z, 'original_user', return_value=SimpleNamespace(pw_uid=501)), \
                    patch.object(z, 'run', return_value=SimpleNamespace(returncode=0, stdout='200 0.1', stderr='')) as run:
                z.connection_details(root, rows)
            commands = [call.args[0] for call in run.call_args_list]
            self.assertEqual(len(commands), 2)
            self.assertTrue(all(cmd[:4] == ['/usr/bin/sudo', '-u', '#501', '--'] for cmd in commands))
            self.assertTrue(any('--ipv4' in cmd for cmd in commands))
            self.assertTrue(any('--ipv6' in cmd for cmd in commands))
            report = json.loads(next((root / 'logs').glob('connection-*.json')).read_text())
            self.assertEqual(report['discord_hosts'], ['203.0.113.5 discord.com updates.discord.com'])
            self.assertEqual(hosts.read_text(), original)

    def test_healthy_targets_do_not_trigger_additional_network_requests(self):
        with patch.object(z, 'run') as run:
            z.connection_details(Path('.'), [dict(name='DiscordMain', tls_reached=True)])
        run.assert_not_called()

    def test_probes_run_as_invoking_user_so_pf_can_intercept_them(self):
        rows = [dict(name=n, url='', http='200', seconds='0', error='', tls_reached=True, application_ok=True) for n in d.CHECKS]
        with patch.object(z.os, 'geteuid', return_value=0, create=True), \
                patch.object(z, 'original_user', return_value=SimpleNamespace(pw_uid=501)), \
                patch.object(z, 'run', return_value=SimpleNamespace(returncode=0, stdout=json.dumps(rows))) as run:
            self.assertEqual(z.discord_tests(), rows)
        self.assertEqual(run.call_args.args[0][:4], ['/usr/bin/sudo', '-u', '#501', '--'])

    def test_probe_process_timeout_and_malformed_result_fail_all_stages(self):
        for error in (subprocess.TimeoutExpired('probe', 60),
                      SimpleNamespace(returncode=0, stdout='{}'),
                      SimpleNamespace(returncode=0, stdout=json.dumps([{'name':n} for n in d.CHECKS]))):
            arguments = {'side_effect': error} if isinstance(error, Exception) else {'return_value':error}
            with self.subTest(error=error), patch.object(z.os, 'geteuid', return_value=501, create=True), \
                    patch.object(z, 'run', **arguments):
                self.assertFalse(any(r['application_ok'] for r in z.discord_tests()))


if __name__ == '__main__':
    unittest.main()
