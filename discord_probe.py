"""Unauthenticated Discord application probes. No account data is accessed."""
import base64
import concurrent.futures
import hashlib
from html.parser import HTMLParser
import http.client
import json
import os
import socket
import ssl
import struct
import time
from urllib.parse import urlsplit

APP = 'https://discord.com/app'
API = 'https://discord.com/api/v10/gateway'
WS = 'wss://gateway.discord.gg/?v=10&encoding=json'
CHECKS = ('DiscordApp', 'DiscordScript', 'DiscordAPI', 'DiscordWebSocket')
SCHEMA = 2
GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'


class ProbeError(Exception):
    pass


def remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise TimeoutError('Время проверки истекло')
    return min(5, value)


def fetch(url, limit):
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or parsed.netloc != 'discord.com' or parsed.fragment:
        raise ProbeError('Неподдерживаемый адрес проверки')
    deadline = time.monotonic() + 20
    conn = http.client.HTTPSConnection('discord.com', timeout=5, context=ssl.create_default_context())
    response = None
    try:
        conn.request('GET', parsed.path + ('?' + parsed.query if parsed.query else ''),
                     headers={'User-Agent': 'Mozilla/5.0', 'Accept-Encoding': 'identity',
                              'Connection': 'close'})
        response = conn.getresponse()
        if response.status != 200:
            raise ProbeError(f'HTTP {response.status}')
        length = response.length
        if length is not None and length > limit:
            raise ProbeError('Ответ превышает лимит проверки')
        result = bytearray()
        while True:
            # read1 returns available data, so the deadline also bounds slow streams.
            if conn.sock is not None:
                conn.sock.settimeout(remaining(deadline))
            else:
                remaining(deadline)
            block = response.read1(min(65536, limit + 1 - len(result)))
            if not block:
                break
            result.extend(block)
            if len(result) > limit:
                raise ProbeError('Ответ превышает лимит проверки')
        if length is not None and len(result) != length:
            raise ProbeError(f'Ответ загружен не полностью: {len(result)}/{length} байт')
        return bytes(result), response.getheader('Content-Type', '').split(';')[0].lower()
    finally:
        if response is not None:
            response.close()
        conn.close()


class Scripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []

    def handle_starttag(self, tag, attrs):
        import re
        src = dict(attrs).get('src') or ''
        if tag == 'script' and re.fullmatch(r'/assets/[A-Za-z0-9_.-]+\.js', src):
            self.urls.append('https://discord.com' + src)


def row(name, url, operation, code='200'):
    start = time.monotonic()
    try:
        operation()
    except (OSError, ValueError, http.client.HTTPException, ProbeError) as error:
        return dict(name=name, url=url, http='---', seconds=f'{time.monotonic()-start:.3f}',
                    tls_reached=False, application_ok=False, error=str(error))
    return dict(name=name, url=url, http=code, seconds=f'{time.monotonic()-start:.3f}',
                tls_reached=True, application_ok=True, error='')


def app_checks():
    scripts = Scripts()
    def app():
        data, kind = fetch(APP, 2 * 1024 * 1024)
        text = data.decode('utf-8')
        if kind != 'text/html' or '</html>' not in text.lower():
            raise ProbeError('Неполная HTML-страница приложения')
        scripts.feed(text)
        if not scripts.urls:
            raise ProbeError('Не найден JavaScript приложения')
    page = row(CHECKS[0], APP, app)
    if not page['application_ok']:
        return [page, dict(name=CHECKS[1], url=APP, http='---', seconds='0',
                           tls_reached=False, application_ok=False, error='Сначала нужна страница приложения')]
    script = scripts.urls[0]
    def asset():
        data, kind = fetch(script, 8 * 1024 * 1024)
        if kind not in ('application/javascript', 'text/javascript', 'application/x-javascript') or not data.strip():
            raise ProbeError('Вместо JavaScript получен другой или пустой ответ')
    return [page, row(CHECKS[1], script, asset)]


def api_check():
    data, kind = fetch(API, 65536)
    value = json.loads(data)
    if kind != 'application/json' or not isinstance(value, dict):
        raise ProbeError('API не вернул JSON')
    url = value.get('url')
    if not isinstance(url, str) or url.rstrip('/') != 'wss://gateway.discord.gg':
        raise ProbeError('API не вернул ожидаемый адрес шлюза')


def send_control(sock, opcode, payload):
    if len(payload) > 125:
        raise ProbeError('Слишком большой control frame')
    mask = os.urandom(4)
    sock.sendall(bytes((0x80 | opcode, 0x80 | len(payload))) + mask
                 + bytes(value ^ mask[i % 4] for i, value in enumerate(payload)))


def gateway_hello(sock, key, deadline):
    buffered = bytearray()
    def receive():
        sock.settimeout(remaining(deadline))
        block = sock.recv(4096)
        if not block:
            raise ProbeError('Шлюз закрыл соединение до Hello')
        buffered.extend(block)
    def exact(size):
        while len(buffered) < size:
            receive()
        result = bytes(buffered[:size])
        del buffered[:size]
        return result
    while b'\r\n\r\n' not in buffered:
        if len(buffered) > 16384:
            raise ProbeError('Слишком большой WebSocket handshake')
        receive()
    header, rest = bytes(buffered).split(b'\r\n\r\n', 1)
    if len(header) > 16384:
        raise ProbeError('Слишком большой WebSocket handshake')
    buffered[:] = rest
    lines = header.decode('iso-8859-1').split('\r\n')
    status = lines[0].split()
    if len(status) < 2 or status[:2] != ['HTTP/1.1', '101']:
        raise ProbeError('WebSocket не получил HTTP 101')
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(':')
        if not separator or name.lower() in headers:
            raise ProbeError('Некорректные WebSocket-заголовки')
        headers[name.lower()] = value.strip()
    accept = base64.b64encode(hashlib.sha1((key + GUID).encode('ascii')).digest()).decode('ascii')
    if (headers.get('sec-websocket-accept') != accept or headers.get('upgrade', '').lower() != 'websocket'
            or 'upgrade' not in [v.strip().lower() for v in headers.get('connection', '').split(',')]
            or 'sec-websocket-extensions' in headers or 'sec-websocket-protocol' in headers):
        raise ProbeError('WebSocket handshake не подтверждён')
    message = bytearray()
    started = False
    for _ in range(16):
        a, b = exact(2)
        final, opcode = bool(a & 0x80), a & 15
        if a & 0x70 or b & 0x80:
            raise ProbeError('Некорректный WebSocket frame')
        size = b & 127
        if size == 126:
            size = struct.unpack('!H', exact(2))[0]
        elif size == 127:
            size = struct.unpack('!Q', exact(8))[0]
        if size > 65536 or len(message) + size > 65536:
            raise ProbeError('Слишком большой WebSocket frame')
        if opcode >= 8 and (not final or size > 125):
            raise ProbeError('Некорректный control frame')
        payload = exact(size)
        if opcode == 9:
            send_control(sock, 10, payload)
            continue
        if opcode == 10:
            continue
        if opcode == 8:
            raise ProbeError('WebSocket закрыт до Hello')
        if (opcode == 1 and started) or (opcode == 0 and not started) or opcode not in (0, 1):
            raise ProbeError('Неожиданный WebSocket frame')
        started = True
        message.extend(payload)
        if final:
            value = json.loads(message.decode('utf-8'))
            if not isinstance(value, dict) or value.get('op') != 10 or not isinstance(value.get('d'), dict):
                raise ProbeError('Шлюз не вернул Hello')
            interval = value['d'].get('heartbeat_interval')
            if type(interval) not in (int, float) or not 0 < interval <= 3600000:
                raise ProbeError('Некорректный Hello')
            return
    raise ProbeError('Не получен Hello за допустимое число frames')


def websocket_check():
    deadline = time.monotonic() + 15
    key = base64.b64encode(os.urandom(16)).decode('ascii')
    with socket.create_connection(('gateway.discord.gg', 443), timeout=5) as tcp:
        with ssl.create_default_context().wrap_socket(tcp, server_hostname='gateway.discord.gg') as sock:
            sock.settimeout(remaining(deadline))
            sock.sendall(('GET /?v=10&encoding=json HTTP/1.1\r\nHost: gateway.discord.gg\r\n'
                          'Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n'
                          'Sec-WebSocket-Key: ' + key + '\r\nUser-Agent: Mozilla/5.0\r\n\r\n').encode('ascii'))
            gateway_hello(sock, key, deadline)
            try:
                send_control(sock, 8, struct.pack('!H', 1000))
            except OSError:
                pass


def probes():
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        app = pool.submit(app_checks)
        api = pool.submit(row, CHECKS[2], API, api_check)
        ws = pool.submit(row, CHECKS[3], WS, websocket_check, '101')
        return app.result() + [api.result(), ws.result()]


if __name__ == '__main__':
    print(json.dumps(probes(), ensure_ascii=False))
