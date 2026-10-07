#!/usr/bin/env python3
"""Experimental local Discord UDP relay. No audio decoding or account access."""
from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import struct
import sys
import time

from zapret import Error, config, ROOT, write_json

UDP_PORT = 989
TEST_PORT = 19294
TEST4 = '198.18.0.254'
TEST6 = '2001:db8::feed'
TEST_PREFIX = b'ZMAC-UDP-PROBE\x00'
NATLOOK_SIZE = 84
DIOCNATLOOK = 0xC0544417  # Darwin _IOWR('D', 23, pfioc_natlook), 84 bytes.
PROFILES = {
    'relay': dict(ttl=0, repeats=0),
    'fake': dict(ttl=0, repeats=6),
    'ttl3': dict(ttl=3, repeats=6),
    'ttl5': dict(ttl=5, repeats=6),
    'ttl7': dict(ttl=7, repeats=6),
    'ttl9': dict(ttl=9, repeats=6),
}


def natlook_buffer(client, local, family, direction=2):
    """ABI mirrors the already bundled tpws macos/net/pfvar.h."""
    raw = bytearray(NATLOOK_SIZE)
    width = 4 if family == socket.AF_INET else 16
    raw[:width] = socket.inet_pton(family, client[0].split('%')[0])
    raw[16:16 + width] = socket.inet_pton(family, local[0].split('%')[0])
    struct.pack_into('!H', raw, 64, client[1])
    struct.pack_into('!H', raw, 68, local[1])
    raw[80:84] = bytes((2 if family == socket.AF_INET else 30, socket.IPPROTO_UDP, 0, direction))
    return raw


def natlook_result(raw, family):
    width = 4 if family == socket.AF_INET else 16
    address = socket.inet_ntop(family, raw[48:48 + width])
    port = struct.unpack_from('!H', raw, 76)[0]
    if not port or ipaddress.ip_address(address).is_unspecified:
        raise Error('PF вернул пустой исходный адрес UDP.')
    return (address, port) if family == socket.AF_INET else (address, port, 0, 0)


class PFResolver:
    def __init__(self):
        if sys.platform != 'darwin':
            raise Error('PF UDP-перехват требует macOS.')
        import fcntl
        self.ioctl = fcntl.ioctl
        self.fd = os.open('/dev/pf', os.O_RDONLY)
        try:
            self.ioctl(self.fd, DIOCNATLOOK, bytearray(NATLOOK_SIZE), True)
        except OSError as error:
            if error.errno != errno.EINVAL:
                self.close()
                raise Error(f'PF NAT lookup ABI недоступен: {error}') from error

    def __call__(self, client, local, family):
        last = None
        for direction in (2, 1):
            raw = natlook_buffer(client, local, family, direction)
            try:
                self.ioctl(self.fd, DIOCNATLOOK, raw, True)
                return natlook_result(raw, family)
            except OSError as error:
                last = error
                # E2BIG means more than one matching PF state. Never guess a destination.
                if error.errno != errno.ENOENT:
                    raise
        raise last

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def classify(data):
    # Discord's current discovery packet: type, length, SSRC, address[64], port.
    if len(data) == 74 and data[:4] == b'\x00\x01\x00\x46' and data[8:] == bytes(66):
        return 'discord-discovery'
    # Older clients use SSRC + empty address + empty port.
    if len(data) == 70 and data[4:] == bytes(66):
        return 'discord-discovery-legacy'
    # Browser/WebRTC STUN. Check both cookie and declared body size.
    if len(data) >= 20 and data[0] & 0xC0 == 0 and data[4:8] == b'\x21\x12\xa4\x42':
        size = struct.unpack_from('!H', data, 2)[0]
        if size % 4 == 0 and len(data) == 20 + size:
            return 'stun'
    return 'other'


def transmit(sock, data, payload, profile, inject):
    """Fakes and real packet use exactly the same socket/NAT mapping."""
    sent = 0
    if inject and profile['repeats']:
        level, option = ((socket.IPPROTO_IP, socket.IP_TTL) if sock.family == socket.AF_INET
                         else (socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS))
        original = sock.getsockopt(level, option) if profile['ttl'] else None
        try:
            if profile['ttl']:
                sock.setsockopt(level, option, profile['ttl'])
            for _ in range(profile['repeats']):
                try:
                    sock.send(payload)
                    sent += 1
                except OSError:
                    # Fake injection is optional; preserve delivery of real data.
                    break
        except OSError:
            pass
        finally:
            if original is not None:
                try:
                    sock.setsockopt(level, option, original)
                except OSError as error:
                    raise Error('Не удалось восстановить обычный TTL; UDP-перехват отключается.') from error
    try:
        sock.send(data)
    except OSError as error:
        if inject and error.errno in (errno.EHOSTUNREACH, errno.ECONNREFUSED):
            # Consume a pending ICMP error from an expired fake and retry once.
            sock.send(data)
        else:
            raise
    return sent


class Relay:
    def __init__(self, resolver, profile='fake', payload=b'', *, status_path=None,
                 probe_token=b'', allow_local_test=False, idle=90, max_sessions=256,
                 exclusions=()):
        self.resolver = resolver
        self.profile = PROFILES[profile]
        self.profile_name = profile
        self.payload = payload
        self.status_path = Path(status_path) if status_path else None
        self.probe_token = probe_token
        self.allow_local_test = allow_local_test
        self.idle = idle
        self.max_sessions = max_sessions
        self.exclusions = [ipaddress.ip_network(item) for item in exclusions]
        self.selector = selectors.DefaultSelector()
        self.listeners = []
        self.sessions = {}
        self.running = True
        self.last_snapshot = 0
        self.lookup_streak = 0
        self.stats = dict(pid=os.getpid(), ready=False, profile=profile,
                          received=0, forwarded=0, replies=0, fakes=0,
                          discoveries=0, stun=0, lookup_errors=0, socket_errors=0,
                          sessions=0, probes4=0, probes6=0, last_error='',
                          last_endpoint='', last_packet='', last_reply_at=0)

    def listen(self, address, family=socket.AF_INET):
        listener = socket.socket(family, socket.SOCK_DGRAM)
        try:
            if family == socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind(address)
            listener.setblocking(False)
            self.selector.register(listener, selectors.EVENT_READ, ('listener', listener))
            self.listeners.append(listener)
            return listener.getsockname()
        except Exception:
            listener.close()
            raise

    def snapshot(self, force=False):
        now = time.monotonic()
        if self.status_path and (force or now - self.last_snapshot >= 1):
            self.stats['sessions'] = len(self.sessions)
            self.stats['updated_at'] = time.time()
            write_json(self.status_path, self.stats)
            self.last_snapshot = now

    def close_session(self, key):
        session = self.sessions.pop(key, None)
        if session:
            self.selector.unregister(session['socket'])
            session['socket'].close()

    def receive_client(self, listener):
        data, client = listener.recvfrom(65535)
        self.stats['received'] += 1
        try:
            destination = self.resolver(client, listener.getsockname(), listener.family)
            self.lookup_streak = 0
        except (OSError, Error) as error:
            self.stats['lookup_errors'] += 1
            self.lookup_streak += 1
            self.stats['last_error'] = 'NAT lookup: ' + str(error)
            if self.lookup_streak >= 3 or getattr(error, 'errno', None) == errno.E2BIG:
                raise Error('PF не восстанавливает адрес UDP; перехват будет отключён.') from error
            return
        if destination[0] in (TEST4, TEST6) and destination[1] == TEST_PORT:
            # Reserved destinations; probe is answered locally and is never relayed.
            if self.probe_token and data == TEST_PREFIX + self.probe_token:
                listener.sendto(data, client)
                self.stats['probes4' if listener.family == socket.AF_INET else 'probes6'] += 1
            return
        address = ipaddress.ip_address(destination[0].split('%')[0])
        if (not self.allow_local_test and not address.is_global) or any(address in n for n in self.exclusions if n.version == address.version):
            self.stats['last_error'] = 'Исключённый исходный адрес UDP: ' + str(destination[0])
            return
        if destination[0] == listener.getsockname()[0] and destination[1] == listener.getsockname()[1]:
            raise Error('PF вернул адрес самого relay; возможна рекурсия.')
        # Looking up each packet detects endpoint changes instead of silently reusing a stale mapping.
        key = (listener.fileno(), client)
        session = self.sessions.get(key)
        if session and session['destination'] != destination:
            self.close_session(key)
            session = None
        if not session:
            if len(self.sessions) >= self.max_sessions:
                self.close_session(min(self.sessions, key=lambda k: self.sessions[k]['last']))
            upstream = socket.socket(listener.family, socket.SOCK_DGRAM)
            try:
                upstream.connect(destination)
                upstream.setblocking(False)
                session = dict(socket=upstream, listener=listener, client=client,
                               destination=destination, last=time.monotonic(),
                               injections=0, last_injection=0)
                self.selector.register(upstream, selectors.EVENT_READ, ('upstream', key))
                self.sessions[key] = session
            except Exception:
                upstream.close()
                raise
        kind = classify(data)
        now = time.monotonic()
        inject = kind != 'other' and session['injections'] < 2 and now - session['last_injection'] >= 1
        self.stats['last_packet'] = kind
        self.stats['last_endpoint'] = f'{destination[0]}:{destination[1]}'
        if kind.startswith('discord-discovery'):
            self.stats['discoveries'] += 1
        if kind == 'stun':
            self.stats['stun'] += 1
        self.stats['fakes'] += transmit(session['socket'], data, self.payload, self.profile, inject)
        self.stats['forwarded'] += 1
        session['last'] = now
        if inject:
            session['injections'] += 1
            session['last_injection'] = now

    def receive_upstream(self, key):
        session = self.sessions.get(key)
        if not session:
            return
        try:
            data = session['socket'].recv(65535)
        except OSError as error:
            # A pending ICMP after a low-TTL fake is not a closed UDP connection.
            self.stats['socket_errors'] += 1
            self.stats['last_error'] = str(error)
            return
        session['listener'].sendto(data, session['client'])
        session['last'] = time.monotonic()
        self.stats['replies'] += 1
        self.stats['last_reply_at'] = time.time()

    def step(self, timeout=0.25):
        for key, _ in self.selector.select(timeout):
            kind, value = key.data
            try:
                if kind == 'listener':
                    self.receive_client(value)
                else:
                    self.receive_upstream(value)
            except BlockingIOError:
                continue
            except OSError as error:
                self.stats['socket_errors'] += 1
                self.stats['last_error'] = str(error)
        now = time.monotonic()
        for key in list(self.sessions):
            if now - self.sessions[key]['last'] > self.idle:
                self.close_session(key)
        self.snapshot()

    def serve(self):
        self.stats['ready'] = True
        self.snapshot(True)
        try:
            while self.running:
                self.step()
        finally:
            self.stats['ready'] = False
            self.snapshot(True)
            self.close()

    def close(self):
        for key in list(self.sessions):
            self.close_session(key)
        for listener in self.listeners:
            self.selector.unregister(listener)
            listener.close()
        self.listeners.clear()
        self.selector.close()


def probe(address, token, timeout=3):
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    packet = TEST_PREFIX + bytes.fromhex(token)
    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.settimeout(timeout)
        client.connect((address, TEST_PORT))
        client.send(packet)
        response = client.recv(4096)
        if response != packet:
            raise Error('UDP-самопроверка получила неправильный ответ.')
    print('UDP PF loop verified:', address)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['serve', 'probe', 'abi'])
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--address', default=TEST4)
    parser.add_argument('--token', default='')
    args = parser.parse_args()
    if args.command == 'abi':
        print(json.dumps(dict(size=NATLOOK_SIZE, request=DIOCNATLOOK, sport=64, dport=68, rdport=76, af=80)))
        return
    if args.command == 'probe':
        probe(args.address, args.token)
        return
    cfg = config(args.root)
    payload = (args.root / 'payloads' / 'discord-fake.bin').read_bytes()
    if not 1 <= len(payload) <= 1400:
        raise Error('UDP-фейк должен иметь размер 1…1400 байт.')
    probe_settings = json.loads((args.root / 'runtime' / 'udp-probe.json').read_text())
    resolver = PFResolver()
    from zapret import load_entries
    relay = Relay(resolver, cfg['voice_profile'], payload,
                  probe_token=bytes.fromhex(probe_settings['token']),
                  status_path=args.root / 'runtime' / 'udp-status.json',
                  exclusions=load_entries(args.root / 'runtime/excluded_ips.txt', 'ip'))
    try:
        relay.listen(('127.0.0.1', UDP_PORT))
        if cfg['ipv6']:
            import zapret
            found = __import__('re').search(r'inet6\s+(fe80:[0-9a-f:]+)', zapret.run(['/sbin/ifconfig', 'lo0']).stdout)
            if not found:
                raise Error('IPv6 lo0 недоступен для UDP-relay.')
            relay.listen((found.group(1), UDP_PORT, 0, socket.if_nametoindex('lo0')), socket.AF_INET6)
        def stop_signal(signum, frame):
            relay.running = False
        signal.signal(signal.SIGTERM, stop_signal)
        signal.signal(signal.SIGINT, stop_signal)
        relay.serve()
    finally:
        relay.close()
        resolver.close()


if __name__ == '__main__':
    try:
        main()
    except (Error, OSError, ValueError) as error:
        print('UDP relay error:', error, file=sys.stderr, flush=True)
        sys.exit(1)
