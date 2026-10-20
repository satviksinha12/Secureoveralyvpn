#!/usr/bin/env python3
"""Point-to-point Linux TUN VPN; one peer per process."""
import argparse
import errno
import fcntl
import hmac
import ipaddress
import json
import logging
import os
import select
import signal
import socket
import struct
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LOG = logging.getLogger('vpn')
HELLO = b'PYVPN1'
MTU = 1400


def derive(secret, salt, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(secret)


class ReplayWindow:
    def __init__(self):
        self.high = -1
        self.bits = 0

    def acceptable(self, seq):
        return seq > self.high or (self.high - seq < 64 and not self.bits & (1 << (self.high - seq)))

    def commit(self, seq):
        if seq > self.high:
            delta = seq - self.high
            self.bits = ((self.bits << delta) | 1) & ((1 << 64) - 1) if delta < 64 else 1
            self.high = seq
        else:
            self.bits |= 1 << (self.high - seq)


class TunnelCrypto:
    def __init__(self, tx_key, rx_key):
        self.tx = AESGCM(tx_key)
        self.rx = AESGCM(rx_key)
        self.seq = 0
        self.window = ReplayWindow()

    def encrypt(self, packet):
        if self.seq >= 1 << 64:
            raise RuntimeError('Sequence exhausted: restart both peers')
        aad = self.seq.to_bytes(8, 'big')
        nonce = b'\0' * 4 + aad
        self.seq += 1
        return aad + nonce + self.tx.encrypt(nonce, packet, aad)

    def decrypt(self, wire):
        if len(wire) < 36 or len(wire) > MTU + 36:
            return None, 'malformed'
        aad, nonce = wire[:8], wire[8:20]
        seq = int.from_bytes(aad, 'big')
        # Authenticate before changing replay state or classifying a replay.
        try:
            plain = self.rx.decrypt(nonce, wire[20:], aad)
        except InvalidTag:
            return None, 'auth'
        if nonce != b'\0' * 4 + aad:
            return None, 'malformed'
        if not self.window.acceptable(seq):
            return None, 'replay'
        self.window.commit(seq)
        return plain, None


def handshake(sock, psk, mode, timeout, expected_peer_ip=None):
    """PSK-authenticated random contributions give fresh, directional session keys."""
    master = derive(psk.encode(), b'pyvpn-v1-psk', b'authentication')
    role = b'S' if mode == 'server' else b'C'
    other = b'C' if role == b'S' else b'S'
    deadline = time.monotonic() + timeout
    remote = None
    if expected_peer_ip is not None:
        # Learn a NAT-mapped source port only after PSK authentication.
        while time.monotonic() < deadline:
            if not select.select([sock], [], [], 0.1)[0]:
                continue
            packet, endpoint = sock.recvfrom(65535)
            if endpoint[0] != expected_peer_ip:
                continue
            if (len(packet) == 71 and packet[:7] == HELLO + other
                    and hmac.compare_digest(packet[-32:], hmac.digest(master, packet[:-32], 'sha256'))):
                remote = packet[7:39]
                sock.connect(endpoint)
                LOG.info('Authenticated peer endpoint %s:%s', *endpoint)
                break
        else:
            raise TimeoutError('No authenticated client arrived before startup timeout')
    local = os.urandom(32)
    body = HELLO + role + local
    hello = body + hmac.digest(master, body, 'sha256')
    last_send = 0
    while time.monotonic() < deadline:
        if time.monotonic() - last_send >= 0.3:
            sock.send(hello)
            if remote is not None:
                transcript = local + remote if role == b'S' else remote + local
                confirm = b'ACK' + role + hmac.digest(master, b'confirm' + role + transcript, 'sha256')
                sock.send(confirm)
            last_send = time.monotonic()
        if not select.select([sock], [], [], 0.1)[0]:
            continue
        packet = sock.recv(65535)
        if len(packet) == 71 and packet[:7] == HELLO + other:
            if hmac.compare_digest(packet[-32:], hmac.digest(master, packet[:-32], 'sha256')):
                candidate = packet[7:39]
                if remote is None:
                    remote = candidate
        elif remote is not None and len(packet) == 36 and packet[:4] == b'ACK' + other:
            transcript = local + remote if role == b'S' else remote + local
            expected = hmac.digest(master, b'confirm' + other + transcript, 'sha256')
            if hmac.compare_digest(packet[4:], expected):
                # Repeat final confirmation to tolerate loss at the transition.
                for _ in range(5):
                    sock.send(b'ACK' + role + hmac.digest(master, b'confirm' + role + transcript, 'sha256'))
                s2c = derive(master, transcript, b'server-to-client')
                c2s = derive(master, transcript, b'client-to-server')
                return TunnelCrypto(s2c, c2s) if role == b'S' else TunnelCrypto(c2s, s2c)
        else:
            LOG.debug('Ignored unauthenticated startup datagram')
    raise TimeoutError('Authenticated startup timed out; start both peers with the same PSK')


def open_tun(name, address):
    fd = os.open('/dev/net/tun', os.O_RDWR)
    try:
        result = fcntl.ioctl(fd, 0x400454CA, struct.pack('16sH', name.encode(), 0x0001 | 0x1000))
        actual = result[:16].split(b'\0', 1)[0].decode()
        subprocess.run(['ip', 'addr', 'add', address + '/24', 'dev', actual], check=True)
        subprocess.run(['ip', 'link', 'set', 'dev', actual, 'mtu', str(MTU), 'up'], check=True)
        return fd
    except BaseException:
        os.close(fd)
        raise


def dashboard(stats, lock, bind, port):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                data = json.dumps(stats, indent=2).encode()
            if self.path == '/stats':
                content, kind = data, 'application/json'
            elif self.path == '/':
                content = (b'<!doctype html><meta http-equiv="refresh" content="2">'
                           b'<title>VPN stats</title><h1>VPN stats</h1><pre>' + data + b'</pre>')
                kind = 'text/html; charset=utf-8'
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        def log_message(self, *args):
            pass
    http = ThreadingHTTPServer((bind, port), Handler)
    threading.Thread(target=http.serve_forever, daemon=True).start()
    return http


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['server', 'client'], required=True)
    parser.add_argument('--peer-ip', required=True)
    parser.add_argument('--port', type=int, default=5555)
    parser.add_argument('--psk', default=os.environ.get('VPN_PSK'))
    parser.add_argument('--tun', default='tun0')
    parser.add_argument('--dashboard-bind', default='127.0.0.1')
    parser.add_argument('--dashboard-port', type=int, default=5000)
    parser.add_argument('--handshake-timeout', type=float, default=60)
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()
    if not args.psk or len(args.psk.encode()) < 16:
        parser.error('Provide a random PSK of at least 16 bytes using VPN_PSK or --psk')
    if not 1 <= args.port <= 65535 or not 1 <= args.dashboard_port <= 65535:
        parser.error('Ports must be between 1 and 65535')
    ipaddress.IPv4Address(args.peer_ip)
    if not 0 < len(args.tun.encode()) < 16:
        parser.error('TUN name must be 1–15 bytes')
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format='%(asctime)s %(levelname)s %(message)s')
    stats = dict(bytes_sent=0, bytes_received=0, packets_sent=0, packets_received=0,
                 dropped_auth=0, dropped_replay=0, dropped_malformed=0, last_seen=None)
    lock = threading.Lock()
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    tun = None
    http = None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('0.0.0.0', args.port))
            if args.mode == 'client':
                sock.connect((args.peer_ip, args.port))
            # UDP ICMP errors are transient while the other process starts.
            LOG.info('Waiting for authenticated peer %s:%s', args.peer_ip, args.port)
            deadline = time.monotonic() + args.handshake_timeout
            while True:
                try:
                    crypto = handshake(sock, args.psk, args.mode, max(0, deadline - time.monotonic()),
                                       args.peer_ip if args.mode == 'server' else None)
                    break
                except ConnectionRefusedError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError('Peer unavailable')
                    time.sleep(0.1)
            address = '10.8.0.1' if args.mode == 'server' else '10.8.0.2'
            tun = open_tun(args.tun, address)
            http = dashboard(stats, lock, args.dashboard_bind, args.dashboard_port)
            LOG.info('Tunnel ready: %s %s; dashboard %s:%s', args.tun, address,
                     args.dashboard_bind, args.dashboard_port)
            while not stop.is_set():
                ready, _, _ = select.select([tun, sock], [], [], 0.5)
                for source in ready:
                    if source == tun:
                        packet = os.read(tun, MTU)
                        sock.send(crypto.encrypt(packet))
                        with lock:
                            stats['packets_sent'] += 1
                            stats['bytes_sent'] += len(packet)
                    else:
                        wire = sock.recv(65535)
                        if wire.startswith(b'ACK') and len(wire) == 36:
                            continue
                        plain, reason = crypto.decrypt(wire)
                        if reason:
                            with lock:
                                stats['dropped_' + reason] += 1
                            LOG.warning('Dropped packet: %s', reason)
                            continue
                        if not plain or plain[0] >> 4 not in (4, 6):
                            with lock:
                                stats['dropped_malformed'] += 1
                            continue
                        try:
                            written = os.write(tun, plain)
                            if written != len(plain):
                                raise OSError(errno.EINVAL, 'Short TUN write')
                        except OSError as exc:
                            if exc.errno not in (errno.EINVAL, errno.EMSGSIZE):
                                raise
                            with lock:
                                stats['dropped_malformed'] += 1
                            LOG.warning('Dropped invalid IP packet: %s', exc)
                            continue
                        with lock:
                            stats['packets_received'] += 1
                            stats['bytes_received'] += len(plain)
                            stats['last_seen'] = time.time()
    finally:
        if http:
            http.shutdown()
            http.server_close()
        if tun is not None:
            os.close(tun)
        LOG.info('Final stats: %s', stats)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, TimeoutError, subprocess.CalledProcessError) as exc:
        LOG.error('%s', exc)
        raise SystemExit(1)
