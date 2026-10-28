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
import sqlite3
import stat
import hashlib
import signal
import socket
import struct
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from internet import InternetRouting

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

LOG = logging.getLogger('vpn')
HELLO = b'PYVPN2'
MTU = 1400


def derive(secret, salt, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(secret)


class SessionStore:
    """Durable counter reservations and replay state; never restore old backups."""
    def __init__(self, path, identity):
        parent = os.stat(os.path.dirname(os.path.abspath(path)))
        if parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
            raise ValueError('State directory must belong to the process user with mode 0700')
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
        self.fd = os.open(path, flags, 0o600)
        try:
            info = os.fstat(self.fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise ValueError('State must be a private, owner-only regular file')
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.db = sqlite3.connect(path)
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('CREATE TABLE IF NOT EXISTS config (name TEXT PRIMARY KEY, value TEXT)')
            self.db.execute('CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, tx TEXT, high TEXT, bits TEXT)')
            with self.db:
                row = self.db.execute("SELECT value FROM config WHERE name='identity'").fetchone()
                if row and row[0] != identity:
                    raise ValueError('State belongs to another mode, peer, or PSK; use a new state file')
                self.db.execute("INSERT OR IGNORE INTO config VALUES ('identity', ?)", (identity,))
                self.db.execute("INSERT OR IGNORE INTO config VALUES ('seed', ?)", (os.urandom(32).hex(),))
            self.seed = bytes.fromhex(self.db.execute("SELECT value FROM config WHERE name='seed'").fetchone()[0])
            if len(self.seed) != 32:
                raise ValueError('Invalid saved session seed; state is corrupt')
        except BaseException:
            if hasattr(self, 'db'):
                self.db.close()
            os.close(self.fd)
            raise

    def load(self, session):
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO sessions VALUES (?, '0', '-1', '0')", (session,))
        row = self.db.execute('SELECT tx, high, bits FROM sessions WHERE id=?', (session,)).fetchone()
        tx, high, bits = map(int, row)
        if not (0 <= tx <= 1 << 64 and -1 <= high < 1 << 64 and 0 <= bits < 1 << 64):
            raise ValueError('Invalid saved counters; refusing to reuse session keys')
        return tx, high, bits

    def reserve(self, session, limit):
        with self.db:
            self.db.execute('UPDATE sessions SET tx=? WHERE id=?', (str(limit), session))

    def receive(self, session, window):
        with self.db:
            self.db.execute('UPDATE sessions SET high=?, bits=? WHERE id=?',
                            (str(window.high), str(window.bits), session))

    def close(self):
        self.db.close()
        os.close(self.fd)


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
    def __init__(self, tx_key, rx_key, store=None):
        self.tx = AESGCM(tx_key)
        self.rx = AESGCM(rx_key)
        self.seq = 0
        self.window = ReplayWindow()
        self.store = store
        self.session = hashlib.sha256(tx_key + rx_key).hexdigest()
        self.limit = 0
        if store:
            self.seq, self.window.high, self.window.bits = store.load(self.session)
            self.limit = self.seq

    def encrypt(self, packet):
        if self.seq >= 1 << 64:
            raise RuntimeError('Sequence exhausted: restart both peers')
        if self.store and self.seq >= self.limit:
            # Commit a block before emitting any nonce in it; crashes skip unused values.
            self.limit = min(self.seq + 4096, 1 << 64)
            self.store.reserve(self.session, self.limit)
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
        if self.store:
            # Commit before delivery, including heartbeats, to reject replay after restart.
            self.store.receive(self.session, self.window)
        return plain, None


def handshake(sock, psk, mode, timeout, expected_peer_ip=None, store=None, stop=None):
    """Fresh authenticated challenges; optional stable seeds retain traffic keys."""
    master = derive(psk.encode(), b'pyvpn-v2-psk', b'authentication')
    role = b'S' if mode == 'server' else b'C'
    other = b'C' if role == b'S' else b'S'
    local = (store.seed if store else os.urandom(32)) + os.urandom(32)
    body = HELLO + role + local
    hello = body + hmac.digest(master, body, 'sha256')
    deadline = time.monotonic() + timeout
    remote = None
    endpoint = None
    last_send = 0
    while time.monotonic() < deadline:
        if stop and stop.is_set():
            raise InterruptedError('Shutdown requested')
        if time.monotonic() - last_send >= 0.3:
            if expected_peer_ip is None or endpoint is not None:
                if expected_peer_ip is None:
                    sock.send(hello)
                else:
                    sock.sendto(hello, endpoint)
                if remote is not None:
                    transcript = local + remote if role == b'S' else remote + local
                    confirm = b'ACK' + role + hmac.digest(master, b'confirm' + role + transcript, 'sha256')
                    if expected_peer_ip is None:
                        sock.send(confirm)
                    else:
                        sock.sendto(confirm, endpoint)
            last_send = time.monotonic()
        if not select.select([sock], [], [], 0.1)[0]:
            continue
        packet, sender = sock.recvfrom(65535)
        if expected_peer_ip is not None and sender[0] != expected_peer_ip:
            continue
        if len(packet) == 103 and packet[:7] == HELLO + other:
            if hmac.compare_digest(packet[-32:], hmac.digest(master, packet[:-32], 'sha256')):
                candidate = packet[7:71]
                if remote is None:
                    remote, endpoint = candidate, sender
                    last_send = 0
        elif remote is not None and len(packet) == 36 and packet[:4] == b'ACK' + other:
            if expected_peer_ip is not None and sender != endpoint:
                continue
            transcript = local + remote if role == b'S' else remote + local
            expected = hmac.digest(master, b'confirm' + other + transcript, 'sha256')
            if hmac.compare_digest(packet[4:], expected):
                if expected_peer_ip is not None:
                    sock.connect(endpoint)
                    LOG.info('Authenticated peer endpoint %s:%s', *endpoint)
                confirm = b'ACK' + role + hmac.digest(master, b'confirm' + role + transcript, 'sha256')
                for _ in range(5):
                    sock.send(confirm)
                seeds = transcript[:32] + transcript[64:96]
                s2c = derive(master, seeds, b'server-to-client')
                c2s = derive(master, seeds, b'client-to-server')
                crypto = TunnelCrypto(s2c, c2s, store) if role == b'S' else TunnelCrypto(c2s, s2c, store)
                crypto.remote_hello = HELLO + other + remote + hmac.digest(master, HELLO + other + remote, 'sha256')
                crypto.local_hello = hello
                crypto.confirm = confirm
                return crypto
    raise TimeoutError('Authenticated startup timed out')


TRANSIENT = {errno.ECONNREFUSED, errno.ENETUNREACH, errno.EHOSTUNREACH,
             errno.ENETDOWN, errno.EHOSTDOWN, errno.ECONNRESET}


def connect_session(args, stop, store):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('0.0.0.0', args.port))
        if args.mode == 'client':
            sock.connect((args.peer_ip, args.port))
        crypto = handshake(sock, args.psk, args.mode, args.handshake_timeout,
                           args.peer_ip if args.mode == 'server' else None, store, stop)
        return sock, crypto
    except BaseException:
        sock.close()
        raise


def forward(tun, sock, crypto, stats, lock, stop, args):
    last_rx = last_tx = time.monotonic()
    while not stop.is_set():
        now = time.monotonic()
        if now - last_rx >= args.peer_timeout:
            raise TimeoutError('No authenticated packets from peer')
        if now - last_tx >= args.keepalive:
            sock.send(crypto.encrypt(b''))
            last_tx = now
        ready, _, _ = select.select([tun, sock], [], [], 0.2)
        for source in ready:
            if source == tun:
                packet = os.read(tun, MTU)
                sock.send(crypto.encrypt(packet))
                last_tx = time.monotonic()
                with lock:
                    stats['packets_sent'] += 1
                    stats['bytes_sent'] += len(packet)
            else:
                wire = sock.recv(65535)
                # Finish a handshake if its final confirmation was lost.
                if wire == crypto.remote_hello:
                    sock.send(crypto.local_hello)
                    sock.send(crypto.confirm)
                    continue
                if wire.startswith(HELLO) or (len(wire) == 36 and wire.startswith(b'ACK')):
                    continue
                plain, reason = crypto.decrypt(wire)
                if reason:
                    with lock:
                        stats['dropped_' + reason] += 1
                    LOG.warning('Dropped packet: %s', reason)
                    continue
                last_rx = time.monotonic()
                with lock:
                    stats['last_seen'] = time.time()
                if plain == b'':
                    continue  # Authenticated keepalive, not a TUN packet.
                if plain[0] >> 4 not in (4, 6):
                    with lock:
                        stats['dropped_malformed'] += 1
                    continue
                try:
                    if os.write(tun, plain) != len(plain):
                        raise OSError(errno.EINVAL, 'Short TUN write')
                except OSError as exc:
                    if exc.errno not in (errno.EINVAL, errno.EMSGSIZE):
                        raise
                    with lock:
                        stats['dropped_malformed'] += 1
                    continue
                with lock:
                    stats['packets_received'] += 1
                    stats['bytes_received'] += len(plain)


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
    parser.add_argument('--state-file', help='Private SQLite session state; use a distinct local path per endpoint')
    parser.add_argument('--reconnect-delay', type=float, default=2)
    parser.add_argument('--keepalive', type=float, default=5)
    parser.add_argument('--peer-timeout', type=float, default=20)
    parser.add_argument('--internet', action='store_true', help='Enable IPv4 internet gateway (server) or split-default routes (client)')
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()
    if not args.psk or len(args.psk.encode()) < 16:
        parser.error('Provide a random PSK of at least 16 bytes using VPN_PSK or --psk')
    if not 1 <= args.port <= 65535 or not 1 <= args.dashboard_port <= 65535:
        parser.error('Ports must be between 1 and 65535')
    if (args.handshake_timeout <= 0 or args.reconnect_delay <= 0 or args.keepalive <= 0
            or args.peer_timeout <= args.keepalive):
        parser.error('Timeout/delay values must be positive; peer timeout must exceed keepalive')
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
    tun = http = store = None
    routing = InternetRouting(args.mode, args.peer_ip, args.tun) if args.internet else None
    try:
        if args.state_file:
            identity = hashlib.sha256((args.mode + ':' + args.peer_ip + ':' + args.psk).encode()).hexdigest()
            store = SessionStore(args.state_file, identity)
        address = '10.8.0.1' if args.mode == 'server' else '10.8.0.2'
        tun = open_tun(args.tun, address)
        with lock:
            stats.update(connection_state='connecting', reconnects=0)
        http = dashboard(stats, lock, args.dashboard_bind, args.dashboard_port)
        if routing and args.mode == 'server':
            routing.enable()
        while not stop.is_set():
            sock = None
            try:
                LOG.info('Waiting for authenticated peer %s:%s', args.peer_ip, args.port)
                sock, crypto = connect_session(args, stop, store)
                if routing and args.mode == 'client':
                    routing.enable()
                with lock:
                    stats['connection_state'] = 'connected'
                    stats['internet_ipv4'] = bool(routing)
                LOG.info('Tunnel ready: %s %s; dashboard %s:%s', args.tun, address,
                         args.dashboard_bind, args.dashboard_port)
                forward(tun, sock, crypto, stats, lock, stop, args)
            except InterruptedError:
                if not stop.is_set():
                    raise
            except (OSError, TimeoutError) as exc:
                if isinstance(exc, OSError) and not isinstance(exc, TimeoutError) and exc.errno not in TRANSIENT:
                    raise
                LOG.warning('Connection lost or unavailable: %s; retrying in %.1fs', exc, args.reconnect_delay)
                with lock:
                    stats['connection_state'] = 'reconnecting'
                    stats['reconnects'] += 1
                stop.wait(args.reconnect_delay)
            finally:
                if sock:
                    sock.close()
    finally:
        if routing:
            routing.close()
        if http:
            http.shutdown()
            http.server_close()
        if tun is not None:
            os.close(tun)
        if store:
            store.close()
        LOG.info('Final stats: %s', stats)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, TimeoutError, sqlite3.Error, subprocess.CalledProcessError) as exc:
        LOG.error('%s', exc)
        raise SystemExit(1)
