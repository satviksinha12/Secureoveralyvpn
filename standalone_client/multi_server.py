"""Single-loop, PSK-authenticated multi-client IPv4 VPN server."""
import hashlib
import hmac
import logging
import os
import select
import socket
import struct
import time

from internet import InternetRouting
from vpn import (HELLO, MTU, SessionStore, TunnelCrypto, dashboard, derive, open_tun)

LOG = logging.getLogger('vpn')
CONFIG = b'\x00CFG'
CONFIG_ACK = b'\x00CFA'


class MultiServer:
    def __init__(self, sock, args, store, stats, lock):
        self.sock, self.args, self.store = sock, args, store
        self.stats, self.lock = stats, lock
        self.master = derive(args.psk.encode(), b'pyvpn-v3-psk', b'authentication')
        self.seed = store.seed if store else os.urandom(32)
        self.pending, self.clients, self.endpoints = {}, {}, {}
        self.leases = {}
        if store:
            with store.db:
                store.db.execute('CREATE TABLE IF NOT EXISTS leases (client TEXT PRIMARY KEY, ip TEXT UNIQUE)')
            self.leases = dict(store.db.execute('SELECT client, ip FROM leases'))

    def count(self, name, amount=1):
        with self.lock:
            self.stats[name] = self.stats.get(name, 0) + amount

    def publish(self):
        with self.lock:
            self.stats['active_clients'] = len(self.clients)
            self.stats['clients'] = [dict(ip=c['ip'], endpoint=f"{c['endpoint'][0]}:{c['endpoint'][1]}",
                                          packets_sent=c['sent'], packets_received=c['received'])
                                     for c in self.clients.values()]

    def lease(self, identity):
        if identity in self.leases:
            return self.leases[identity]
        used = set(self.leases.values())
        for number in range(2, 255):
            address = '10.8.0.' + str(number)
            if address not in used:
                if self.store:
                    with self.store.db:
                        self.store.db.execute('INSERT INTO leases VALUES (?, ?)', (identity, address))
                self.leases[identity] = address
                return address
        raise ValueError('Tunnel address pool exhausted (253 device identities)')

    def send(self, endpoint, wire):
        try:
            self.sock.sendto(wire, endpoint)
            return True
        except OSError as exc:
            LOG.warning('UDP send to %s failed: %s', endpoint, exc)
            return False

    def control(self, pending):
        remote, local = pending['remote'], pending['local']
        body = HELLO + b'S' + local
        hello = body + hmac.digest(self.master, body, 'sha256')
        ack = b'ACKS' + hmac.digest(self.master, b'confirmS' + local + remote, 'sha256')
        self.send(pending['endpoint'], hello)
        self.send(pending['endpoint'], ack)
        pending['last_tx'] = time.monotonic()
        return hello, ack

    def receive(self, wire, endpoint):
        now = time.monotonic()
        if self.args.peer_ip and endpoint[0] != self.args.peer_ip:
            return None
        if len(wire) == 103 and wire[:7] == HELLO + b'C':
            if not hmac.compare_digest(wire[-32:], hmac.digest(self.master, wire[:-32], 'sha256')):
                self.count('dropped_auth')
                return None
            active = self.endpoints.get(endpoint)
            if active and wire == active['remote_hello']:
                self.send(endpoint, active['hello'])
                self.send(endpoint, active['ack'])
                return None
            pending = self.pending.get(endpoint)
            if pending is None or pending['remote'] != wire[7:71]:
                if len(self.pending) >= 128:
                    return None
                pending = dict(remote=wire[7:71], local=self.seed + os.urandom(32),
                               endpoint=endpoint, created=now, last_tx=0)
                self.pending[endpoint] = pending
            self.control(pending)
            return None
        if len(wire) == 36 and wire[:4] == b'ACKC':
            pending = self.pending.get(endpoint)
            if not pending:
                return None
            transcript = pending['local'] + pending['remote']
            expected = hmac.digest(self.master, b'confirmC' + transcript, 'sha256')
            if not hmac.compare_digest(wire[4:], expected):
                self.count('dropped_auth')
                return None
            identity = hashlib.sha256(pending['remote'][:32]).hexdigest()
            try:
                address = self.lease(identity)
            except ValueError as exc:
                LOG.warning('%s', exc)
                del self.pending[endpoint]
                return None
            seeds = pending['local'][:32] + pending['remote'][:32]
            crypto = TunnelCrypto(derive(self.master, seeds, b'server-to-client'),
                                  derive(self.master, seeds, b'client-to-server'), self.store)
            hello, ack = self.control(pending)
            previous = self.clients.get(identity)
            if previous:
                self.endpoints.pop(previous['endpoint'], None)
            # A UDP endpoint can have only one authenticated device at a time.
            displaced = self.endpoints.get(endpoint)
            if displaced:
                self.clients.pop(displaced['identity'], None)
            client = dict(identity=identity, ip=address, endpoint=endpoint, crypto=crypto,
                          hello=hello, ack=ack, remote_hello=HELLO + b'C' + pending['remote'] +
                          hmac.digest(self.master, HELLO + b'C' + pending['remote'], 'sha256'),
                          last_rx=now, last_tx=now, configured=False, sent=0, received=0)
            self.clients[identity] = self.endpoints[endpoint] = client
            del self.pending[endpoint]
            self.send(endpoint, crypto.encrypt(CONFIG + socket.inet_aton(address)))
            self.publish()
            LOG.info('Client authenticated: %s:%s -> %s', *endpoint, address)
            return None
        client = self.endpoints.get(endpoint)
        if not client:
            return None
        plain, reason = client['crypto'].decrypt(wire)
        if reason:
            self.count('dropped_' + reason)
            LOG.warning('Dropped packet from %s: %s', endpoint, reason)
            return None
        client['last_rx'] = now
        with self.lock:
            self.stats['last_seen'] = time.time()
        if plain == CONFIG_ACK + socket.inet_aton(client['ip']):
            client['configured'] = True
            return None
        if not plain:
            return None
        # Enforce the address lease: authenticated devices cannot spoof other clients.
        if (len(plain) < 20 or plain[0] >> 4 != 4 or (plain[0] & 15) < 5
                or len(plain) < (plain[0] & 15) * 4
                or struct.unpack('!H', plain[2:4])[0] != len(plain)
                or plain[12:16] != socket.inet_aton(client['ip'])):
            self.count('dropped_malformed')
            return None
        client['received'] += 1
        self.count('packets_received')
        self.count('bytes_received', len(plain))
        self.publish()
        return plain

    def from_tun(self, packet):
        if len(packet) < 20 or packet[0] >> 4 != 4:
            self.count('dropped_unroutable')
            return
        destination = socket.inet_ntoa(packet[16:20])
        client = next((c for c in self.clients.values() if c['ip'] == destination), None)
        if not client:
            self.count('dropped_unroutable')
            return
        if self.send(client['endpoint'], client['crypto'].encrypt(packet)):
            client['last_tx'] = time.monotonic()
            client['sent'] += 1
            self.count('packets_sent')
            self.count('bytes_sent', len(packet))
            self.publish()

    def tick(self):
        now = time.monotonic()
        for endpoint, pending in list(self.pending.items()):
            if now - pending['created'] > self.args.handshake_timeout:
                del self.pending[endpoint]
            elif now - pending['last_tx'] >= 0.3:
                self.control(pending)
        for identity, client in list(self.clients.items()):
            if now - client['last_rx'] >= self.args.peer_timeout:
                del self.clients[identity]
                self.endpoints.pop(client['endpoint'], None)
                LOG.info('Client timed out: %s', client['ip'])
                self.publish()
            elif not client['configured'] and now - client['last_tx'] >= 1:
                self.send(client['endpoint'], client['crypto'].encrypt(CONFIG + socket.inet_aton(client['ip'])))
                client['last_tx'] = now
            elif now - client['last_tx'] >= self.args.keepalive:
                self.send(client['endpoint'], client['crypto'].encrypt(b''))
                client['last_tx'] = now


def run_server(args, stop, stats, lock):
    tun = http = store = routing = None
    try:
        if args.state_file:
            identity = hashlib.sha256(('server-v3:' + args.psk).encode()).hexdigest()
            store = SessionStore(args.state_file, identity)
        tun = open_tun(args.tun, '10.8.0.1')
        if args.internet:
            routing = InternetRouting('server', None, args.tun)
            routing.enable()
        with lock:
            stats.update(connection_state='listening', active_clients=0, clients=[],
                         internet_ipv4=args.internet, reconnects=0)
        http = dashboard(stats, lock, args.dashboard_bind, args.dashboard_port)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('0.0.0.0', args.port))
            engine = MultiServer(sock, args, store, stats, lock)
            LOG.info('Multi-client server ready on UDP %s; accepting %s', args.port, args.peer_ip or 'any PSK-authenticated IPv4 peer')
            while not stop.is_set():
                ready, _, _ = select.select([tun, sock], [], [], 0.1)
                for source in ready:
                    if source == sock:
                        wire, endpoint = sock.recvfrom(65535)
                        plain = engine.receive(wire, endpoint)
                        if plain:
                            try:
                                os.write(tun, plain)
                            except OSError as exc:
                                LOG.warning('Invalid packet for TUN: %s', exc)
                                engine.count('dropped_malformed')
                    else:
                        engine.from_tun(os.read(tun, MTU))
                engine.tick()
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
        LOG.info('Final server stats: %s', stats)
