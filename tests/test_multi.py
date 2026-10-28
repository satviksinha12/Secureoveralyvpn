import concurrent.futures
import socket
import struct
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace

from multi_server import MultiServer
from vpn import SessionStore, connect_session


def packet(source, destination, payload=b'demo'):
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), 0, 0, 64, 17, 0,
                       socket.inet_aton(source), socket.inet_aton(destination)) + payload


class MultiClientTests(unittest.TestCase):
    def test_two_clients_independent_addresses_replies_and_reconnect(self):
        stop = threading.Event()
        ready = threading.Event()
        errors = []
        details = {}
        stats, lock = {}, threading.Lock()
        with tempfile.TemporaryDirectory() as folder:
            def server():
                store = SessionStore(folder + '/server', 'server-test')
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                        sock.bind(('127.0.0.1', 0))
                        sock.settimeout(0.02)
                        args = SimpleNamespace(psk='shared-demo-secret', peer_ip=None,
                                               handshake_timeout=2, peer_timeout=3, keepalive=0.1)
                        engine = MultiServer(sock, args, store, stats, lock)
                        details['port'] = sock.getsockname()[1]
                        ready.set()
                        while not stop.is_set():
                            try:
                                wire, endpoint = sock.recvfrom(65535)
                            except socket.timeout:
                                engine.tick()
                                continue
                            plain = engine.receive(wire, endpoint)
                            if plain:
                                engine.from_tun(packet('10.8.0.1', socket.inet_ntoa(plain[12:16]), plain[20:]))
                            engine.tick()
                except BaseException as exc:
                    errors.append(exc)
                    ready.set()
                finally:
                    store.close()
            thread = threading.Thread(target=server)
            thread.start()
            ready.wait(3)
            def client(name, gate=None, spoof=False):
                store = SessionStore(folder + '/' + name, name)
                args = SimpleNamespace(mode='client', port=details['port'], local_port=0,
                                       peer_ip='127.0.0.1', psk='shared-demo-secret', handshake_timeout=3)
                sock = None
                try:
                    sock, crypto = connect_session(args, threading.Event(), store)
                    if gate:
                        gate.wait(timeout=3)
                    sock.send(crypto.encrypt(packet(crypto.assigned_ip, '10.8.0.1', name.encode())))
                    sock.settimeout(3)
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline:
                        plain, reason = crypto.decrypt(sock.recv(65535))
                        if reason is None and len(plain) >= 20:
                            self.assertEqual(plain[20:], name.encode())
                            self.assertEqual(socket.inet_ntoa(plain[16:20]), crypto.assigned_ip)
                            if spoof:
                                sock.send(crypto.encrypt(packet('10.8.0.250', '10.8.0.1')))
                            return crypto.assigned_ip, sock.getsockname()[1]
                    self.fail('No routed reply')
                finally:
                    if sock:
                        sock.close()
                    store.close()
            try:
                gate = threading.Barrier(2)
                with concurrent.futures.ThreadPoolExecutor(2) as pool:
                    first = pool.submit(client, 'deviceA', gate, True)
                    second = pool.submit(client, 'deviceB', gate)
                    a, b = first.result(), second.result()
                self.assertNotEqual(a[0], b[0])
                self.assertNotEqual(a[1], b[1])
                again = client('deviceA')
                self.assertEqual(a[0], again[0])
                with lock:
                    self.assertEqual(stats['active_clients'], 2)
                    self.assertEqual(stats['packets_received'], 3)
                # Both share the PSK but cannot use another tunnel source address.
                for _ in range(50):
                    with lock:
                        if stats.get('dropped_malformed', 0):
                            break
                    time.sleep(0.01)
                self.assertGreater(stats['dropped_malformed'], 0)
            finally:
                stop.set()
                thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])

    def test_established_client_answers_hello_with_confirmation_only(self):
        from vpn import TunnelCrypto, forward
        stop = threading.Event()
        tun, app = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        with tun, app, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
            server.bind(('127.0.0.1', 0))
            client.connect(server.getsockname())
            server.connect(client.getsockname())
            crypto = TunnelCrypto(b'a' * 32, b'b' * 32)
            crypto.remote_hello = b'authenticated-server-hello'
            crypto.local_hello = b'client-hello'
            crypto.confirm = b'client-confirmation'
            args = SimpleNamespace(keepalive=10, peer_timeout=20)
            with concurrent.futures.ThreadPoolExecutor(1) as pool:
                future = pool.submit(forward, tun.fileno(), client, crypto, {}, threading.Lock(), stop, args)
                try:
                    server.send(crypto.remote_hello)
                    server.settimeout(2)
                    self.assertEqual(server.recv(65535), crypto.confirm)
                finally:
                    stop.set()
                future.result(timeout=3)

    def test_unauthenticated_device_cannot_allocate_address(self):
        from unittest.mock import Mock
        sock = Mock()
        stats = {}
        args = SimpleNamespace(psk='shared-demo-secret', peer_ip=None)
        engine = MultiServer(sock, args, None, stats, threading.Lock())
        engine.receive(b'PYVPN3C' + b'x' * 96, ('198.51.100.20', 40000))
        self.assertEqual(stats['dropped_auth'], 1)
        self.assertEqual(engine.clients, {})
        self.assertEqual(engine.pending, {})
        self.assertEqual(engine.leases, {})
        sock.sendto.assert_not_called()

    def test_pool_retains_unique_leases_after_server_restart(self):
        with tempfile.TemporaryDirectory() as folder:
            store = SessionStore(folder + '/state', 'server')
            args = SimpleNamespace(psk='shared-demo-secret')
            engine = MultiServer(None, args, store, {}, threading.Lock())
            a, b = engine.lease('deviceA'), engine.lease('deviceB')
            store.close()
            store = SessionStore(folder + '/state', 'server')
            try:
                engine = MultiServer(None, args, store, {}, threading.Lock())
                self.assertEqual(engine.lease('deviceA'), a)
                self.assertEqual(engine.lease('deviceB'), b)
                self.assertNotIn(engine.lease('deviceC'), (a, b))
            finally:
                store.close()


if __name__ == '__main__':
    unittest.main()
