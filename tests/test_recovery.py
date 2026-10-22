import concurrent.futures
import errno
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import select

def select_ready(sock):
    return select.select([sock], [], [], 0)[0]


from vpn import SessionStore, TunnelCrypto, derive, forward, handshake, main


class PersistenceTests(unittest.TestCase):
    def test_restart_skips_reserved_nonces_and_keeps_replay_window(self):
        a, b = derive(b'key', b'salt', b'a'), derive(b'key', b'salt', b'b')
        with tempfile.TemporaryDirectory() as folder:
            path = folder + '/state.sqlite'
            store = SessionStore(path, 'test')
            seed = store.seed
            crypto = TunnelCrypto(a, b, store)
            old = crypto.encrypt(b'before crash')
            incoming = TunnelCrypto(b, a).encrypt(b'received')
            self.assertEqual(crypto.decrypt(incoming), (b'received', None))
            store.close()
            store = SessionStore(path, 'test')
            try:
                self.assertEqual(seed, store.seed)
                crypto = TunnelCrypto(a, b, store)
                new = crypto.encrypt(b'after restart')
                self.assertGreaterEqual(int.from_bytes(new[:8], 'big'), 4096)
                self.assertNotEqual(old[8:20], new[8:20])
                self.assertEqual(crypto.decrypt(incoming), (None, 'replay'))
            finally:
                store.close()

    def test_abrupt_process_exit_preserves_reservation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = folder + '/state.sqlite'
            script = ('from vpn import SessionStore, TunnelCrypto; import os, sys; '
                      's=SessionStore(sys.argv[1], "test"); '
                      'c=TunnelCrypto(b"a"*32,b"b"*32,s); c.encrypt(b"crash"); os._exit(0)')
            subprocess.run([sys.executable, '-c', script, path], check=True)
            store = SessionStore(path, 'test')
            try:
                self.assertEqual(TunnelCrypto(b'a' * 32, b'b' * 32, store).seq, 4096)
            finally:
                store.close()

    def test_abrupt_exit_preserves_received_packet_rejection(self):
        wire = TunnelCrypto(b'b' * 32, b'a' * 32).encrypt(b'accepted before crash')
        with tempfile.TemporaryDirectory() as folder:
            path = folder + '/state.sqlite'
            script = ('from vpn import SessionStore, TunnelCrypto; import os, sys; '
                      's=SessionStore(sys.argv[1], "test"); '
                      'c=TunnelCrypto(b"a"*32,b"b"*32,s); '
                      'assert c.decrypt(bytes.fromhex(sys.argv[2]))[1] is None; os._exit(0)')
            subprocess.run([sys.executable, '-c', script, path, wire.hex()], check=True)
            store = SessionStore(path, 'test')
            try:
                self.assertEqual(TunnelCrypto(b'a' * 32, b'b' * 32, store).decrypt(wire), (None, 'replay'))
            finally:
                store.close()

    def test_private_file_lock_and_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            path = folder + '/state.sqlite'
            store = SessionStore(path, 'owner')
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            with self.assertRaises(BlockingIOError):
                SessionStore(path, 'owner')
            store.close()
            with self.assertRaises(ValueError):
                SessionStore(path, 'wrong identity')
            os.chmod(path, 0o644)
            with self.assertRaises(ValueError):
                SessionStore(path, 'owner')
            os.symlink(path, folder + '/link')
            with self.assertRaises(OSError):
                SessionStore(folder + '/link', 'owner')

    def test_repeated_handshake_retains_keys_and_replay_state(self):
        with tempfile.TemporaryDirectory() as folder:
            def endpoint(sock, mode, previous):
                store = SessionStore(folder + '/' + mode, mode)
                try:
                    crypto = handshake(sock, 'test-secret-123456', mode, 3,
                                       '127.0.0.1' if mode == 'server' else None, store)
                    result = crypto.decrypt(previous) if previous else None
                    wire = crypto.encrypt(b'payload')
                    return crypto.session, wire, result, crypto.local_hello
                finally:
                    store.close()
            previous_server = previous_client = None
            first_server = first_client = None
            ids = []
            challenges = []
            for _ in range(2):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    server.bind(('127.0.0.1', 0))
                    client.bind(('127.0.0.1', 0))
                    client.connect(server.getsockname())
                    with concurrent.futures.ThreadPoolExecutor(2) as pool:
                        sf = pool.submit(endpoint, server, 'server', previous_client)
                        cf = pool.submit(endpoint, client, 'client', previous_server)
                        s, c = sf.result(), cf.result()
                ids.append((s[0], c[0]))
                challenges.append((s[3], c[3]))
                if previous_server:
                    self.assertEqual(s[2], (b'payload', None))
                    self.assertEqual(c[2], (b'payload', None))
                    self.assertGreaterEqual(int.from_bytes(c[1][:8], 'big'), 4096)
                if first_server is None:
                    first_server, first_client = s[1], c[1]
                previous_server, previous_client = s[1], c[1]
            self.assertEqual(ids[0], ids[1])
            self.assertNotEqual(challenges[0], challenges[1])
            # Third handshake must reject the first-session packet already accepted above.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                server.bind(('127.0.0.1', 0))
                client.bind(('127.0.0.1', 0))
                client.connect(server.getsockname())
                with concurrent.futures.ThreadPoolExecutor(2) as pool:
                    sf = pool.submit(endpoint, server, 'server', first_client)
                    cf = pool.submit(endpoint, client, 'client', first_server)
                    s, c = sf.result(), cf.result()
                    self.assertEqual(s[0], ids[0][0])
                    self.assertEqual(c[0], ids[0][1])
                    self.assertEqual(s[2], (None, 'replay'))
                    self.assertEqual(c[2], (None, 'replay'))


class RecoveryTests(unittest.TestCase):
    def test_handshake_shutdown_is_prompt(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            stop = threading.Event()
            stop.set()
            start = time.monotonic()
            with self.assertRaises(InterruptedError):
                handshake(sock, 'shared-secret-1234', 'server', 60, '127.0.0.1', stop=stop)
            self.assertLess(time.monotonic() - start, 0.5)

    def test_old_startup_confirmation_cannot_resume_new_challenge(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            server.bind(('127.0.0.1', 0))
            client.bind(('127.0.0.1', 0))
            server.connect(client.getsockname())
            client.connect(server.getsockname())
            with concurrent.futures.ThreadPoolExecutor(2) as pool:
                sf = pool.submit(handshake, server, 'test-secret-123456', 'server', 3)
                cf = pool.submit(handshake, client, 'test-secret-123456', 'client', 3)
                old_server, _ = sf.result(), cf.result()
            while select_ready(client):
                client.recv(65535)
            server.send(old_server.local_hello)
            server.send(old_server.confirm)
            with self.assertRaises(TimeoutError):
                handshake(client, 'test-secret-123456', 'client', 0.15)

    def test_peer_timeout_and_encrypted_keepalive(self):
        tun, app = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        with tun, app, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as outgoing, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peer:
            peer.bind(('127.0.0.1', 0))
            outgoing.connect(peer.getsockname())
            crypto = TunnelCrypto(b'a' * 32, b'b' * 32)
            args = SimpleNamespace(keepalive=0.01, peer_timeout=0.25)
            with self.assertRaises(TimeoutError):
                forward(tun.fileno(), outgoing, crypto, {}, threading.Lock(), threading.Event(), args)
            peer.settimeout(1)
            wire = peer.recv(2048)
            self.assertEqual(TunnelCrypto(b'b' * 32, b'a' * 32).decrypt(wire), (b'', None))

    def test_main_retries_without_recreating_tun(self):
        stop = None
        attempts = []
        fake_sock = unittest.mock.Mock()
        def register(sig, handler):
            nonlocal stop
            if sig == signal.SIGTERM:
                stop = handler
        def connect(*args):
            attempts.append(1)
            if len(attempts) == 1:
                raise ConnectionRefusedError(errno.ECONNREFUSED, 'peer unavailable')
            return fake_sock, object()
        def finish(*args):
            stop()
        with patch.object(sys, 'argv', ['vpn.py', '--mode', 'client', '--peer-ip', '127.0.0.1', '--psk', 'test-secret-123456', '--reconnect-delay', '0.001']), patch('vpn.signal.signal', side_effect=register), patch('vpn.open_tun', return_value=99) as tun, patch('vpn.os.close'), patch('vpn.dashboard') as dashboard, patch('vpn.connect_session', side_effect=connect), patch('vpn.forward', side_effect=finish):
            main()
            self.assertEqual(len(attempts), 2)
            tun.assert_called_once()
            dashboard.assert_called_once()
            fake_sock.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
