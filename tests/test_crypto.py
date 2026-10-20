import unittest
from vpn import ReplayWindow, TunnelCrypto, derive

class CryptoTests(unittest.TestCase):
    def setUp(self):
        a = derive(b'secret', b'session', b'a')
        b = derive(b'secret', b'session', b'b')
        self.client = TunnelCrypto(a, b)
        self.server = TunnelCrypto(b, a)

    def test_roundtrip_replay_tamper(self):
        wire = self.client.encrypt(b'hello')
        bad = bytearray(wire)
        bad[-1] ^= 1
        self.assertEqual(self.server.decrypt(bytes(bad)), (None, 'auth'))
        self.assertEqual(self.server.decrypt(wire), (b'hello', None))
        self.assertEqual(self.server.decrypt(wire), (None, 'replay'))

    def test_aad_and_nonce_authenticated(self):
        wire = self.client.encrypt(b'hello')
        for offset in (0, 8, 20):
            bad = bytearray(wire)
            bad[offset] ^= 1
            self.assertEqual(self.server.decrypt(bytes(bad)), (None, 'auth'))
        self.assertEqual(self.server.window.high, -1)

    def test_reorder_window_boundary(self):
        packets = [self.client.encrypt(bytes([i])) for i in range(66)]
        self.assertIsNone(self.server.decrypt(packets[65])[1])
        self.assertIsNone(self.server.decrypt(packets[2])[1])
        self.assertEqual(self.server.decrypt(packets[1])[1], 'replay')
        self.assertEqual(self.server.decrypt(packets[2])[1], 'replay')

    def test_bad_lengths_and_wrong_direction(self):
        for wire in (b'', b'x' * 35, b'x' * 1437):
            self.assertEqual(self.server.decrypt(wire)[1], 'malformed')
        self.assertEqual(self.client.decrypt(self.client.encrypt(b'x'))[1], 'auth')


class HandshakeTests(unittest.TestCase):
    def test_real_udp_handshake_and_session_freshness(self):
        import concurrent.futures
        import socket
        from vpn import handshake
        ciphertexts = []
        for _ in range(2):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as a, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as b:
                a.bind(('127.0.0.1', 0))
                b.bind(('127.0.0.1', 0))
                a.connect(b.getsockname())
                b.connect(a.getsockname())
                with concurrent.futures.ThreadPoolExecutor(2) as pool:
                    server = pool.submit(handshake, a, 'test-secret-123456', 'server', 3)
                    client = pool.submit(handshake, b, 'test-secret-123456', 'client', 3)
                    s, c = server.result(), client.result()
                wire = c.encrypt(b'payload')
                self.assertEqual(s.decrypt(wire), (b'payload', None))
                self.assertEqual(c.decrypt(s.encrypt(b'reply')), (b'reply', None))
                ciphertexts.append(wire)
        self.assertNotEqual(*ciphertexts)

class ServiceTests(unittest.TestCase):
    def test_wrong_psk_times_out(self):
        import concurrent.futures
        import socket
        from vpn import handshake
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as a, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as b:
            a.bind(('127.0.0.1', 0))
            b.bind(('127.0.0.1', 0))
            a.connect(b.getsockname())
            b.connect(a.getsockname())
            with concurrent.futures.ThreadPoolExecutor(2) as pool:
                futures = [pool.submit(handshake, a, 'secret-one', 'server', 0.3),
                           pool.submit(handshake, b, 'secret-two', 'client', 0.3)]
                for future in futures:
                    with self.assertRaises(TimeoutError):
                        future.result()

    def test_server_learns_authenticated_client_source_port(self):
        import concurrent.futures
        import socket
        from vpn import handshake
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            server.bind(('127.0.0.1', 0))
            client.bind(('127.0.0.1', 0))
            client.connect(server.getsockname())
            # A forged hello must not pin the server to the wrong source port.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as attacker:
                attacker.sendto(b'PYVPN1C' + b'x' * 64, server.getsockname())
            with concurrent.futures.ThreadPoolExecutor(2) as pool:
                sf = pool.submit(handshake, server, 'shared-test-secret', 'server', 3, '127.0.0.1')
                cf = pool.submit(handshake, client, 'shared-test-secret', 'client', 3)
                s, c = sf.result(), cf.result()
            self.assertEqual(server.getpeername(), client.getsockname())
            self.assertEqual(s.decrypt(c.encrypt(b'client behind NAT')), (b'client behind NAT', None))
            self.assertEqual(c.decrypt(s.encrypt(b'reply')), (b'reply', None))

    def test_dashboard_json_and_refresh(self):
        import json
        import threading
        import urllib.request
        from vpn import dashboard
        http = dashboard({'packets_received': 7, 'last_seen': None}, threading.Lock(), '127.0.0.1', 0)
        base = 'http://127.0.0.1:' + str(http.server_port)
        try:
            with urllib.request.urlopen(base + '/stats') as response:
                self.assertEqual(json.load(response)['packets_received'], 7)
            with urllib.request.urlopen(base + '/') as response:
                self.assertIn(b'content="2"', response.read())
        finally:
            http.shutdown()
            http.server_close()


if __name__ == '__main__':
    unittest.main()
