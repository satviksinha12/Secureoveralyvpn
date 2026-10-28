import io
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.error import URLError
from urllib.request import urlopen

from internet import InternetRouting
from file_transfer import digest, receive


class RoutingTests(unittest.TestCase):
    def test_client_pins_outer_peer_before_redirecting_and_restores(self):
        calls = []
        def run(*args):
            calls.append(args)
            if args[:6] == ('ip', '-j', '-4', 'route', 'get', '203.0.113.10'):
                return '[{"dev":"wlan0","gateway":"192.168.1.1"}]'
            if 'show' in args:
                return '[]'
            return ''
        route = InternetRouting('client', '203.0.113.10', 'tun0')
        with patch.object(route, 'run', side_effect=run):
            route.enable()
            changes = [call for call in calls if 'add' in call]
            self.assertEqual(changes[0], ('ip', '-4', 'route', 'add', '203.0.113.10/32', 'via', '192.168.1.1', 'dev', 'wlan0'))
            self.assertEqual(changes[1][4], '0.0.0.0/1')
            self.assertEqual(changes[2][4], '128.0.0.0/1')
            route.enable()
            self.assertEqual(len([c for c in calls if 'add' in c]), 3)
            route.close()
            deletes = [c for c in calls if 'del' in c]
            self.assertEqual([c[4] for c in deletes], ['128.0.0.0/1', '0.0.0.0/1', '203.0.113.10/32'])

    def test_partial_route_failure_rolls_back_only_created_routes(self):
        calls = []
        def run(*args):
            calls.append(args)
            if 'get' in args:
                return '[{"dev":"wlan0","gateway":"192.168.1.1"}]'
            if 'show' in args:
                return '[]'
            if 'add' in args and '128.0.0.0/1' in args:
                raise subprocess.CalledProcessError(2, args)
            return ''
        route = InternetRouting('client', '203.0.113.10', 'tun0')
        with patch.object(route, 'run', side_effect=run):
            with self.assertRaises(subprocess.CalledProcessError):
                route.enable()
        self.assertEqual(len([c for c in calls if 'del' in c]), 2)
        self.assertFalse(route.active)

    def test_existing_host_route_is_preserved_and_conflicts_refused(self):
        route = InternetRouting('client', '203.0.113.10', 'tun0')
        with patch.object(route, 'run', side_effect=['[{"dev":"wlan0"}]', '[{"dst":"203.0.113.10/32"}]', '[]', '[]', '', '', '', '']) as run:
            route.enable()
            route.close()
            self.assertFalse(any('/32' in str(c) and ("'add'" in str(c) or "'del'" in str(c)) for c in run.call_args_list))
        with patch.object(route, 'run', side_effect=['[{"dev":"wlan0"}]', '[]', '[{"dst":"0.0.0.0/1"}]']):
            with self.assertRaises(ValueError):
                route.enable()

    def test_server_nat_is_scoped_and_forwarding_restored(self):
        calls = []
        def run(*args):
            calls.append(args)
            if 'get' in args:
                return '[{"dev":"ens4"}]'
            if args[:2] == ('sysctl', '-n'):
                return '0\n'
            return ''
        route = InternetRouting('server', '203.0.113.10', 'tun0')
        with patch.object(route, 'run', side_effect=run):
            route.enable()
            route.close()
        masquerade = next(c for c in calls if '-I' in c and 'MASQUERADE' in c)
        self.assertIn('10.8.0.2/32', masquerade)
        self.assertIn('ens4', masquerade)
        self.assertEqual(len([c for c in calls if '-D' in c]), 4)
        self.assertEqual(calls[-1], ('sysctl', '-w', 'net.ipv4.ip_forward=0'))


class TransferTests(unittest.TestCase):
    def test_real_http_transfer_and_checksum(self):
        with tempfile.TemporaryDirectory() as folder:
            source, dest = Path(folder) / 'sample.bin', Path(folder) / 'received.bin'
            source.write_bytes(bytes(range(256)) * 4096)
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            process = subprocess.Popen([sys.executable, 'file_transfer.py', 'serve', '--file', str(source), '--bind', '127.0.0.1', '--port', str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                base = f'http://127.0.0.1:{port}'
                for _ in range(100):
                    try:
                        with urlopen(base + '/manifest', timeout=0.2) as response:
                            json.load(response)
                        break
                    except URLError:
                        time.sleep(0.02)
                receive(base, dest)
                self.assertEqual(digest(source), digest(dest))
                with self.assertRaises(ValueError):
                    receive(base, dest)
            finally:
                process.terminate()
                process.wait(timeout=5)

    def test_tampered_transfer_does_not_leave_output(self):
        with tempfile.TemporaryDirectory() as folder:
            dest = Path(folder) / 'received'
            manifest = io.BytesIO(json.dumps({'bytes': 4, 'sha256': '0' * 64}).encode())
            with patch('file_transfer.urlopen', side_effect=[manifest, io.BytesIO(b'evil')]):
                with self.assertRaises(ValueError):
                    receive('http://127.0.0.1:8000', dest)
            self.assertFalse(dest.exists())
            self.assertEqual(list(Path(folder).iterdir()), [])


if __name__ == '__main__':
    unittest.main()
