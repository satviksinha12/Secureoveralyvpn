import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit
from urllib.request import build_opener, ProxyHandler, HTTPCookieProcessor
from http.cookiejar import CookieJar

ROOT = Path(__file__).resolve().parents[1] / 'standalone_client'
spec = importlib.util.spec_from_file_location('standalone_app', ROOT / 'app.py')
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class StandaloneTests(unittest.TestCase):
    def test_windows_does_not_attempt_linux_launcher(self):
        with patch.object(app.sys, 'platform', 'win32'), patch.object(app.socket, 'socket') as socket_mock:
            with self.assertRaises(app.LauncherUnavailable):
                app.LauncherClient('unused').call(op='status')
            socket_mock.assert_not_called()

    def test_windows_capabilities_and_honest_disconnect_state(self):
        client = app.LauncherClient('unused')
        ui = app.UIState(client, 5000, 'https://api.ipify.org')
        with patch.object(app.sys, 'platform', 'win32'), patch.object(app.LocalFetcher, 'stats', return_value=None):
            result = ui.status()
        self.assertEqual(result['platform'], 'win32')
        self.assertFalse(result['native_vpn_supported'])
        self.assertFalse(result['download_cancel_supported'])
        self.assertFalse(result['managed'])
        self.assertEqual(result['status'], 'disconnected')
        with patch.object(app.sys, 'platform', 'win32'):
            with self.assertRaises(app.UserError):
                ui.downloads.cancel()

    def test_standalone_project_serves_without_parent_working_directory(self):
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        with tempfile.TemporaryDirectory() as folder:
            proc = subprocess.Popen([sys.executable, str(ROOT / 'app.py'), '--no-browser', '--port', str(port),
                                     '--launcher-socket', str(Path(folder) / 'missing.sock')],
                                    cwd=folder, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                line = proc.stdout.readline().strip()
                self.assertIn('?token=', line)
                url = line.split('UI: ', 1)[1]
                opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()))
                with opener.open(url, timeout=5) as response:
                    self.assertIn(b'Secure VPN Desktop Client', response.read())
                base = 'http://' + urlsplit(url).netloc
                with opener.open(base + '/api/status', timeout=10) as response:
                    result = json.load(response)
                self.assertIn('native_vpn_supported', result)
                self.assertEqual(result['status'], 'disconnected')
                with opener.open(base + '/app.js', timeout=5) as response:
                    self.assertIn(b'Windows / macOS interface preview', response.read())
            finally:
                proc.terminate()
                stdout, stderr = proc.communicate(timeout=10)
                self.assertEqual(proc.returncode, 0, stderr)


if __name__ == '__main__':
    unittest.main()
