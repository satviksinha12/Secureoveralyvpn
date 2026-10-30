import http.client
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ui import app, launcher

FAKE = str(Path(__file__).resolve().parent / 'fake_vpn.py')
PSK = 'correct-horse-battery-staple'


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def wait_for(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError('timed out waiting for condition')


class StartupTests(unittest.TestCase):
    def test_blocked_desktop_browser_does_not_block_http(self):
        entered, release = threading.Event(), threading.Event()
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', '2')
                self.end_headers()
                self.wfile.write(b'OK')
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        def blocked_browser(url):
            entered.set()
            release.wait(5)
            return True
        try:
            with unittest.mock.patch('webbrowser.open', side_effect=blocked_browser):
                app.start_server_and_browser(server, 'http://127.0.0.1:%d/' % server.server_port)
                self.assertTrue(entered.wait(2))
                conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=2)
                try:
                    conn.request('GET', '/')
                    self.assertEqual(conn.getresponse().read(), b'OK')
                finally:
                    conn.close()
        finally:
            release.set()
            server.shutdown()
            server.server_close()


class ValidationTests(unittest.TestCase):
    good = dict(server_ip='203.0.113.10', port=5555, dashboard_port=5000, internet=True, psk=PSK)

    def test_accepts_valid_request(self):
        self.assertEqual(launcher.validate_start(self.good), ('203.0.113.10', 5555, 5000, True, PSK))

    def test_rejects_bad_input(self):
        for change in (dict(server_ip='example.com'), dict(server_ip='0.0.0.0'), dict(server_ip='127.0.0.1'),
                       dict(server_ip='203.0.113.10; reboot'), dict(server_ip='::1'), dict(port=0),
                       dict(port=70000), dict(port='5555'), dict(port=True), dict(dashboard_port=-1),
                       dict(internet='yes'), dict(psk='short'), dict(psk=None), dict(psk='x' * 16 + '\n'),
                       dict(psk='x' * 600)):
            with self.assertRaises(launcher.RequestError, msg=change):
                launcher.validate_start({**self.good, **change})

    def test_argv_never_contains_secret_and_has_fixed_shape(self):
        argv = launcher.build_argv('/p/python', '/p/vpn.py', '/var/lib/pyvpn', '203.0.113.10', 5555, 5000, True)
        self.assertEqual(argv[:6], ['/p/python', '/p/vpn.py', '--mode', 'client', '--peer-ip', '203.0.113.10'])
        self.assertIn('--internet', argv)
        self.assertIn('/var/lib/pyvpn/client-203-0-113-10.sqlite', argv)
        self.assertNotIn('--psk', argv)
        self.assertNotIn('--internet', launcher.build_argv('p', 'v', 's', '203.0.113.10', 1, 2, False))

    def test_redactor(self):
        redact = launcher.Redactor(PSK)
        self.assertNotIn(PSK, redact('secret ' + PSK))
        self.assertEqual(redact('run --psk abc123 now'), 'run --psk [redacted] now')
        self.assertEqual(redact('VPN_PSK=abc'), 'VPN_PSK=[redacted]')


class TrustCheckTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, 'vpn.py')
        Path(self.path).write_text('')

    def check(self, mode, private):
        os.chmod(self.path, mode)
        with unittest.mock.patch.object(launcher, 'private_group', return_value=private):
            launcher.check_trusted([self.path], os.getuid(), False)

    def test_owner_only_and_default_modes_are_accepted(self):
        self.check(0o644, False)

    def test_group_write_is_accepted_only_for_a_private_group(self):
        self.check(0o664, True)  # Ubuntu default umask 002
        with self.assertRaises(SystemExit):
            self.check(0o664, False)

    def test_world_write_is_always_refused(self):
        with self.assertRaises(SystemExit):
            self.check(0o666, True)

    def test_strict_requires_root_ownership(self):
        with self.assertRaises(SystemExit):
            launcher.check_trusted([self.path], os.getuid(), True) if os.getuid() else self.skipTest('root')


class LauncherTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.state_dir = os.path.join(self.tmp, 'state')
        self.sock_path = os.path.join(self.tmp, 'l.sock')
        self.backend = launcher.Backend(sys.executable, FAKE, self.state_dir, self.tmp, stop_timeout=10)
        self.server = launcher.bind_socket(self.sock_path, None)
        self.server.settimeout(0.2)
        self.running = True
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
        self.dport = free_port()

    def serve(self):
        while self.running:
            try:
                conn, _ = self.server.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=launcher.handle, args=(conn, self.backend, None), daemon=True).start()

    def tearDown(self):
        self.backend.stop()
        wait_for(lambda: not self.backend.alive())
        self.running = False
        self.thread.join(2)
        self.server.close()

    def request(self, **fields):
        return app.LauncherClient(self.sock_path).call(**fields)

    def start_request(self, **extra):
        return dict(op='start', server_ip='203.0.113.10', port=5555, dashboard_port=self.dport, internet=True,
                    psk=PSK, **extra)


class LauncherTests(LauncherTestCase):
    def test_start_stop_lifecycle_and_state_file_argument(self):
        self.request(**self.start_request())
        status = wait_for(lambda: (s := self.request(op='status')['status']) and s['state'] == 'running' and s)
        self.assertEqual(status['server_ip'], '203.0.113.10')
        self.assertNotIn('psk', json.dumps(status))
        wait_for(lambda: any('Tunnel ready' in e['line'] for e in self.request(op='logs', since=0)['lines']))
        self.request(op='stop')
        status = wait_for(lambda: (s := self.request(op='status')['status']) and s['state'] == 'exited' and s)
        self.assertEqual(status['exit_code'], 0)
        self.assertTrue(os.path.isdir(self.state_dir))
        self.assertEqual(os.stat(self.state_dir).st_mode & 0o777, 0o700)

    def test_restart_right_after_stop_is_not_blocked_by_time_wait(self):
        self.request(**self.start_request())
        wait_for(lambda: app.LocalFetcher.stats(self.dport))
        self.request(op='stop')
        wait_for(lambda: self.request(op='status')['status']['state'] == 'exited')
        self.request(**self.start_request())  # same dashboard port, immediately
        self.assertEqual(self.request(op='status')['status']['state'], 'running')

    def test_second_start_is_refused_while_running(self):
        self.request(**self.start_request())
        with self.assertRaises(app.UserError) as ctx:
            self.request(**{**self.start_request(), 'dashboard_port': free_port()})
        self.assertIn('already running', str(ctx.exception))

    def test_invalid_request_is_rejected_by_privileged_side(self):
        with self.assertRaises(app.UserError):
            self.request(**{**self.start_request(), 'server_ip': '1.2.3.4 --internet'})
        with self.assertRaises(app.UserError):
            self.request(op='run', cmd='id')
        self.assertEqual(self.request(op='status')['status']['state'], 'idle')

    def test_busy_dashboard_port_is_reported(self):
        with socket.socket() as busy:
            busy.bind(('127.0.0.1', 0))
            with self.assertRaises(app.UserError) as ctx:
                self.request(**{**self.start_request(), 'dashboard_port': busy.getsockname()[1]})
        self.assertIn('not available', str(ctx.exception))

    def test_secret_is_redacted_from_logs(self):
        self.backend.extra_env = {'FAKE_MODE': 'leak'}
        self.request(**self.start_request())
        lines = wait_for(lambda: [e['line'] for e in self.request(op='logs', since=0)['lines']
                                  if 'debug: psk' in e['line']])
        self.assertNotIn(PSK, ''.join(lines))
        self.assertIn('[redacted]', lines[0])

    def test_failure_exposes_exit_code_and_last_error(self):
        self.backend.extra_env = {'FAKE_MODE': 'fail'}
        self.request(**self.start_request())
        status = wait_for(lambda: (s := self.request(op='status')['status']) and s['state'] == 'exited' and s)
        self.assertEqual(status['exit_code'], 1)
        self.assertIn('State belongs to another', status['last_error'])


class HTTPTestCase(LauncherTestCase):
    def setUp(self):
        super().setUp()
        self.ip_server = self.serve_text('198.51.100.9')
        self.ui = app.UIState(app.LauncherClient(self.sock_path), self.dport,
                              'http://127.0.0.1:%d/' % self.ip_server.server_port)
        self.token = 'tok-' + 'a' * 20
        port = free_port()
        self.hosts = {'127.0.0.1:%d' % port}
        self.http = ThreadingHTTPServer(('127.0.0.1', port), app.make_handler(self.ui, self.token, self.hosts))
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.port = port

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.ip_server.shutdown()
        self.ip_server.server_close()
        super().tearDown()

    @staticmethod
    def serve_text(text):
        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = text.encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), H)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        return server

    def fetch(self, method, path, body=None, headers=None, cookie=True, host=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        h = {'Host': host or '127.0.0.1:%d' % self.port}
        if cookie:
            h['Cookie'] = '%s=%s' % (app.COOKIE, self.token)
        h.update(headers or {})
        payload = None if body is None else json.dumps(body)
        conn.request(method, path, payload, h)
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return response, data

    def post(self, path, body=None, **kw):
        headers = {'Content-Type': 'application/json', 'X-PyVPN-UI': '1', **kw.pop('headers', {})}
        response, data = self.fetch('POST', path, body if body is not None else {}, headers, **kw)
        return response.status, json.loads(data or b'{}')

    def status(self):
        response, data = self.fetch('GET', '/api/status')
        self.assertEqual(response.status, 200)
        return json.loads(data)


class AccessControlTests(HTTPTestCase):
    def test_unauthenticated_requests_are_rejected(self):
        self.assertEqual(self.fetch('GET', '/', cookie=False)[0].status, 401)
        self.assertEqual(self.fetch('GET', '/api/status', cookie=False)[0].status, 401)
        self.assertEqual(self.post('/api/disconnect', cookie=False)[0], 403)

    def test_token_sets_cookie_and_redirects(self):
        response, _ = self.fetch('GET', '/?token=' + self.token, cookie=False)
        self.assertEqual(response.status, 303)
        self.assertIn('HttpOnly', response.getheader('Set-Cookie'))
        self.assertIn('SameSite=Strict', response.getheader('Set-Cookie'))
        self.assertEqual(self.fetch('GET', '/?token=wrong', cookie=False)[0].status, 403)

    def test_dns_rebinding_and_cross_site_posts_are_rejected(self):
        self.assertEqual(self.fetch('GET', '/api/status', host='evil.example:80')[0].status, 403)
        self.assertEqual(self.post('/api/disconnect', headers={'Origin': 'http://evil.example'})[0], 403)
        response, _ = self.fetch('POST', '/api/disconnect', {}, {'Content-Type': 'text/plain'})
        self.assertEqual(response.status, 403)  # missing custom header

    def test_static_files_and_security_headers(self):
        response, data = self.fetch('GET', '/')
        self.assertEqual(response.status, 200)
        self.assertIn(b'Secure Overlay VPN', data)
        self.assertIn("default-src 'self'", response.getheader('Content-Security-Policy'))
        self.assertEqual(self.fetch('GET', '/../vpn.py')[0].status, 404)


class FullStackTests(HTTPTestCase):
    def connect(self, **extra):
        return self.post('/api/connect', dict(server_ip='203.0.113.10', psk=PSK, internet=True, port=5555,
                                              dashboard_port=self.dport, **extra))

    def test_not_managed_when_launcher_missing(self):
        self.ui.launcher = app.LauncherClient(os.path.join(self.tmp, 'missing.sock'))
        status = self.status()
        self.assertEqual((status['mode'], status['status'], status['managed']), ('none', 'disconnected', False))
        code, body = self.connect()
        self.assertEqual(code, 400)
        self.assertIn('not managed', body['error'])

    def test_connect_status_exit_ip_and_disconnect(self):
        self.assertEqual(self.status()['status'], 'disconnected')
        code, body = self.connect()
        self.assertEqual(code, 200, body)
        status = wait_for(lambda: (s := self.status()) and s['status'] == 'connected' and s)
        self.assertEqual(status['server_ip'], '203.0.113.10')
        self.assertEqual(status['assigned_ip'], '10.8.0.7')  # from the Tunnel ready log line
        self.assertEqual(status['exit_ip']['baseline']['ip'], '198.51.100.9')
        status = wait_for(lambda: (s := self.status()) and s['exit_ip']['current'].get('state') == 'ok' and s)
        self.assertEqual(status['exit_ip']['current']['ip'], '198.51.100.9')
        self.assertGreaterEqual(status['stats']['packets_sent'], 0)
        self.assertNotIn(PSK, json.dumps(status))
        response, data = self.fetch('GET', '/api/logs?since=0')
        self.assertIn('Tunnel ready', data.decode())
        self.assertNotIn(PSK, data.decode())
        code, body = self.connect()          # repeat Connect must not spawn another backend
        self.assertEqual(code, 400)
        code, _ = self.post('/api/disconnect')
        self.assertEqual(code, 200)
        status = wait_for(lambda: (s := self.status()) and s['status'] == 'disconnected' and s)
        self.assertIsNone(status['assigned_ip'])
        self.assertEqual(status['exit_ip']['current']['state'], 'idle')

    def test_backend_failure_is_shown_as_error(self):
        self.backend.extra_env = {'FAKE_MODE': 'fail'}
        self.connect()
        status = wait_for(lambda: (s := self.status()) and s['status'] == 'error' and s)
        self.assertEqual(status['exit_code'], 1)
        self.assertIn('State belongs to another', status['last_error'])

    def test_input_validation(self):
        self.assertEqual(self.post('/api/connect', dict(server_ip='nope', psk=PSK, internet=True))[0], 400)
        self.assertEqual(self.post('/api/connect', dict(server_ip='203.0.113.10', psk='short', internet=True))[0], 400)
        self.assertEqual(self.status()['status'], 'disconnected')


class DownloadTests(HTTPTestCase):
    def setUp(self):
        super().setUp()
        self.payload = b'hello vpn' * 1000
        payload = self.payload
        slow = self.slow = threading.Event()

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', str(len(payload) + 10))
                self.end_headers()
                self.wfile.write(payload)
                self.wfile.flush()
                if self.path == '/slow':
                    slow.wait(20)

            def log_message(self, *a):
                pass
        self.file_server = ThreadingHTTPServer(('127.0.0.1', 0), H)
        threading.Thread(target=self.file_server.serve_forever, daemon=True).start()
        self.base = 'http://127.0.0.1:%d' % self.file_server.server_port
        self.dest = os.path.join(self.tmp, 'out')

    def tearDown(self):
        self.slow.set()
        self.file_server.shutdown()
        self.file_server.server_close()
        super().tearDown()

    def test_validation(self):
        v = app.Downloads.validate
        for bad in (dict(url='ftp://x/y'), dict(url='https://user:pw@example.com/f'), dict(url='https://a b/c'),
                    dict(url='https://example.com/f', sha256='zz'), dict(url='https://example.com/f', mode='x'),
                    dict(url='https://example.com/f', mode='vpn'),
                    dict(url='http://10.8.0.1:8000', mode='vpn', sha256='a' * 64),
                    dict(url='https://example.com/f', destination=self.tmp)):
            with self.assertRaises(app.UserError, msg=bad):
                v(bad)
        mode, url, out, digest = v(dict(url='https://www.rfc-editor.org/rfc/rfc791.txt'))
        self.assertEqual(out, app.PROJECT / 'results' / 'rfc791.txt')

    def test_existing_destination_is_never_overwritten(self):
        existing = os.path.join(self.tmp, 'exists.bin')
        Path(existing).write_text('keep')
        with self.assertRaises(app.UserError):
            app.Downloads.validate(dict(url='https://example.com/f', destination=existing))

    def test_download_success_reports_bytes_and_hash(self):
        import hashlib
        # serve an exact-length body for this case
        class Exact(BaseHTTPRequestHandler):
            def do_GET(inner):
                inner.send_response(200)
                inner.send_header('Content-Length', str(len(self.payload)))
                inner.end_headers()
                inner.wfile.write(self.payload)

            def log_message(inner, *a):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Exact)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        digest = hashlib.sha256(self.payload).hexdigest()
        code, body = self.post('/api/download', dict(mode='public', url='http://127.0.0.1:%d/f' % server.server_port,
                                                     destination=self.dest + '-ok', sha256=digest))
        self.assertEqual(code, 200, body)
        job = wait_for(lambda: (j := self.status()['download']) and j['state'] != 'running' and j)
        server.shutdown()
        server.server_close()
        self.assertEqual((job['state'], job['bytes'], job['sha256'], job['verified']),
                         ('done', len(self.payload), digest, True))
        self.assertEqual(Path(self.dest + '-ok').read_bytes(), self.payload)
        response, saved = self.fetch('GET', '/api/download/file?job=' + str(job['id']))
        self.assertEqual(response.status, 200)
        self.assertIn('attachment', response.getheader('Content-Disposition'))
        self.assertEqual(saved, self.payload)
        self.assertEqual(self.fetch('GET', '/api/download/file?job=' + str(job['id']), cookie=False)[0].status, 401)
        self.assertEqual(self.fetch('GET', '/api/download/file?job=999999')[0].status, 404)
        Path(self.dest + '-ok').write_bytes(b'changed after download')
        self.assertEqual(self.fetch('GET', '/api/download/file?job=' + str(job['id']))[0].status, 404)
        self.assertEqual(self.post('/api/download', dict(url='http://127.0.0.1:1/x', destination=self.dest + '-ok'))[0], 400)

    def test_checksum_mismatch_is_reported_and_leaves_no_file_or_temp(self):
        code, _ = self.post('/api/download', dict(url=self.base + '/short', destination=self.dest + '-bad',
                                                  sha256='0' * 64))
        self.assertEqual(code, 200)
        job = wait_for(lambda: (j := self.status()['download']) and j['state'] != 'running' and j)
        self.assertEqual(job['state'], 'error')
        self.assertFalse(os.path.exists(self.dest + '-bad'))
        self.assertEqual([n for n in os.listdir(self.tmp) if n.startswith('.pyvpn-download-')], [])

    def test_short_response_without_hash_is_rejected(self):
        code, _ = self.post('/api/download', dict(url=self.base + '/short', destination=self.dest + '-truncated'))
        self.assertEqual(code, 200)
        job = wait_for(lambda: (j := self.status()['download']) and j['state'] != 'running' and j)
        self.assertEqual(job['state'], 'error')
        self.assertIn('Incomplete download', job['message'])
        self.assertFalse(Path(self.dest + '-truncated').exists())
        self.assertEqual(self.fetch('GET', '/api/download/file?job=' + str(job['id']))[0].status, 404)

    def test_manifest_download_through_ui_api(self):
        import hashlib
        digest = hashlib.sha256(self.payload).hexdigest()
        payload = self.payload
        class Source(BaseHTTPRequestHandler):
            def do_GET(inner):
                if inner.path == '/manifest':
                    content = json.dumps(dict(name='sample.bin', bytes=len(payload), sha256=digest)).encode()
                else:
                    content = payload
                inner.send_response(200)
                inner.send_header('Content-Length', str(len(content)))
                inner.end_headers()
                inner.wfile.write(content)
            def log_message(inner, *args):
                pass
        source = ThreadingHTTPServer(('127.0.0.1', 0), Source)
        threading.Thread(target=source.serve_forever, daemon=True).start()
        try:
            code, body = self.post('/api/download', dict(mode='vpn', url='http://127.0.0.1:%d' % source.server_port,
                                                        destination=self.dest + '-manifest'))
            self.assertEqual(code, 200, body)
            job = wait_for(lambda: (j := self.status()['download']) and j['state'] != 'running' and j)
            self.assertEqual(job['state'], 'done')
            self.assertTrue(job['verified'])
            response, saved = self.fetch('GET', '/api/download/file?job=' + str(job['id']))
            self.assertEqual(response.status, 200)
            self.assertEqual(hashlib.sha256(saved).hexdigest(), digest)
        finally:
            source.shutdown()
            source.server_close()

    def test_cancel_removes_temporary_file(self):
        code, _ = self.post('/api/download', dict(url=self.base + '/slow', destination=self.dest + '-cancel'))
        self.assertEqual(code, 200)
        wait_for(lambda: [n for n in os.listdir(self.tmp) if n.startswith('.pyvpn-download-')])
        self.post('/api/download/cancel')
        job = wait_for(lambda: (j := self.status()['download']) and j['state'] != 'running' and j)
        self.assertEqual(job['state'], 'cancelled')
        self.assertEqual([n for n in os.listdir(self.tmp) if n.startswith('.pyvpn-download-')], [])


if __name__ == '__main__':
    unittest.main()
