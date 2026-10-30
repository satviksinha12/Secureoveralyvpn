#!/usr/bin/env python3
"""Unprivileged local web UI for the Secure Overlay VPN client.

Serves the static UI and a small JSON API on loopback. It talks to the privileged launcher
(ui/launcher.py) for Connect/Disconnect, polls the backend's own /stats API, looks up the IPv4
exit address, and runs file_transfer.py for downloads. The standard library is all it needs.
"""
import argparse
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit, quote
from urllib.request import build_opener, ProxyHandler

PROJECT = Path(__file__).resolve().parent.parent
STATIC = Path(__file__).resolve().parent / 'static'
sys.path.insert(0, str(PROJECT))
from file_transfer import urlopen as ipv4_urlopen  # noqa: E402  IPv4-only, no proxies, verified HTTPS

DEFAULT_SOCKET = '/run/pyvpn-ui/launcher.sock'
IP_SERVICE = 'https://api.ipify.org'
COOKIE = 'pyvpn_ui'
MAX_BODY = 8192
STATS_KEYS = ('bytes_sent', 'bytes_received', 'packets_sent', 'packets_received',
              'dropped_auth', 'dropped_replay', 'dropped_malformed')
ACTIVE = ('starting', 'connecting', 'connected', 'reconnecting')
RESULT = re.compile(r'(PASS|Downloaded[^:]*): received (\d+) bytes; SHA-256 ([0-9a-f]{64})')
TUN_ADDRESS = re.compile(r'Tunnel ready: \S+ (\d+\.\d+\.\d+\.\d+)')
SECRET_ARGS = re.compile(r'(--psk[= ]|VPN_PSK=)\S+')
STATIC_FILES = {'/': ('index.html', 'text/html; charset=utf-8'),
                '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
                '/app.css': ('app.css', 'text/css; charset=utf-8'),
                '/favicon.svg': ('favicon.svg', 'image/svg+xml')}


class UserError(ValueError):
    """An error whose message is safe and useful to show in the UI."""


class LauncherUnavailable(Exception):
    pass


class LauncherClient:
    def __init__(self, path):
        self.path = path

    def call(self, **request):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5)
        try:
            sock.connect(self.path)
            sock.sendall(json.dumps(request).encode() + b'\n')
            data = b''
            while not data.endswith(b'\n'):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
            reply = json.loads(data.decode())
        except (OSError, ValueError) as exc:
            raise LauncherUnavailable(str(exc))
        finally:
            sock.close()
        if not reply.get('ok'):
            raise UserError(reply.get('error') or 'Launcher rejected the request')
        return reply


class LocalFetcher:
    """Reads the backend's own stats API on loopback, bypassing any proxy."""
    opener = build_opener(ProxyHandler({}))

    @classmethod
    def stats(cls, port):
        try:
            with cls.opener.open('http://127.0.0.1:%d/stats' % port, timeout=1.5) as response:
                data = json.load(response)
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict) or not all(isinstance(data.get(k), (int, float)) for k in STATS_KEYS):
            return None
        return data


def tun_address(tun='tun0'):
    """Read-only query of the interface's actual IPv4 address."""
    if not shutil.which('ip'):
        return None
    try:
        out = subprocess.run(['ip', '-j', '-4', 'addr', 'show', 'dev', tun], capture_output=True, text=True,
                             timeout=2).stdout
        for entry in json.loads(out or '[]'):
            for info in entry.get('addr_info', []):
                if info.get('local', '').startswith('10.8.0.'):
                    return info['local']
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return None


class ExitIP:
    """Fresh IPv4-only public address lookups, recorded before and after connecting."""

    def __init__(self, service):
        self.service = service
        self.lock = threading.Lock()
        self.baseline = dict(state='idle')
        self.current = dict(state='idle')
        self.key = None

    @staticmethod
    def fetch(service, timeout):
        try:
            with ipv4_urlopen(service, timeout=timeout) as response:
                text = response.read(64).decode(errors='replace').strip()
            return dict(state='ok', ip=str(ipaddress.IPv4Address(text)), at=time.time())
        except ValueError:
            return dict(state='error', error='Lookup service returned an unexpected answer', at=time.time())
        except OSError as exc:
            return dict(state='error', error='Exit IP lookup unavailable: %s' % (getattr(exc, 'reason', exc),),
                        at=time.time())

    def run_baseline(self, timeout=6):
        result = self.fetch(self.service, timeout)
        with self.lock:
            self.baseline = result
            self.current = dict(state='idle')

    def run_current(self, delay=0.0, retries=1):
        with self.lock:
            if self.current.get('state') == 'loading':
                return
            self.current = dict(state='loading')
        def work():
            time.sleep(delay)
            for attempt in range(retries + 1):
                result = self.fetch(self.service, 15)
                if result['state'] == 'ok' or attempt == retries:
                    break
                time.sleep(3)
            with self.lock:
                self.current = result
        threading.Thread(target=work, daemon=True).start()

    def run_baseline_async(self):
        with self.lock:
            if self.baseline.get('state') == 'loading':
                return
            self.baseline = dict(state='loading')
        def work():
            result = self.fetch(self.service, 15)
            with self.lock:
                self.baseline = result
        threading.Thread(target=work, daemon=True).start()

    def observe(self, status, key):
        """Start one fresh lookup per connection; discard stale results when not connected."""
        if status == 'connected':
            if key != self.key:
                self.key = key
                self.run_current(delay=1.5)
        else:
            self.key = None
            with self.lock:
                if self.current.get('state') != 'idle' and status != 'reconnecting':
                    self.current = dict(state='idle')

    def snapshot(self):
        with self.lock:
            return dict(baseline=dict(self.baseline), current=dict(self.current))


class Downloads:
    """Runs file_transfer.py as an ordinary unprivileged process, one at a time."""

    def __init__(self):
        self.lock = threading.Lock()
        self.job = None
        self.proc = None
        self.counter = 0

    @staticmethod
    def validate(request):
        mode = request.get('mode', 'public')
        if mode not in ('public', 'vpn'):
            raise UserError('Unknown download mode')
        url = str(request.get('url', '')).strip()
        parts = urlsplit(url)
        if (parts.scheme not in ('http', 'https') or not parts.hostname or re.search(r'[\s\x00-\x1f]', url)
                or parts.username or parts.password):
            raise UserError('Enter an http(s) URL without embedded credentials')
        if mode == 'vpn' and not url.startswith('http://'):
            raise UserError('VPN server transfers use http:// over the tunnel, e.g. http://10.8.0.1:8000')
        digest = str(request.get('sha256', '')).strip().lower()
        if digest and not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise UserError('Expected SHA-256 must be 64 hexadecimal characters')
        if digest and mode == 'vpn':
            raise UserError('Server transfers are verified against the server manifest; leave SHA-256 empty')
        dest = str(request.get('destination', '')).strip()
        if not dest:
            name = os.path.basename(parts.path.rstrip('/')) or 'download.bin'
            dest = re.sub(r'[^A-Za-z0-9._-]', '_', name).lstrip('.') or 'download.bin'
        if '\0' in dest:
            raise UserError('Invalid destination')
        out = Path(dest).expanduser()
        if not out.is_absolute():
            out = PROJECT / 'results' / out
        out = Path(os.path.normpath(out))
        if out.is_dir():
            raise UserError('Destination is a directory; enter a filename')
        if out.exists():
            raise UserError('Destination already exists; choose another filename (downloads never overwrite)')
        return mode, url, out, digest

    def start(self, request):
        mode, url, out, digest = self.validate(request)
        with self.lock:
            if self.job and self.job['state'] == 'running':
                raise UserError('A download is already running')
            out.parent.mkdir(parents=True, exist_ok=True)
            cmd = [sys.executable, str(PROJECT / 'file_transfer.py'), 'download' if mode == 'public' else 'receive',
                   '--url', url, '--output', str(out)]
            if digest:
                cmd += ['--sha256', digest]
            env = {k: v for k, v in os.environ.items() if k not in ('VPN_PSK', 'PYTHONPATH', 'PYTHONHOME')}
            env['PYTHONDONTWRITEBYTECODE'] = '1'
            proc = subprocess.Popen(cmd, cwd=str(PROJECT), env=env, shell=False, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                    start_new_session=True)
            self.counter += 1
            self.proc = proc
            self.job = dict(id=self.counter, state='running', url=url, output=str(out), started=time.time(),
                            expected_sha256=digest or None, mode=mode, cancel_requested=False)
            threading.Thread(target=self.finish, args=(self.job, proc), daemon=True).start()
            return self.job['id']

    def finish(self, job, proc):
        stdout, stderr = proc.communicate()
        with self.lock:
            job['exit_code'] = proc.returncode
            job['finished'] = time.time()
            match = RESULT.search(stdout or '')
            if proc.returncode == 0 and match:
                try:
                    info = os.stat(job['output'], follow_symlinks=False)
                except OSError:
                    job.update(state='error', message='Downloaded file is no longer available')
                    return
                job.update(state='done', verified=match.group(1) == 'PASS', bytes=int(match.group(2)),
                           sha256=match.group(3), file_identity=[info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns])
                job['message'] = ('Checksum verified' if job['verified']
                                  else 'Downloaded; no expected checksum was supplied, so content is not independently verified')
            elif job['cancel_requested']:
                job['state'] = 'cancelled'
                job['message'] = 'Download cancelled'
            else:
                job['state'] = 'error'
                text = (stderr or stdout or '').strip().splitlines()
                job['message'] = SECRET_ARGS.sub(r'\1[redacted]', text[-1]) if text else 'Download failed (exit code %s)' % proc.returncode

    def open_completed(self, job_id):
        """Open only this app's latest completed result, never an arbitrary path."""
        with self.lock:
            if not self.job or self.job['id'] != job_id or self.job['state'] != 'done':
                raise UserError('Completed download not found; finish a download first')
            job = dict(self.job)
        try:
            fd = os.open(job['output'], os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
            source = os.fdopen(fd, 'rb')
            info = os.fstat(source.fileno())
            identity = [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns]
            if identity != job['file_identity']:
                source.close()
                raise UserError('Downloaded file changed; download it again before saving')
            return source, Path(job['output']).name, info.st_size
        except OSError:
            raise UserError('Downloaded file is no longer available') from None

    def cancel(self):
        """SIGINT lets the tool delete its temporary file; escalate to SIGTERM only if it hangs."""
        with self.lock:
            job, proc = self.job, self.proc
            if not job or job['state'] != 'running':
                return
            if proc.poll() is not None:
                return
            job['cancel_requested'] = True
        try:
            proc.send_signal(signal.SIGINT)
        except ProcessLookupError:
            return
        def escalate():
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.terminate()
        threading.Thread(target=escalate, daemon=True).start()

    def snapshot(self):
        with self.lock:
            return dict(self.job) if self.job else None


class UIState:
    def __init__(self, launcher, dashboard_port, ip_service):
        self.launcher = launcher
        self.dashboard_port = dashboard_port
        self.exit_ip = ExitIP(ip_service)
        self.downloads = Downloads()
        self.lock = threading.Lock()
        self.logs_cache = []
        self.log_seq = 0
        self.tunnel_ip_from_log = None

    def launcher_status(self):
        try:
            return self.launcher.call(op='status')['status'], None
        except LauncherUnavailable as exc:
            return None, str(exc)

    def pull_logs(self):
        try:
            reply = self.launcher.call(op='logs', since=self.log_seq)
        except (LauncherUnavailable, UserError):
            return
        with self.lock:
            if reply['seq'] < self.log_seq:  # backend restarted; sequence continues, so this is defensive only
                self.logs_cache = []
            for entry in reply['lines']:
                self.logs_cache.append(entry)
                match = TUN_ADDRESS.search(entry['line'])
                if match:
                    self.tunnel_ip_from_log = match.group(1)
            self.logs_cache = self.logs_cache[-1000:]
            self.log_seq = reply['seq']

    def status(self):
        proc, launcher_error = self.launcher_status()
        if proc:
            self.dashboard_port = proc.get('dashboard_port', self.dashboard_port)
        stats = LocalFetcher.stats(self.dashboard_port)
        managed = proc is not None
        result = dict(managed=managed, mode='managed' if managed else 'none', stats=None, assigned_ip=None,
                      server_ip=None, internet=None, exit_code=None, last_error=None, pid=None, detail='',
                      launcher_error=launcher_error)
        key = None
        if proc:
            result.update(server_ip=proc.get('server_ip'), internet=proc.get('internet'), pid=proc.get('pid'))
            state = proc['state']
            if state == 'running':
                if stats:
                    status = stats.get('connection_state') if stats.get('connection_state') in ACTIVE else 'connecting'
                    result['stats'] = stats
                    key = (proc.get('pid'), stats.get('reconnects'))
                else:
                    status = 'starting'
                    result['detail'] = 'Starting the VPN backend and waiting for its dashboard'
            elif state == 'stopping':
                status = 'disconnecting'
                result['detail'] = ('Cleanup is taking longer than expected; the process was not force-killed'
                                    if proc.get('cleanup_timeout') else 'Waiting for the backend to restore routes')
            elif state == 'exited':
                code = proc.get('exit_code')
                if code == 0:
                    status = 'disconnected'
                else:
                    status = 'error'
                    result['exit_code'] = code
                    result['last_error'] = proc.get('last_error') or 'Backend exited with code %s' % code
            else:
                status = 'disconnected'
            if proc.get('cleanup_timeout'):
                result['last_error'] = 'Cleanup did not finish in time. Check `ip route`, then press Disconnect again.'
            self.pull_logs()
        elif stats:
            result['mode'] = 'external'
            status = stats.get('connection_state') if stats.get('connection_state') in ACTIVE else 'connecting'
            result['stats'] = stats
            result['detail'] = 'Monitoring a backend that was started outside this UI (read-only)'
            key = ('external', stats.get('reconnects'))
        else:
            status = 'disconnected'
        result['status'] = status
        if status == 'connected':
            result['assigned_ip'] = tun_address() or self.tunnel_ip_from_log
        self.exit_ip.observe(status, key)
        result['exit_ip'] = self.exit_ip.snapshot()
        result['download'] = self.downloads.snapshot()
        result['log_seq'] = self.log_seq
        result['dashboard_port'] = self.dashboard_port
        return result

    def connect(self, request):
        psk = request.get('psk')
        if not isinstance(psk, str):
            raise UserError('Shared secret must be at least 16 bytes')
        body = dict(op='start', server_ip=request.get('server_ip'), psk=psk, internet=request.get('internet'),
                    port=request.get('port', 5555), dashboard_port=request.get('dashboard_port', 5000))
        proc, _ = self.launcher_status()
        if proc is None:
            raise UserError('The privileged launcher is not running, so Connect is not managed. '
                            'Start it with: sudo .venv/bin/python ui/launcher.py')
        if proc['state'] in ('running', 'stopping'):
            raise UserError('A connection is already active')
        try:
            ipaddress.IPv4Address(str(body['server_ip']).strip())
        except ValueError:
            raise UserError('Server address must be a numeric IPv4 address')
        if len(psk.encode()) < 16:
            raise UserError('Shared secret must be at least 16 bytes')
        self.exit_ip.run_baseline()  # record the pre-connection address before routes change
        try:
            self.launcher.call(**body)
        except LauncherUnavailable:
            raise UserError('Lost contact with the launcher')
        with self.lock:
            self.logs_cache = []
            self.tunnel_ip_from_log = None
            self.log_seq = 0

    def disconnect(self):
        try:
            self.launcher.call(op='stop')
        except LauncherUnavailable:
            raise UserError('The launcher is not running; there is no managed connection to stop')

    def logs(self, since):
        with self.lock:
            return dict(lines=[e for e in self.logs_cache if e['seq'] > since], seq=self.log_seq)


def make_handler(ui, token, allowed_hosts):
    class Handler(BaseHTTPRequestHandler):
        server_version = 'PyVPNUI'
        protocol_version = 'HTTP/1.1'

        def log_message(self, *args):
            pass  # request lines and bodies may include sensitive input; keep the console quiet

        def send(self, code, body, kind='application/json', extra=()):
            self.send_response(code)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Content-Security-Policy',
                             "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            for name, value in extra:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def reply(self, code, payload):
            self.send(code, json.dumps(payload).encode())

        def host_ok(self):
            return self.headers.get('Host', '') in allowed_hosts

        def authed(self):
            cookies = dict(c.strip().split('=', 1) for c in self.headers.get('Cookie', '').split(';') if '=' in c)
            return hmac.compare_digest(cookies.get(COOKIE, ''), token)

        def do_GET(self):
            if not self.host_ok():
                return self.reply(403, dict(error='Bad host'))
            parts = urlsplit(self.path)
            supplied = parse_qs(parts.query).get('token', [''])[0]
            if parts.path == '/' and supplied:
                if hmac.compare_digest(supplied, token):
                    return self.send(303, b'', extra=[
                        ('Location', '/'), ('Set-Cookie', '%s=%s; HttpOnly; SameSite=Strict; Path=/' % (COOKIE, token))])
                return self.reply(403, dict(error='Invalid token'))
            if not self.authed():
                return self.send(401, b'Open the URL printed by ui/app.py in your terminal to start a session.\n',
                                 'text/plain; charset=utf-8')
            if parts.path in STATIC_FILES:
                name, kind = STATIC_FILES[parts.path]
                return self.send(200, (STATIC / name).read_bytes(), kind)
            if parts.path == '/api/download/file':
                try:
                    job_id = int(parse_qs(parts.query).get('job', ['0'])[0])
                    source, filename, length = ui.downloads.open_completed(job_id)
                except (ValueError, UserError) as exc:
                    return self.reply(404, dict(error=str(exc)))
                with source:
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/octet-stream')
                    self.send_header('Content-Length', str(length))
                    self.send_header('Content-Disposition', "attachment; filename=download.bin; filename*=UTF-8''" + quote(filename, safe=''))
                    self.send_header('Cache-Control', 'no-store')
                    self.send_header('X-Content-Type-Options', 'nosniff')
                    self.end_headers()
                    try:
                        shutil.copyfileobj(source, self.wfile, length=256 * 1024)
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                return
            if parts.path == '/api/status':
                return self.reply(200, ui.status())
            if parts.path == '/api/logs':
                try:
                    since = int(parse_qs(parts.query).get('since', ['0'])[0])
                except ValueError:
                    since = 0
                return self.reply(200, ui.logs(max(since, 0)))
            self.reply(404, dict(error='Not found'))

        def do_POST(self):
            if not self.host_ok() or not self.authed():
                return self.reply(403, dict(error='Not authorized'))
            origin = self.headers.get('Origin')
            if (origin and urlsplit(origin).netloc not in allowed_hosts) or self.headers.get('X-PyVPN-UI') != '1':
                return self.reply(403, dict(error='Cross-site request rejected'))
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 <= length <= MAX_BODY:
                    return self.reply(413, dict(error='Request too large'))
                raw = self.rfile.read(length)
                request = json.loads(raw.decode() or '{}')
                if not isinstance(request, dict):
                    raise ValueError
            except (ValueError, UnicodeDecodeError):
                return self.reply(400, dict(error='Malformed request'))
            path = urlsplit(self.path).path
            try:
                if path == '/api/connect':
                    ui.connect(request)
                elif path == '/api/disconnect':
                    ui.disconnect()
                elif path == '/api/exit-ip':
                    status = ui.status()
                    if status['status'] == 'connected':
                        ui.exit_ip.run_current()
                    elif status['status'] in ('disconnected', 'error'):
                        ui.exit_ip.run_baseline_async()
                    else:
                        raise UserError('Exit IP can be checked once connected or while disconnected')
                elif path == '/api/download':
                    ui.downloads.start(request)
                elif path == '/api/download/cancel':
                    ui.downloads.cancel()
                else:
                    return self.reply(404, dict(error='Not found'))
            except UserError as exc:
                return self.reply(400, dict(ok=False, error=str(exc)))
            except OSError as exc:
                return self.reply(500, dict(ok=False, error='Operation failed: %s' % exc.strerror))
            self.reply(200, dict(ok=True))
    return Handler


def start_server_and_browser(server, url, open_browser=True):
    """Serve first; desktop browser helpers must never block the local UI."""
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if open_browser:
        def launch():
            import webbrowser
            try:
                if not webbrowser.open(url):
                    print('Browser did not open automatically; use the URL printed above.', flush=True)
            except Exception:
                print('Browser launch failed; use the URL printed above.', flush=True)
        threading.Thread(target=launch, daemon=True).start()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='127.0.0.1', help='Loopback only unless you add your own protection')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--launcher-socket', default=DEFAULT_SOCKET)
    parser.add_argument('--dashboard-port', type=int, default=5000, help='Backend stats port to monitor')
    parser.add_argument('--ip-service', default=IP_SERVICE, help='IPv4 address lookup endpoint')
    parser.add_argument('--keep-connection', action='store_true',
                        help='Leave a connection started here running when this app exits')
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    if args.host not in ('127.0.0.1', 'localhost', '::1'):
        parser.error('Refusing to bind the control UI to a non-loopback address')
    ui = UIState(LauncherClient(args.launcher_socket), args.dashboard_port, args.ip_service)
    token = secrets.token_urlsafe(32)
    allowed = {'127.0.0.1:%d' % args.port, 'localhost:%d' % args.port}
    server = ThreadingHTTPServer((args.host, args.port), make_handler(ui, token, allowed))
    server.daemon_threads = True
    url = 'http://127.0.0.1:%d/?token=%s' % (args.port, token)
    print('Secure Overlay VPN UI: %s' % url, flush=True)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    start_server_and_browser(server, url, open_browser=not args.no_browser)
    try:
        stop.wait()
    finally:
        server.shutdown()
        server.server_close()
        proc, _ = ui.launcher_status()
        if proc and proc['state'] in ('running', 'stopping'):
            if args.keep_connection:
                print('Leaving the VPN connected. Stop it later from this UI or by stopping the launcher.', flush=True)
            else:
                print('Disconnecting before exit...', flush=True)
                ui.disconnect()
                deadline = time.monotonic() + 40
                while time.monotonic() < deadline:
                    proc, _ = ui.launcher_status()
                    if not proc or proc['state'] not in ('running', 'stopping'):
                        break
                    time.sleep(0.5)
                else:
                    print('Backend cleanup did not finish; it is still owned by the launcher.', file=sys.stderr)


if __name__ == '__main__':
    main()
