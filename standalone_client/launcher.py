#!/usr/bin/env python3
"""Narrow privileged launcher for the UI client.

Run once as root (for example `sudo .venv/bin/python launcher.py`). It owns at most one
`vpn.py --mode client` process, accepts requests only from the invoking user's UID on a Unix
socket, and only ever runs the fixed project interpreter and script with validated options.
The PSK is handed to the backend through its environment and never appears in arguments,
status replies, or redacted log output.
"""
import argparse
import collections
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

PROJECT = Path(__file__).resolve().parent
DEFAULT_SOCKET = '/run/pyvpn-desktop/launcher.sock'
DEFAULT_STATE_DIR = '/var/lib/pyvpn-desktop'
STOP_TIMEOUT = 30.0
MAX_REQUEST = 8192
LOG_LINES = 2000
PSK_PATTERN = re.compile(r'(--psk[= ]|VPN_PSK=)\S+')
ERROR_PATTERN = re.compile(r'\bERROR\b|error:|Error|Traceback|Exception')


class RequestError(ValueError):
    """A rejected request; the message is safe to show to the user."""


def validate_start(request):
    """Return (server_ip, port, dashboard_port, internet, psk) or raise RequestError."""
    try:
        server = ipaddress.IPv4Address(str(request.get('server_ip', '')).strip())
    except ValueError:
        raise RequestError('Server address must be a numeric IPv4 address')
    if (server.is_unspecified or server.is_loopback or server.is_multicast
            or server.is_link_local or server.is_reserved or str(server) == '255.255.255.255'):
        raise RequestError('Server address is not a usable unicast IPv4 address')
    ports = []
    for field, label in (('port', 'Server port'), ('dashboard_port', 'Dashboard port')):
        value = request.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
            raise RequestError(label + ' must be a number from 1 to 65535')
        ports.append(value)
    internet = request.get('internet')
    if not isinstance(internet, bool):
        raise RequestError('internet must be true or false')
    psk = request.get('psk')
    if not isinstance(psk, str) or len(psk.encode()) < 16:
        raise RequestError('Shared secret must be at least 16 bytes')
    if len(psk.encode()) > 512 or '\0' in psk or '\n' in psk or '\r' in psk:
        raise RequestError('Shared secret contains unsupported characters or is too long')
    return str(server), ports[0], ports[1], internet, psk


def state_path(state_dir, server_ip):
    """One stable state file per server address; a PSK change surfaces the backend's own mismatch error."""
    return os.path.join(state_dir, 'client-' + server_ip.replace('.', '-') + '.sqlite')


def build_argv(python, vpn, state_dir, server_ip, port, dashboard_port, internet):
    argv = [python, vpn, '--mode', 'client', '--peer-ip', server_ip, '--port', str(port),
            '--dashboard-port', str(dashboard_port), '--state-file', state_path(state_dir, server_ip),
            '--verbose']
    if internet:
        argv.append('--internet')
    return argv


class Redactor:
    def __init__(self, secret=None):
        self.secret = secret

    def __call__(self, text):
        if self.secret:
            text = text.replace(self.secret, '[redacted]')
        return PSK_PATTERN.sub(r'\1[redacted]', text)


class Backend:
    """Owns one backend process: start, graceful stop, exit status, and a bounded redacted log."""

    def __init__(self, python, vpn, state_dir, cwd, stop_timeout=STOP_TIMEOUT):
        self.python, self.vpn, self.state_dir, self.cwd = python, vpn, state_dir, cwd
        self.stop_timeout = stop_timeout
        self.extra_env = {}  # test hook only; the real launcher never sets it
        self.lock = threading.RLock()
        self.logs = collections.deque(maxlen=LOG_LINES)
        self.seq = 0
        self.reset()

    def reset(self):
        self.proc = None
        self.state = 'idle'
        self.exit_code = None
        self.started_at = None
        self.stop_requested = False
        self.stopping_since = None
        self.cleanup_timeout = False
        self.info = {}

    def log(self, line):
        with self.lock:
            self.seq += 1
            self.logs.append((self.seq, line))

    def prepare_state_dir(self):
        os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        info = os.stat(self.state_dir)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise RequestError('State directory %s must belong to the launcher user with mode 0700' % self.state_dir)

    def start(self, request):
        server, port, dashboard_port, internet, psk = validate_start(request)
        with self.lock:
            if self.state in ('running', 'stopping'):
                raise RequestError('A VPN client process is already running; disconnect it first')
            self.prepare_state_dir()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                # Match the backend's HTTP server: lingering TIME_WAIT sockets from stats polling must not count as busy.
                probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    probe.bind(('127.0.0.1', dashboard_port))
                except OSError as exc:
                    raise RequestError('Dashboard port %d is not available (%s). Another process may be using it.'
                                       % (dashboard_port, exc.strerror))
            argv = build_argv(self.python, self.vpn, self.state_dir, server, port, dashboard_port, internet)
            env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'VPN_PSK': psk, 'LANG': 'C.UTF-8',
                   'PYTHONUNBUFFERED': '1', 'PYTHONDONTWRITEBYTECODE': '1', **self.extra_env}
            self.logs.clear()
            self.reset()
            self.log('[launcher] starting backend for %s:%d (internet routing %s)'
                     % (server, port, 'on' if internet else 'off'))
            try:
                self.proc = subprocess.Popen(argv, cwd=self.cwd, env=env, shell=False, stdin=subprocess.DEVNULL,
                                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                             start_new_session=True)
            except OSError as exc:
                self.state = 'exited'
                self.exit_code = 127
                raise RequestError('Could not start backend: %s' % exc.strerror)
            self.state = 'running'
            self.started_at = time.time()
            self.info = dict(server_ip=server, port=port, dashboard_port=dashboard_port, internet=internet)
            redact = Redactor(psk)
            threading.Thread(target=self.drain, args=(self.proc, redact), daemon=True).start()
            threading.Thread(target=self.wait, args=(self.proc,), daemon=True).start()

    def drain(self, proc, redact):
        for raw in proc.stderr:
            line = redact(raw.decode(errors='replace').rstrip())
            if line:
                self.log(line)
        proc.stderr.close()

    def wait(self, proc):
        code = proc.wait()
        with self.lock:
            if self.proc is not proc:
                return
            self.exit_code = code
            self.state = 'exited'
            self.cleanup_timeout = False
            self.log('[launcher] backend exited with code %s' % code)

    def stop(self):
        """Request graceful shutdown (SIGTERM). Never escalates to SIGKILL."""
        with self.lock:
            if self.state not in ('running', 'stopping'):
                return
            self.stop_requested = True
            if self.state == 'running':
                self.state = 'stopping'
                self.stopping_since = time.time()
                self.log('[launcher] disconnect requested; waiting for backend cleanup')
                threading.Thread(target=self.watch_stop, args=(self.proc,), daemon=True).start()
            else:
                self.log('[launcher] disconnect requested again; resending SIGTERM')
                self.stopping_since = time.time()
                self.cleanup_timeout = False
                threading.Thread(target=self.watch_stop, args=(self.proc,), daemon=True).start()
            try:
                self.proc.send_signal(signal.SIGTERM)
            except ProcessLookupError:
                pass

    def watch_stop(self, proc):
        try:
            proc.wait(self.stop_timeout)
        except subprocess.TimeoutExpired:
            with self.lock:
                if self.proc is proc and self.state == 'stopping':
                    self.cleanup_timeout = True
                    self.log('[launcher] ERROR backend did not finish cleanup within %ds; it was not force-killed. '
                             'Check routes with `ip route` and retry Disconnect.' % self.stop_timeout)

    def status(self):
        with self.lock:
            last_error = None
            for _, line in reversed(self.logs):
                if not line.startswith('[launcher]') and ERROR_PATTERN.search(line):
                    last_error = line
                    break
            return dict(state=self.state, pid=self.proc.pid if self.proc else None, exit_code=self.exit_code,
                        started_at=self.started_at, stop_requested=self.stop_requested,
                        cleanup_timeout=self.cleanup_timeout, last_error=last_error, log_seq=self.seq,
                        **self.info)

    def read_logs(self, since):
        with self.lock:
            return [dict(seq=seq, line=line) for seq, line in self.logs if seq > since], self.seq

    def alive(self):
        with self.lock:
            return self.state in ('running', 'stopping')


def peer_uid(conn):
    if hasattr(socket, 'SO_PEERCRED'):
        _, uid, _ = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
        return uid
    return None


def handle(conn, backend, allowed_uid):
    with conn:
        conn.settimeout(5)
        try:
            uid = peer_uid(conn)
            if allowed_uid is not None and uid is not None and uid not in (allowed_uid, 0):
                reply = dict(ok=False, error='Not authorized')
            else:
                data = b''
                while not data.endswith(b'\n') and len(data) <= MAX_REQUEST:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                if len(data) > MAX_REQUEST:
                    raise RequestError('Request too large')
                request = json.loads(data.decode())
                reply = dispatch(backend, request)
        except RequestError as exc:
            reply = dict(ok=False, error=str(exc))
        except (ValueError, UnicodeDecodeError):
            reply = dict(ok=False, error='Malformed request')
        except OSError:
            return
        try:
            conn.sendall(json.dumps(reply).encode() + b'\n')
        except OSError:
            pass


def dispatch(backend, request):
    if not isinstance(request, dict):
        raise RequestError('Malformed request')
    op = request.get('op')
    if op == 'status':
        return dict(ok=True, status=backend.status())
    if op == 'start':
        backend.start(request)
        return dict(ok=True, status=backend.status())
    if op == 'stop':
        backend.stop()
        return dict(ok=True, status=backend.status())
    if op == 'logs':
        since = request.get('since', 0)
        if isinstance(since, bool) or not isinstance(since, int) or since < 0:
            raise RequestError('Invalid log cursor')
        lines, seq = backend.read_logs(since)
        return dict(ok=True, lines=lines, seq=seq)
    raise RequestError('Unknown operation')


def bind_socket(path, uid):
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o755, exist_ok=True)
    if os.path.lexists(path):
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(1)
            probe.connect(path)
            raise SystemExit('Another launcher is already listening on ' + path)
        except OSError:
            os.unlink(path)
        finally:
            probe.close()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o177)
    try:
        server.bind(path)
    finally:
        os.umask(old)
    if uid is not None:
        os.chown(path, uid, -1)
    os.chmod(path, 0o600)
    server.listen(8)
    return server


def private_group(gid, uid):
    """True if `uid` is the only member of group `gid` (Ubuntu-style user-private group)."""
    import grp
    import pwd
    try:
        user, group = pwd.getpwuid(uid), grp.getgrgid(gid)
    except KeyError:
        return False
    if user.pw_gid != gid or any(name != user.pw_name for name in group.gr_mem):
        return False
    return all(entry.pw_uid == uid for entry in pwd.getpwall() if entry.pw_gid == gid)


def check_trusted(paths, uid, strict):
    """The launcher runs these files as root, so they must not be writable by other users.

    Group-write is fine when the group is the invoking user's private group (the default umask 002 on
    Ubuntu/Debian makes every clone group-writable): nobody gains write access they did not already have.
    """
    for path in paths:
        info = os.stat(path)
        if info.st_mode & 0o002 or (info.st_mode & 0o020 and not private_group(info.st_gid, uid)):
            raise SystemExit('Refusing to run: %s is writable by users other than its owner. '
                             'Run `chmod go-w` on it, or keep it in a private group.' % path)
        if info.st_uid not in (0, uid):
            raise SystemExit('Refusing to run: %s belongs to an unexpected user' % path)
        if strict and info.st_uid != 0:
            raise SystemExit('--strict requires %s to be owned by root' % path)
        if info.st_uid != 0:
            print('warning: %s is owned by a non-root user; that user can alter code this launcher runs as '
                  'root. Use --strict with a root-owned install for a persistent service.' % path,
                  file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', default=DEFAULT_SOCKET)
    parser.add_argument('--state-dir', default=DEFAULT_STATE_DIR)
    parser.add_argument('--uid', type=int, help='Local user allowed to use the launcher (default: SUDO_UID/PKEXEC_UID)')
    parser.add_argument('--strict', action='store_true', help='Require root-owned backend files')
    args = parser.parse_args()
    if sys.platform != 'linux':
        raise SystemExit('The VPN backend needs Linux TUN support; the launcher runs only on Linux')
    if os.geteuid() != 0:
        raise SystemExit('The launcher must run as root, e.g. sudo .venv/bin/python launcher.py')
    uid = args.uid if args.uid is not None else int(os.environ.get('SUDO_UID') or os.environ.get('PKEXEC_UID') or 0)
    if uid <= 0:
        raise SystemExit('Cannot tell which user may use the launcher; start it with sudo or pass --uid')
    python = PROJECT / '.venv' / 'bin' / 'python'
    vpn = PROJECT / 'vpn.py'
    if not os.access(python, os.X_OK) or not vpn.is_file():
        raise SystemExit('Missing %s or %s; create the virtualenv first (see ui/README.md)' % (python, vpn))
    check_trusted([str(PROJECT), str(vpn), str(PROJECT / 'internet.py'), str(PROJECT / 'multi_server.py'),
                   str(python)], uid, args.strict)
    backend = Backend(str(python), str(vpn), args.state_dir, str(PROJECT))
    server = bind_socket(args.socket, uid)
    done = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: done.set())
    server.settimeout(0.5)
    print('Launcher ready for uid %d on %s. Press Ctrl+C to stop it (this also disconnects).' % (uid, args.socket),
          flush=True)
    try:
        while not done.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle, args=(conn, backend, uid), daemon=True).start()
    finally:
        server.close()
        if backend.alive():
            print('Stopping backend and waiting for cleanup...', flush=True)
            backend.stop()
            deadline = time.monotonic() + backend.stop_timeout + 5
            while backend.alive() and time.monotonic() < deadline:
                time.sleep(0.2)
            if backend.alive():
                print('Backend still running; cleanup incomplete. Not force-killed.', file=sys.stderr)
        try:
            os.unlink(args.socket)
        except OSError:
            pass


if __name__ == '__main__':
    main()
