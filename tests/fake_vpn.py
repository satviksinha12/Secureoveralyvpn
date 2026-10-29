"""Stand-in for `vpn.py --mode client` used by the UI tests (no TUN, root, or network needed).

It accepts the same options, logs to stderr, serves /stats on --dashboard-port, and exits on SIGTERM.
FAKE_MODE=fail exits with an error; FAKE_MODE=leak logs the PSK to prove the launcher redacts it.
"""
import argparse
import json
import logging
import os
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

parser = argparse.ArgumentParser()
parser.add_argument('--mode')
parser.add_argument('--peer-ip')
parser.add_argument('--port', type=int, default=5555)
parser.add_argument('--dashboard-port', type=int, default=5000)
parser.add_argument('--state-file')
parser.add_argument('--internet', action='store_true')
parser.add_argument('--verbose', action='store_true')
args = parser.parse_args()
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')
LOG = logging.getLogger('vpn')
mode = os.environ.get('FAKE_MODE', '')
psk = os.environ.get('VPN_PSK', '')

if mode == 'fail':
    LOG.error('State belongs to another mode, peer, or PSK; use a new state file')
    raise SystemExit(1)
if mode == 'leak':
    LOG.info('debug: psk is %s and VPN_PSK=%s', psk, psk)

stats = dict(bytes_sent=0, bytes_received=0, packets_sent=0, packets_received=0, dropped_auth=0,
             dropped_replay=0, dropped_malformed=0, last_seen=None, connection_state='connecting', reconnects=0)
stop = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: stop.set())
signal.signal(signal.SIGINT, lambda *_: stop.set())


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(stats).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


http = ThreadingHTTPServer(('127.0.0.1', args.dashboard_port), Handler)
threading.Thread(target=http.serve_forever, daemon=True).start()
LOG.info('Waiting for authenticated peer %s:%s', args.peer_ip, args.port)
time.sleep(0.3)
stats.update(connection_state='connected', internet_ipv4=args.internet, last_seen=time.time())
LOG.info('Tunnel ready: tun0 10.8.0.7; dashboard 127.0.0.1:%s', args.dashboard_port)
while not stop.wait(0.2):
    stats['bytes_sent'] += 100
    stats['packets_sent'] += 1
    stats['last_seen'] = time.time()
LOG.info('Final stats: %s', stats)
http.shutdown()
