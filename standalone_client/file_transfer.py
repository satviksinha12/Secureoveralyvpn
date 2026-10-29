#!/usr/bin/env python3
"""Serve or receive one file over the VPN, checking its SHA-256 digest."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
from http.client import HTTPConnection, HTTPSConnection
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import build_opener, ProxyHandler, HTTPHandler, HTTPSHandler

def connect_ipv4(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
    last_error = None
    for entry in socket.getaddrinfo(address[0], address[1], socket.AF_INET, socket.SOCK_STREAM):
        try:
            return socket.create_connection((entry[4][0], entry[4][1]), timeout, source_address)
        except OSError as exc:
            last_error = exc
    if last_error:
        raise last_error
    raise OSError('No IPv4 address for download host')


class IPv4HTTPConnection(HTTPConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = connect_ipv4


class IPv4HTTPSConnection(HTTPSConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._create_connection = connect_ipv4


class IPv4HTTPHandler(HTTPHandler):
    def http_open(self, request):
        return self.do_open(IPv4HTTPConnection, request)


class IPv4HTTPSHandler(HTTPSHandler):
    def https_open(self, request):
        return self.do_open(IPv4HTTPSConnection, request, context=self._context)


# Connect directly over IPv4, preserving normal HTTPS certificate verification.
urlopen = build_opener(ProxyHandler({}), IPv4HTTPHandler(), IPv4HTTPSHandler()).open


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def serve(path, bind, port):
    path = Path(path).resolve(strict=True)
    if not path.is_file():
        raise ValueError('Select a regular file')
    manifest = json.dumps(dict(name=path.name, bytes=path.stat().st_size, sha256=digest(path))).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/manifest':
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(manifest)))
                self.end_headers()
                self.wfile.write(manifest)
            elif self.path == '/file':
                with path.open('rb') as source:
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/octet-stream')
                    self.send_header('Content-Length', str(os.fstat(source.fileno()).st_size))
                    self.end_headers()
                    shutil.copyfileobj(source, self.wfile)
            else:
                self.send_error(404)

    with ThreadingHTTPServer((bind, port), Handler) as http:
        print(f'Serving {path.name} at http://{bind}:{http.server_port}; SHA-256 {digest(path)}', flush=True)
        http.serve_forever()


def download(url, output, expected_hash=None, expected_size=None):
    output = Path(output)
    if output.exists():
        raise ValueError('Output already exists; choose another filename')
    if not url.startswith(('https://', 'http://')):
        raise ValueError('Use an HTTP or HTTPS URL')
    if expected_hash is not None:
        expected_hash = expected_hash.lower()
        if len(expected_hash) != 64 or any(c not in '0123456789abcdef' for c in expected_hash):
            raise ValueError('Expected SHA-256 must contain 64 hexadecimal characters')
    fd, temporary = tempfile.mkstemp(prefix='.pyvpn-download-', dir=output.parent)
    try:
        actual = hashlib.sha256()
        size = 0
        with os.fdopen(fd, 'wb') as dest, urlopen(url, timeout=60) as source:
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                dest.write(block)
                actual.update(block)
                size += len(block)
        if ((expected_size is not None and size != expected_size)
                or (expected_hash is not None and actual.hexdigest() != expected_hash)):
            raise ValueError('Download checksum or length mismatch')
        os.link(temporary, output)
        status = 'PASS' if expected_hash is not None else 'Downloaded (no expected checksum supplied)'
        print(f'{status}: received {size} bytes; SHA-256 {actual.hexdigest()}', flush=True)
    finally:
        os.unlink(temporary)


def receive(base_url, output):
    if Path(output).exists():
        raise ValueError('Output already exists; choose another filename')
    with urlopen(base_url.rstrip('/') + '/manifest', timeout=30) as response:
        info = json.load(response)
    download(base_url.rstrip('/') + '/file', output, info['sha256'], info['bytes'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    server = commands.add_parser('serve')
    server.add_argument('--file', required=True)
    server.add_argument('--bind', default='10.8.0.1')
    server.add_argument('--port', type=int, default=8000)
    client = commands.add_parser('receive')
    client.add_argument('--url', default='http://10.8.0.1:8000')
    client.add_argument('--output', required=True)
    public = commands.add_parser('download', help='Download an ordinary public HTTP(S) file using current VPN routes')
    public.add_argument('--url', required=True)
    public.add_argument('--output', required=True)
    public.add_argument('--sha256', help='Optional expected publisher SHA-256')
    args = parser.parse_args()
    if args.command == 'serve':
        serve(args.file, args.bind, args.port)
    elif args.command == 'receive':
        receive(args.url, args.output)
    else:
        download(args.url, args.output, args.sha256)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, KeyError) as exc:
        raise SystemExit(str(exc))
