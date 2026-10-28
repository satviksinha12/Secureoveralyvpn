#!/usr/bin/env python3
"""Serve or receive one file over the VPN, checking its SHA-256 digest."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import build_opener, ProxyHandler

# Tunnel file transfers must connect directly, even when shell proxy variables exist.
urlopen = build_opener(ProxyHandler({})).open


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


def receive(base_url, output):
    output = Path(output)
    if output.exists():
        raise ValueError('Output already exists; choose another filename')
    with urlopen(base_url.rstrip('/') + '/manifest', timeout=30) as response:
        info = json.load(response)
    fd, temporary = tempfile.mkstemp(prefix='.pyvpn-download-', dir=output.parent)
    try:
        actual = hashlib.sha256()
        size = 0
        with os.fdopen(fd, 'wb') as dest, urlopen(base_url.rstrip('/') + '/file', timeout=60) as source:
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                dest.write(block)
                actual.update(block)
                size += len(block)
        if size != info['bytes'] or actual.hexdigest() != info['sha256']:
            raise ValueError('Download checksum or length mismatch')
        # Hard link refuses to overwrite a destination created during the download.
        os.link(temporary, output)
        print(f'PASS: received {size} bytes; SHA-256 {actual.hexdigest()}', flush=True)
    finally:
        os.unlink(temporary)


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
    args = parser.parse_args()
    if args.command == 'serve':
        serve(args.file, args.bind, args.port)
    else:
        receive(args.url, args.output)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, KeyError) as exc:
        raise SystemExit(str(exc))
