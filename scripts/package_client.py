#!/usr/bin/env python3
"""Package only standalone client source/assets; never include environments or secrets."""
import argparse
import hashlib
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parents[1]
CLIENT = ROOT / 'standalone_client'
FILES = ['README.md', 'requirements.txt', '.gitignore', 'app.py', 'launcher.py',
         'vpn.py', 'multi_server.py', 'internet.py', 'file_transfer.py',
         'start-client.cmd', 'start-client.sh', 'start-launcher.sh',
         'static/index.html', 'static/app.js', 'static/app.css', 'static/favicon.svg']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'dist' / 'SecureVPNClient.zip')
    args = parser.parse_args()
    for name in FILES:
        if not (CLIENT / name).is_file():
            raise SystemExit('Missing client file: ' + name)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    checksums = []
    with ZipFile(args.output, 'w', ZIP_DEFLATED) as archive:
        for name in FILES:
            source = CLIENT / name
            archive.write(source, 'standalone_client/' + name)
            checksums.append(hashlib.sha256(source.read_bytes()).hexdigest() + '  ' + name)
        archive.writestr('standalone_client/SHA256SUMS', '\n'.join(checksums) + '\n')
    with ZipFile(args.output) as archive:
        if archive.testzip() is not None:
            raise SystemExit('Archive integrity check failed')
    print(f'Created {args.output} ({args.output.stat().st_size} bytes), {len(FILES)} source/asset files plus checksums')


if __name__ == '__main__':
    main()
