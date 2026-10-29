#!/usr/bin/env python3
"""Linux preflight for the VPN: reports what would stop a client from connecting or routing traffic.

    sudo .venv/bin/python ui/doctor.py --role client --server VM_EXTERNAL_IPV4
    sudo .venv/bin/python ui/doctor.py --role server

Read-only: it inspects the system and never changes routes, firewall rules, or files. It does not need the PSK.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))
results = []


def report(level, name, detail='', fix=''):
    results.append(level)
    print('[%s] %s%s' % (level, name, ': ' + detail if detail else ''))
    if fix and level != 'PASS':
        print('       fix: ' + fix)


def run(*args):
    try:
        return subprocess.run(list(args), capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None


def routes(*args):
    out = run('ip', '-j', '-4', 'route', *args)
    try:
        return json.loads(out or '[]')
    except ValueError:
        return []


def port_free(kind, port):
    with socket.socket(socket.AF_INET, kind) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(('0.0.0.0' if kind == socket.SOCK_DGRAM else '127.0.0.1', port))
            return True
        except OSError:
            return False


def common():
    if sys.platform != 'linux':
        report('FAIL', 'Operating system', sys.platform, 'The VPN backend needs Linux (TUN, iproute2). Use a Linux machine or VM.')
        return False
    report('PASS', 'Operating system', 'Linux')
    report('PASS' if sys.version_info >= (3, 10) else 'FAIL', 'Python', sys.version.split()[0], 'Python 3.10+ is required')
    try:
        import cryptography
        report('PASS', 'cryptography package', cryptography.__version__)
    except ImportError:
        report('FAIL', 'cryptography package', 'not importable by this Python',
               'python3 -m venv .venv && .venv/bin/python -m pip install -r requirements.txt, then run this with .venv/bin/python')
    venv = PROJECT / '.venv' / 'bin' / 'python'
    report('PASS' if os.access(venv, os.X_OK) else 'FAIL', 'Project virtualenv', str(venv),
           'python3 -m venv .venv && .venv/bin/python -m pip install -r requirements.txt')
    tun = Path('/dev/net/tun')
    report('PASS' if tun.exists() else 'FAIL', '/dev/net/tun', 'present' if tun.exists() else 'missing',
           'sudo modprobe tun (inside containers add --device /dev/net/tun --cap-add NET_ADMIN)')
    report('PASS' if shutil.which('ip') else 'FAIL', 'iproute2 (ip)', shutil.which('ip') or 'not found',
           'sudo apt-get install -y iproute2')
    report('PASS' if os.geteuid() == 0 else 'WARN', 'Running as root', '' if os.geteuid() == 0 else 'some checks are limited',
           'Re-run with sudo for complete results')
    for name in ('vpn.py', 'internet.py', 'multi_server.py', 'file_transfer.py'):
        if not (PROJECT / name).is_file():
            report('FAIL', 'Project file ' + name, 'missing', 'Keep vpn.py, multi_server.py, internet.py and file_transfer.py together')
    return True


def client(server, dashboard_port):
    try:
        server = str(ipaddress.IPv4Address(server))
    except ValueError:
        report('FAIL', 'Server address', repr(server), 'Use the VM external IPv4 (numeric), not a hostname')
        return
    if ipaddress.IPv4Address(server).is_private:
        report('WARN', 'Server address', server + ' is a private address',
               'A home client needs the VM External IP, not the internal 10.x/172.16-31.x/192.168.x address')
    route = routes('get', server)
    if route:
        report('PASS', 'Route to server', 'via %s dev %s' % (route[0].get('gateway', 'direct'), route[0].get('dev')))
        if route[0].get('dev') == 'tun0':
            report('FAIL', 'Route to server', 'already goes into tun0', 'Stop any running VPN client and remove its routes first')
    else:
        report('FAIL', 'Route to server', 'no route', 'Check your network connection and default gateway')
    split = [r['dst'] for net in ('0.0.0.0/1', '128.0.0.0/1') for r in routes('show', 'exact', net)]
    report('FAIL' if split else 'PASS', 'Other split-default routes', ', '.join(split) or 'none',
           'Another VPN or a previous client left routes behind. Disconnect it, or: sudo ip route del 0.0.0.0/1 dev tun0; sudo ip route del 128.0.0.0/1 dev tun0')
    leftover = run('ip', '-br', 'link', 'show', 'tun0')
    report('FAIL' if leftover and 'tun0' in leftover else 'PASS', 'tun0 interface',
           'already exists' if leftover and 'tun0' in leftover else 'free',
           'A client is already running, or crashed. Stop it; as a last resort: sudo ip link del tun0')
    report('PASS' if port_free(socket.SOCK_STREAM, dashboard_port) else 'FAIL', 'Dashboard port %d' % dashboard_port,
           '' if port_free(socket.SOCK_STREAM, dashboard_port) else 'in use',
           'Stop the other process or choose another port under Advanced')
    state = Path('/var/lib/pyvpn')
    if state.is_dir():
        info = state.stat()
        ok = info.st_uid == os.geteuid() and not info.st_mode & 0o077
        report('PASS' if ok else 'FAIL', 'State directory', '/var/lib/pyvpn', 'sudo chown root:root /var/lib/pyvpn && sudo chmod 700 /var/lib/pyvpn')
    else:
        report('WARN', 'State directory', '/var/lib/pyvpn missing', 'sudo install -d -m 700 /var/lib/pyvpn (the launcher creates it)')
    print('\nCannot be checked from the client: the server being up, matching PSK, and UDP 5555 being open at the VM.\n'
          'If the client stays on "Connecting", ask the server operator to run this script with --role server.')


def server():
    forward = Path('/proc/sys/net/ipv4/ip_forward')
    report('PASS', 'IPv4 forwarding', 'enabled' if forward.read_text().strip() == '1' else 'off (vpn.py --internet turns it on)')
    ipt = shutil.which('iptables')
    report('PASS' if ipt else 'FAIL', 'iptables', ipt or 'not found',
           'sudo apt-get install -y iptables. Without it --internet fails and clients cannot reach the internet')
    default = routes('get', '1.1.1.1')
    if default:
        report('PASS', 'Internet egress interface', default[0].get('dev', '?'))
    else:
        report('FAIL', 'Internet egress interface', 'no route to the internet', 'The VM needs a default route')
    report('PASS' if port_free(socket.SOCK_DGRAM, 5555) else 'WARN', 'UDP 5555',
           'free (the server is not running yet)' if port_free(socket.SOCK_DGRAM, 5555) else 'in use (expected if the server is running)',
           'Start the server: sudo env VPN_PSK="$VPN_PSK" .venv/bin/python vpn.py --mode server --state-file /var/lib/pyvpn/server-multi.sqlite --internet --verbose')
    tun = run('ip', '-br', '-4', 'addr', 'show', 'tun0') or ''
    report('PASS' if '10.8.0.1' in tun else 'WARN', 'Server tunnel interface', tun.strip() or 'tun0 not up',
           'The server is not running, or was started without root')
    if ipt and os.geteuid() == 0:
        rules = run('iptables', '-w', '-t', 'nat', '-S', 'POSTROUTING') or ''
        report('PASS' if 'pyvpn-internet' in rules else 'WARN', 'NAT rule for clients', 'present' if 'pyvpn-internet' in rules else 'missing',
               'Start the server with --internet so it adds forwarding and NAT rules')
    try:
        from file_transfer import urlopen
        with urlopen('https://api.ipify.org', timeout=8) as response:
            seen = response.read(64).decode().strip()
        report('PASS', 'Outbound IPv4 address seen by the internet', seen)
    except Exception as exc:  # network lookup is advisory only
        report('WARN', 'Outbound IPv4 lookup', str(exc))
    print('\nAlso confirm in the cloud console: a firewall rule allowing UDP 5555 ingress from any IPv4 (0.0.0.0/0).\n'
          'Clients must use the VM External IP, and the server must run WITHOUT --peer-ip.')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--role', choices=['client', 'server'], required=True)
    parser.add_argument('--server', help='VM external IPv4 (client role)')
    parser.add_argument('--dashboard-port', type=int, default=5000)
    args = parser.parse_args()
    if args.role == 'client' and not args.server:
        parser.error('--server VM_EXTERNAL_IPV4 is required for the client role')
    print('Secure Overlay VPN preflight (%s)\n' % args.role)
    if common():
        client(args.server, args.dashboard_port) if args.role == 'client' else server()
    failures = results.count('FAIL')
    print('\n%d failed, %d warnings, %d passed' % (failures, results.count('WARN'), results.count('PASS')))
    raise SystemExit(1 if failures else 0)


if __name__ == '__main__':
    main()
