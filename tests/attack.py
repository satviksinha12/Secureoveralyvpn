#!/usr/bin/env python3
"""Run on the receiving server before ping: capture a VPN packet, replay and tamper."""
import argparse
import json
import socket
import struct
import time
import urllib.request


def stats():
    with urllib.request.urlopen('http://127.0.0.1:5000/stats', timeout=3) as response:
        return json.load(response)


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--interface', default='veth_s')
parser.add_argument('--peer-ip', default='192.0.2.2', help='Observed incoming client IPv4 (public IP on cloud)')
parser.add_argument('--port', type=int, default=5555)
args = parser.parse_args()
peer = socket.inet_aton(args.peer_ip)
deadline = time.monotonic() + 30
print('Waiting for an incoming VPN data packet; generate ping traffic now.', flush=True)

with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as capture:
    capture.bind((args.interface, 0))
    capture.settimeout(15)
    while time.monotonic() < deadline:
        frame = capture.recv(65535)
        if frame[12:14] != b'\x08\x00':
            continue
        packet = bytearray(frame[14:])
        ihl = (packet[0] & 15) * 4
        if packet[9] != 17 or len(packet) < ihl + 8 + 36:
            continue
        src, dst, length = struct.unpack('!HHH', packet[ihl:ihl + 6])
        if dst == args.port and packet[12:16] == peer:
            payload = packet[ihl + 8:ihl + length]
            if payload.startswith(b'PYVPN') or payload.startswith(b'ACK'):
                continue
            packet = packet[:struct.unpack('!H', packet[2:4])[0]]
            break
    else:
        raise SystemExit('No incoming VPN data packet captured within 30 seconds')
# Let the original pass through the receiver before replaying it.
time.sleep(0.5)
before = stats()
# IPv4 allows a zero UDP checksum; GCM still verifies the encrypted payload.
packet[ihl + 6:ihl + 8] = b'\0\0'
with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as inject:
    inject.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    inject.sendto(packet, (socket.inet_ntoa(packet[16:20]), 0))
    packet[-1] ^= 1
    inject.sendto(packet, (socket.inet_ntoa(packet[16:20]), 0))
for _ in range(30):
    after = stats()
    if after['dropped_replay'] > before['dropped_replay'] and after['dropped_auth'] > before['dropped_auth']:
        print(json.dumps({'before': before, 'after': after, 'result': 'PASS'}, indent=2))
        break
    time.sleep(0.1)
else:
    raise SystemExit('FAIL: replay/auth counters did not both increase')
