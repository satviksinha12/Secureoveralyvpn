"""Reversible IPv4 routing/NAT configuration for the optional VPN gateway."""
import json
import logging
import subprocess

LOG = logging.getLogger('vpn')


class InternetRouting:
    def __init__(self, mode, peer_ip, tun):
        self.mode, self.peer_ip, self.tun = mode, peer_ip, tun
        self.undo = []
        self.active = False
        self.client_ip = '10.8.0.2'

    @staticmethod
    def run(*args):
        try:
            return subprocess.run(list(args), check=True, capture_output=True, text=True).stdout
        except subprocess.CalledProcessError as exc:
            LOG.error('Network configuration command failed: %s: %s', args, exc.stderr.strip())
            raise

    def change(self, command, reverse):
        self.run(*command)
        self.undo.append(reverse)

    def enable(self):
        if self.active:
            return
        try:
            if self.mode == 'client':
                self.client()
            else:
                self.server()
            self.active = True
        except BaseException:
            self.close()
            raise

    def client(self):
        route = json.loads(self.run('ip', '-j', '-4', 'route', 'get', self.peer_ip))[0]
        dev = route['dev']
        if dev == self.tun:
            raise ValueError('Server endpoint already routes into TUN; restore physical routing first')
        # Preserve any pre-existing host route instead of replacing it.
        existing = json.loads(self.run('ip', '-j', '-4', 'route', 'show', 'exact', self.peer_ip + '/32'))
        for network in ('0.0.0.0/1', '128.0.0.0/1'):
            if json.loads(self.run('ip', '-j', '-4', 'route', 'show', 'exact', network)):
                raise ValueError('Another split default route exists; disable the other VPN first')
        if not existing:
            route_args = ['ip', '-4', 'route', 'add', self.peer_ip + '/32']
            if route.get('gateway'):
                route_args += ['via', route['gateway']]
            route_args += ['dev', dev]
            self.change(route_args, ['ip', '-4', 'route', 'del', self.peer_ip + '/32', 'dev', dev])
        for network in ('0.0.0.0/1', '128.0.0.0/1'):
            self.change(['ip', '-4', 'route', 'add', network, 'dev', self.tun, 'src', self.client_ip],
                        ['ip', '-4', 'route', 'del', network, 'dev', self.tun])

    def set_address(self, address):
        if self.active and address != self.client_ip:
            for network in ('0.0.0.0/1', '128.0.0.0/1'):
                self.run('ip', '-4', 'route', 'replace', network, 'dev', self.tun, 'src', address)
        self.client_ip = address

    def server(self):
        route = json.loads(self.run('ip', '-j', '-4', 'route', 'get', '1.1.1.1'))[0]
        dev = route['dev']
        if dev == self.tun:
            raise ValueError('Server internet egress must not be TUN')
        previous = self.run('sysctl', '-n', 'net.ipv4.ip_forward').strip()
        # Check iptables exists before changing system state.
        self.run('iptables', '--version')
        if previous != '1':
            self.change(['sysctl', '-w', 'net.ipv4.ip_forward=1'],
                        ['sysctl', '-w', 'net.ipv4.ip_forward=' + previous])
        rules = [
            ('filter', 'FORWARD', ['-i', self.tun, '-o', dev, '-s', '10.8.0.0/24',
                                   '-m', 'conntrack', '--ctstate', 'NEW,ESTABLISHED,RELATED', '-j', 'ACCEPT']),
            ('filter', 'FORWARD', ['-i', dev, '-o', self.tun, '-d', '10.8.0.0/24',
                                   '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT']),
            ('nat', 'POSTROUTING', ['-s', '10.8.0.0/24', '-o', dev, '-j', 'MASQUERADE']),
            ('mangle', 'FORWARD', ['-o', self.tun, '-p', 'tcp', '--tcp-flags', 'SYN,RST', 'SYN',
                                   '-j', 'TCPMSS', '--clamp-mss-to-pmtu']),
        ]
        for table, chain, rule in rules:
            rule = ['-m', 'comment', '--comment', 'pyvpn-internet'] + rule
            self.change(['iptables', '-w', '-t', table, '-I', chain, '1'] + rule,
                        ['iptables', '-w', '-t', table, '-D', chain] + rule)

    def close(self):
        failures = []
        for command in reversed(self.undo):
            try:
                self.run(*command)
            except (OSError, subprocess.CalledProcessError) as exc:
                LOG.error('Could not restore routing: %s: %s', command, exc)
                failures.append(command)
        self.undo = list(reversed(failures))
        self.active = False
        if failures:
            LOG.error('Routing cleanup incomplete; rerun the logged commands as root')
