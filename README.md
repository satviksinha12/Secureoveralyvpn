# Python point-to-point VPN

A Linux TUN tunnel using UDP and AES-256-GCM. Python 3.10+ and `cryptography` are the only Python dependencies. Run both endpoints with root privileges. This is a one-peer demonstration implementation.

```text
client_ns                                           server_ns
10.8.0.2/24 tun0                                     tun0 10.8.0.1/24
      |                                                   |
  vpn.py client --- AES-GCM over UDP port 5555 --- vpn.py server
      |                                                   |
veth_c 192.0.2.2/24 -------- veth pair -------- 192.0.2.1/24 veth_s
```

## Install and run the complete demo

On Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y python3-venv iproute2 iputils-ping tcpdump iperf3
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
sudo modprobe tun
sudo env PATH="$PWD/.venv/bin:$PATH" bash tests/demo.sh
```

The demo creates `client_ns` and `server_ns`, starts both VPN endpoints, pings 10.8.0.1, records a pcap, injects a replay and a tampered packet, and benchmarks TCP over both paths for five seconds each. It generates a random PSK unless `VPN_PSK` is supplied. It cleans up its namespaces and their processes on exit. Use these namespace names only for this project: teardown terminates all processes in them. Setup refuses to overwrite existing namespaces.

Artifacts are saved under `results/`: endpoint logs, `ping.txt`, `tunnel.pcap`, attack counter snapshots in `attacks.json`, raw iperf JSON, and `benchmark.md`. A failed check makes the demo exit nonzero. Throughput is machine-dependent; both processes share one host.

## Manual operation

```bash
sudo bash setup_ns.sh
# Generate once and export the SAME value in both terminals:
export VPN_PSK='<random shared secret of at least 16 bytes>'
# Terminal 1
sudo env VPN_PSK="$VPN_PSK" ip netns exec server_ns .venv/bin/python vpn.py \
  --mode server --peer-ip 192.0.2.2 --port 5555 --verbose
# Terminal 2
sudo env VPN_PSK="$VPN_PSK" ip netns exec client_ns .venv/bin/python vpn.py \
  --mode client --peer-ip 192.0.2.1 --port 5555 --verbose
# Terminal 3
sudo ip netns exec client_ns ping -c 5 10.8.0.1
sudo ip netns exec server_ns curl http://127.0.0.1:5000/stats
sudo bash teardown_ns.sh
```

Use `openssl rand -hex 32` or Python's `secrets.token_hex(32)` to generate the PSK. Prefer `VPN_PSK` to the `--psk` option so it does not appear in command-line listings. Root can still inspect process environments. Both peers bind the chosen UDP port. The client contacts the configured server IP/port; the server learns the client source port from a PSK-authenticated hello from the configured client IP, then filters traffic to that endpoint. Start both within the default 60-second handshake timeout. Restart both endpoints together after either stops.

TUN is created using `/dev/net/tun`, `fcntl.ioctl`, and `IFF_TUN | IFF_NO_PI`. Each endpoint configures its /24 address and MTU 1400 with `ip`. The resulting connected route sends traffic for 10.8.0.0/24 into TUN. The main loop uses `select()` on TUN and UDP. Closing the file descriptor removes the nonpersistent TUN device.

## Encryption and startup

Data datagrams have exactly this structure:

```text
0                  8                   20                   end
+------------------+-------------------+---------------------+
| sequence (8 BE)  | nonce (12 bytes)  | ciphertext | tag(16) |
+------------------+-------------------+---------------------+
AAD = the exact 8 sequence bytes
nonce = four zero bytes || sequence (8 BE)
```

Sequence numbers start at zero independently in each direction. Overflow stops transmission. Each direction uses a different 256-bit key. Packet overhead is 36 bytes plus the outer UDP/IP headers. Counters measure inner IP bytes successfully sent or written to TUN, rather than outer wire bytes.

HKDF-SHA256 derives a master authentication key from the PSK using a protocol-specific salt and label. Startup uses `PYVPN1 || role(1) || random(32) || HMAC-SHA256(32)`. Each side generates a fresh cryptographic random contribution. A `ACK || role(1) || HMAC-SHA256(32)` message confirms both contributions in server/client order. HKDF then derives separate server-to-client and client-to-server AES keys from the master and both contributions.

Fresh session keys make restarting counters safe; nonce uniqueness within a session follows from the counter. This relies on the OS cryptographic random generator for fresh sessions. This startup exchange uses library HMAC/HKDF; there is no custom cipher implementation. It is PSK authentication, **not X25519**, and does not provide forward secrecy. Random contributions and packet lengths/timing are public. Captures permit offline guessing of weak PSKs, so use a generated secret. No data packets are accepted until startup completes. Startup retries every 300 ms and times out; severe packet loss during final confirmation can require restarting both endpoints. Established sessions do not accept renegotiation.

A 64-packet replay bitmap accepts reordered packets within the window once each. Authentication succeeds before the bitmap changes, so forged sequence numbers cannot advance it. Packets at least 64 behind the highest accepted sequence and duplicates are dropped. Short/oversized datagrams, invalid tags, and invalid IP packets are rejected and counted. Invalid tags and drops are logged. No retransmission is added to UDP.

## Dashboard

A standard-library `ThreadingHTTPServer` runs in a background thread on loopback port 5000 in each namespace. `/` refreshes every two seconds; `/stats` returns JSON. This preserves the requirement of only one third-party dependency instead of adding Flask. Stats access is protected by a lock. `last_seen` is Unix time for the most recent accepted inbound IP packet; drop counters distinguish authentication, replay, and malformed input.

To view in a browser, explicitly bind the server dashboard to its veth IP with `--dashboard-bind 192.0.2.1` and run a browser in a namespace with connectivity to it. The default loopback binding keeps this unauthenticated dashboard local to its namespace.

## Tests and current results

```bash
.venv/bin/python -m unittest discover -s tests -v
sudo env PATH="$PWD/.venv/bin:$PATH" bash tests/demo.sh
```

| Check | Result in development environment |
| --- | --- |
| Crypto round trip, tamper, replay | PASS |
| Sequence AAD and nonce authentication | PASS |
| Window boundaries, reordering, duplicates | PASS |
| Malformed lengths, wrong direction key | PASS |
| Real UDP startup, bidirectional keys, fresh sessions | PASS |
| Python compilation and shell syntax | PASS |
| Namespace ping | Not run: root unavailable and `/dev/net/tun` missing |
| Live capture replay and tamper counters | Not run: same prerequisites |
| Direct veth TCP Mbit/s | Not measured: iperf3 missing |
| Tunnel TCP Mbit/s | Not measured: iperf3 missing |

Eight automated tests passed, including authenticated discovery of a different client source port, including rejection of mismatched PSKs and dashboard JSON/refresh checks. The live UDP test was run outside the restricted socket sandbox. The full root demo was attempted but `sudo -n` reported that a password is required. This environment also lacks tcpdump. No network benchmark values or successful TUN demo results are claimed. Run the complete demo on Ubuntu to produce measured results in `results/benchmark.md`.

`tests/attack.py` runs in server_ns, captures an actual incoming tunnel datagram from `veth_s`, resends its IP/UDP bytes using a raw socket, then flips a ciphertext/tag byte and resends. IPv4 UDP checksum is zeroed to ensure GCM, rather than UDP checksum validation, rejects the tamper. It asserts that both relevant drop counters increase. Run it before generating ping traffic; `tests/demo.sh` handles this order.

Inspect the capture using Wireshark's UDP stream view or:

```bash
tcpdump -nn -XX -r results/tunnel.pcap
```

The outer IPv4 addresses and UDP ports are visible. The data payload begins with a visible sequence and nonce, followed by encrypted inner IP packets and a tag; inner ping/TCP payloads are not plaintext. Random-looking bytes alone are not proof of security; authenticated encryption and negative tests provide the actual checks. A capture on tun0 shows decrypted inner packets by design.

The plaintext-only development milestone could not be validated without TUN/root access; the shipped implementation always encrypts. X25519 was deferred to keep the core small.

## Future work

- Multi-client support.
- NAT/routing to the internet.
- Packet loss analytics.
- Certificate-based authentication.
- X25519 exchange authenticated with the PSK for forward secrecy.
- More robust handshake loss recovery, rekeying, and automatic peer restart recovery.

## Google Cloud VM server

Use an Ubuntu Compute Engine VM for the server and a separate Linux machine for the client. Run directly on both machines; namespace setup/teardown scripts are only for the single-machine demo.

1. Assign the VM an external IPv4 address, preferably a reserved static address.
2. Add a VPC ingress rule allowing **UDP 5555**, targeted to this VM, with the client's public IPv4 `/32` as the source. If a guest firewall such as UFW is enabled, allow that same traffic there too.
3. Install Python, venv, iproute2, and cryptography on both machines using the installation commands above. Copy `vpn.py` and `requirements.txt` to each. Run `sudo modprobe tun` and check `test -c /dev/net/tun`.
4. Supply the same generated PSK in `VPN_PSK` on both machines. Start these commands within 60 seconds of one another (or increase `--handshake-timeout`).

On the VM, from the project directory:

```bash
sudo env VPN_PSK="$VPN_PSK" .venv/bin/python vpn.py \
  --mode server --peer-ip CLIENT_PUBLIC_IPV4 --port 5555 --verbose
```

On the Linux client:

```bash
sudo env VPN_PSK="$VPN_PSK" .venv/bin/python vpn.py \
  --mode client --peer-ip VM_EXTERNAL_IPV4 --port 5555 --verbose
ping -c 5 10.8.0.1
```

Replace the uppercase address placeholders with numeric IPv4 addresses. The server binds `0.0.0.0`; do not try to assign its Google Cloud external IPv4 to a local interface. The tunnel addresses remain 10.8.0.1 and 10.8.0.2. Check for conflicts with existing local routes to 10.8.0.0/24.

**Home Wi-Fi:** the client initiates outbound UDP to the VM, and the server learns its NAT-mapped source port from a PSK-authenticated startup packet. Router port forwarding is not required. Use the home network's public IPv4 as the server's `--peer-ip`, rather than the client's private 192.168.x.x address. The server remains pinned to the authenticated endpoint for the session. Restart both peers if the public IP or NAT mapping changes. A network that blocks outbound UDP will still prevent connection. There is no idle keepalive yet; after prolonged inactivity, NAT may expire the mapping, requiring both peers to restart.

Keep dashboard port 5000 on loopback. To view the VM dashboard from your local browser, forward it through SSH:

```bash
ssh -N -L 15000:127.0.0.1:5000 USER@VM_EXTERNAL_IPV4
# Open http://127.0.0.1:15000 locally.
```

Use your configured SSH user/key or an equivalent `gcloud compute ssh` tunnel. No Google Cloud IP forwarding or internet NAT configuration is needed for pinging the VPN endpoints themselves. Internet browsing through the tunnel remains outside this project's scope. Cloud deployment has not been tested from this workspace.

Google Cloud references: [static external IPs](https://docs.cloud.google.com/vpc/docs/reserve-static-external-ip-address) and [VPC firewall rules](https://docs.cloud.google.com/firewall/docs/using-firewalls).

### Cloud demo evidence

A user-run home-to-cloud test returned 5/5 ping replies to 10.8.0.1 (0% loss, average RTT 285.836 ms). Screenshots also showed continuously increasing dashboard counters. This was observed from user-provided screenshots; cloud throughput and live attack rejection are still unmeasured.

Keep both VPN processes running during these checks. On the cloud VM, start a capture in a second SSH terminal:

```bash
mkdir -p ~/vpn-project/results
sudo timeout 20 tcpdump -ni ens4 -s 0 -w ~/vpn-project/results/cloud-tunnel.pcap 'udp port 5555'
```

During the capture, on the laptop run `ping -c 10 -W 2 10.8.0.1`. Replace `ens4` if `ip route show default` names a different interface. Inspect with `sudo tcpdump -nn -XX -r ~/vpn-project/results/cloud-tunnel.pcap` or download the pcap for Wireshark. Outer addresses and sequence/nonce remain visible; the inner packet is encrypted.

For live attacks, upload the updated `tests/attack.py` to the VM and put it in `~/vpn-project/tests/attack.py`. From the VM project directory, run:

```bash
sudo .venv/bin/python tests/attack.py --interface ens4 --peer-ip YOUR_HOME_PUBLIC_IP
```

While it waits, ping from the laptop. It learns the NAT source port from the captured IP/UDP packet and injects a duplicate and a tampered copy to the VM's internal destination IP. PASS requires both the replay and authentication drop counters to increase. The namespace defaults still work without arguments. A failed result needs diagnosis; do not claim rejection without observing the counters.

For cloud throughput, bind iperf to the tunnel address on the VM:

```bash
iperf3 -s -B 10.8.0.1
```

On the laptop:

```bash
mkdir -p results
iperf3 -c 10.8.0.1 -t 10 -J > results/cloud-tunnel.json
```

This needs no public iperf firewall opening. A direct cloud comparison requires a separate iperf listener on the VM internal address and a temporary TCP 5201 VPC/guest firewall allowance restricted to the home public IP. That compares the same internet path with/without tunneling; it is distinct from the direct-veth namespace benchmark. Remove the temporary allowance afterward.
