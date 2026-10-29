# Secure overlay VPN

**Separate client application:** [standalone_client/README.md](standalone_client/README.md). It runs independently of the original UI: Linux VPN client plus a Windows interface preview. Package it with `python3 scripts/package_client.py`.

**Building the client UI? Start with [UI_CLIENT_GUIDE.md](UI_CLIENT_GUIDE.md).** It defines the backend commands, stats fields, privilege handling, and public-IP demonstration.

## Current commands: multi-device internet VPN

Upload/update `vpn.py`, `multi_server.py`, `internet.py`, and `file_transfer.py` together. This is protocol v3; older clients are incompatible. Create new v3 state paths once, then keep them for future restarts. Each device creates its own state file; never copy a client's state file to another device.

From the project directory on each endpoint, in **Bash**, enter the same PSK privately:

```bash
read -rsp "Shared PSK: " VPN_PSK
```

Prepare state storage on each machine:

```bash
sudo install -d -m 700 /var/lib/pyvpn
```

**Cloud server:** no home IP or client port settings required:

```bash
sudo env VPN_PSK="$VPN_PSK" .venv/bin/python vpn.py --mode server --state-file /var/lib/pyvpn/server-multi.sqlite --internet --verbose
```

Allow VPC ingress **UDP 5555 from 0.0.0.0/0** once. The PSK still authenticates clients. Install `iptables` on the VM for --internet. The server accepts multiple devices and assigns their tunnel IPs automatically.

**Each Linux client:** replace VM_EXTERNAL_IP with the VM's current numeric external IPv4 address:

```bash
sudo env VPN_PSK="$VPN_PSK" .venv/bin/python vpn.py --mode client --peer-ip VM_EXTERNAL_IP --state-file /var/lib/pyvpn/client-multi.sqlite --internet --verbose
```

No --port or --local-port arguments are needed with the defaults. Remove --internet from the client command for endpoint-only traffic; the server can keep gateway mode enabled for other clients.

**Verify from another client terminal:**

```bash
ping -c 5 -W 2 10.8.0.1
curl --noproxy '*' -4 --max-time 30 https://api.ipify.org
echo
curl --max-time 3 http://127.0.0.1:5000/stats
```

With --internet active, the public IPv4 should match the cloud VM's external IPv4. A browser IP-location page generally reports a location associated with that address, not a guaranteed physical location. This feature is IPv4 exit-node routing; IPv6, local DNS, and more-specific local routes can bypass it. Do not label it complete leak protection.

**Download a public file through the active IPv4 VPN routes:**

```bash
mkdir -p results
.venv/bin/python file_transfer.py download --url https://www.rfc-editor.org/rfc/rfc791.txt --output results/rfc791.txt
```

Use a new output filename on subsequent runs. Add --sha256 with a publisher's expected 64-digit hash when available to verify downloaded contents.

**Current multi-device setup: [MULTI_DEVICE.md](MULTI_DEVICE.md).** Protocol v3 accepts multiple PSK-authenticated clients from any IPv4 source when the server omits `--peer-ip`; clients choose local ports automatically. Update all endpoints and use new v3 state paths once.

**Internet access and file transfer:** see [INTERNET_DEMO.md](INTERNET_DEMO.md). Enable `--internet` on both endpoints for an IPv4 gateway; use `file_transfer.py` for checksum-verified transfers.

**Teammates: start with [TEAM_SETUP.md](TEAM_SETUP.md)** for repository access, cloud/laptop setup, demo steps, and troubleshooting.

A multi-client Linux IPv4 TUN tunnel using UDP and AES-256-GCM. Python 3.10+ and `cryptography` are the only Python dependencies. Run endpoints with root privileges. Each authenticated client receives a separate tunnel IP and traffic keys.

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

Use `openssl rand -hex 32` or Python's `secrets.token_hex(32)` to generate the PSK. Prefer `VPN_PSK` to the `--psk` option so it does not appear in command-line listings. Root can still inspect process environments. The server binds the chosen UDP port; clients bind automatically selected local UDP ports by default. The client contacts the configured server IP/port; the server authenticates and tracks each learned UDP endpoint independently. A server --peer-ip is now an optional source filter, not required. Start both endpoints; failed handshake rounds automatically retry. The default 60-second handshake timeout applies to each round.

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

HKDF-SHA256 derives a master authentication key from the PSK using a protocol-specific salt and label. Protocol v3 startup uses `PYVPN3 || role(1) || seed(32) || challenge(32) || HMAC-SHA256(32)`. Challenges are fresh for every attempt. A `ACK || role(1) || HMAC-SHA256(32)` confirmation binds both seeds and fresh challenges in server/client order. HKDF derives separate directional traffic keys from the PSK-derived master and the ordered seeds. Changing either seed creates new traffic keys.

By default seeds are random per handshake, so reconnects use fresh traffic keys. With `--state-file`, each peer retains its seed and its per-key nonce/replay state; using the same PSK and both saved seeds regenerates the same directional traffic keys after a restart. Fresh challenges still authenticate every reconnect. This is PSK authentication, **not X25519**, and does not provide forward secrecy. Weak PSKs permit offline guessing. Both endpoints must run protocol v3; earlier versions are incompatible.

Handshake messages retry every 300 ms. A completed peer answers repeated matching hellos so lost final confirmations can recover. After an idle-peer timeout, a new handshake learns a changed NAT source port. Arbitrary packets cannot extend the authenticated peer liveness timer. See the persistence section below for restart-safety requirements.

A 64-packet replay bitmap accepts reordered packets within the window once each. Authentication succeeds before the bitmap changes, so forged sequence numbers cannot advance it. Packets at least 64 behind the highest accepted sequence and duplicates are dropped. Short/oversized datagrams, invalid tags, and invalid IP packets are rejected and counted. Invalid tags and drops are logged. No retransmission is added to UDP.

## Dashboard

A standard-library `ThreadingHTTPServer` runs in a background thread on loopback port 5000 in each namespace. `/` refreshes every two seconds; `/stats` returns JSON. This preserves the requirement of only one third-party dependency instead of adding Flask. Stats access is protected by a lock. `last_seen` is Unix time for the most recent accepted authenticated packet, including a keepalive; drop counters distinguish authentication, replay, and malformed input.

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

Twenty-seven automated tests pass. The suite covers crypto, authenticated endpoint discovery, wrong-PSK rejection, dashboard serving, durable nonce reservations, persistent replay rejection, fresh reconnect challenges, encrypted keepalives, cancellation, and retry behavior. The live UDP test was run outside the restricted socket sandbox. The full root demo was attempted but `sudo -n` reported that a password is required. This environment also lacks tcpdump. No network benchmark values or successful TUN demo results are claimed. Run the complete demo on Ubuntu to produce measured results in `results/benchmark.md`.

`tests/attack.py` runs in server_ns, captures an actual incoming tunnel datagram from `veth_s`, resends its IP/UDP bytes using a raw socket, then flips a ciphertext/tag byte and resends. IPv4 UDP checksum is zeroed to ensure GCM, rather than UDP checksum validation, rejects the tamper. It asserts that both relevant drop counters increase. Run it before generating ping traffic; `tests/demo.sh` handles this order.

Inspect the capture using Wireshark's UDP stream view or:

```bash
tcpdump -nn -XX -r results/tunnel.pcap
```

The outer IPv4 addresses and UDP ports are visible. The data payload begins with a visible sequence and nonce, followed by encrypted inner IP packets and a tag; inner ping/TCP payloads are not plaintext. Random-looking bytes alone are not proof of security; authenticated encryption and negative tests provide the actual checks. A capture on tun0 shows decrypted inner packets by design.

The plaintext-only development milestone could not be validated without TUN/root access; the shipped implementation always encrypts. X25519 was deferred to keep the core small.

## Future work

- Per-device credentials and revocation.
- IPv6 internet routing and resolver integration.
- Packet loss analytics.
- Certificate-based authentication.
- X25519 exchange authenticated with the PSK for forward secrecy.
- Periodic rekeying, stronger denial-of-service resistance, and extended network-fault testing.

## Google Cloud VM server

Use an Ubuntu Compute Engine VM for the server and a separate Linux machine for the client. Run directly on both machines; namespace setup/teardown scripts are only for the single-machine demo.

1. Assign the VM an external IPv4 address, preferably a reserved static address.
2. Add a VPC ingress rule allowing **UDP 5555**, targeted to this VM, with the client's public IPv4 `/32` as the source. If a guest firewall such as UFW is enabled, allow that same traffic there too.
3. Install Python, venv, iproute2, and cryptography on both machines using the installation commands above. Copy `vpn.py`, `multi_server.py`, `internet.py`, and `requirements.txt` to each. Also copy `file_transfer.py` for the file demo. Run `sudo modprobe tun` and check `test -c /dev/net/tun`.
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

**Home Wi-Fi:** the client initiates outbound UDP to the VM, and the server learns its NAT-mapped source port from a PSK-authenticated startup packet. Router port forwarding is not required. Use the home network's public IPv4 as the server's `--peer-ip`, rather than the client's private 192.168.x.x address. The server remains pinned to the authenticated endpoint for the session. Encrypted keepalives maintain activity, and timed-out sessions automatically retry and relearn the NAT port. If the home public IP changes, update the server peer IP and firewall source range; use a different state file for a different configured peer. A network that blocks outbound UDP still prevents connection.

Keep dashboard port 5000 on loopback. To view the VM dashboard from your local browser, forward it through SSH:

```bash
ssh -N -L 15000:127.0.0.1:5000 USER@VM_EXTERNAL_IPV4
# Open http://127.0.0.1:15000 locally.
```

Use your configured SSH user/key or an equivalent `gcloud compute ssh` tunnel. No Google Cloud IP forwarding or internet NAT configuration is needed for pinging the VPN endpoints themselves. Optional IPv4 internet routing is now available with `--internet` on both endpoints; see INTERNET_DEMO.md. Cloud deployment has not been tested from this workspace.

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


## Automatic reconnect and restart-safe sessions (protocol v3)

Both peers automatically retry startup and recover after peer timeouts or transient UDP errors. Defaults are `--keepalive 5`, `--peer-timeout 20`, and `--reconnect-delay 2` (seconds). `--handshake-timeout` bounds each attempt, not total process lifetime. Recovery can take a peer timeout plus a handshake round; queued TUN packets may be lost during outages. TUN and the dashboard stay available while reconnecting. `connection_state` reports connecting/connected/reconnecting, and `reconnects` counts failed rounds or established connection failures. Ctrl+C/SIGTERM now cancels a waiting handshake promptly. Stopping the process still requires starting it again manually or through a process supervisor.

To retain traffic keys through restarts, enable persistence on **all machines**. Once on each machine:

```bash
sudo install -d -m 700 /var/lib/pyvpn
```

Start the server with its existing PSK and addresses, adding:

```bash
sudo env VPN_PSK="$VPN_PSK" .venv/bin/python vpn.py --mode server --peer-ip HOME_PUBLIC_IP --state-file /var/lib/pyvpn/server.sqlite --verbose
```

On the client:

```bash
sudo env VPN_PSK="$VPN_PSK" .venv/bin/python vpn.py --mode client --peer-ip VM_EXTERNAL_IP --state-file /var/lib/pyvpn/client.sqlite --verbose
```

The PSK must still be supplied after a process restart; it is not stored in the database. The database retains the local derivation seed and per-key sequence/replay state, allowing the same traffic keys to be regenerated. It must be a mode-0600 regular file in a mode-0700 directory owned by the process user (root for sudo). Concurrent use of a state file is refused. Client state is bound to the protocol, server IP, and PSK; server state is bound to the protocol and PSK. Use a new file when changing these settings. Never share a state file between endpoints or running instances. State errors are fatal: the program will not silently reset counters under retained keys.

Before sending, SQLite commits a reservation for the next 4096 sequence numbers with synchronous=FULL. Restart skips unused reserved numbers, so even an abrupt process exit cannot reuse already-issued nonces, provided storage honors durable writes. Incoming replay state is committed **before** delivering each authenticated packet. This intentionally adds a disk transaction per received datagram and can reduce throughput. The previous 13.2 Mbit/s result predates persistence and is not a benchmark of this version. Process counters reset on restart; cryptographic counters do not.

**Never restore or roll back an old session-state backup, clone a VM with active state, or copy the database to another sender.** A rollback can reuse nonces or admit old packets. If restoring a machine snapshot, stop both peers, rotate the PSK, and use new state files on both. A local database cannot detect rollback of itself. Losing a state file generates a new seed and thus different traffic keys after reauthentication; packets from the previous key are no longer accepted. X25519 forward secrecy and automatic key rotation remain future work.

Recovery verification: keep a ping running, stop one endpoint with Ctrl+C, verify the survivor shows reconnecting, and restart the stopped endpoint with the same state path and PSK. Ping should recover after reauthentication without restarting the survivor. Repeat in both directions. The automated tests exercise local UDP and persistence without privileged TUN; repeat this full cloud check before claiming deployment recovery results.


## Multi-client address configuration

The v3 server sends each authenticated client an AES-GCM-protected `\x00CFG || assigned IPv4(4)` control payload and retries until it receives `\x00CFA || assigned IPv4(4)`. These records use the same durable counter and replay rules as data. Clients configure the leased address before forwarding application traffic. The server routes returning TUN IPv4 packets to the matching client and rejects client source addresses that differ from the lease. Empty encrypted records remain keepalives. See [MULTI_DEVICE.md](MULTI_DEVICE.md) for current deployment commands.
