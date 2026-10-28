# Multiple devices, one shared PSK, no per-client port setup

Protocol v3 accepts multiple Linux devices simultaneously. The server can accept authenticated clients from **any IPv4 address**. Each client automatically chooses a local UDP port; its router's translated port is learned by the server. You configure one server listener/firewall port, UDP 5555, once. Devices need only the server's current external IPv4 address and the same PSK.

## 1. Update the cloud VM manually

Stop the old VPN on the VM and laptops with Ctrl+C. Upload **all four files** from the updated project to the VM:

```text
vpn.py
multi_server.py
internet.py
file_transfer.py
```

In the VM SSH terminal:

```bash
mv ~/vpn.py ~/multi_server.py ~/internet.py ~/file_transfer.py ~/vpn-project/
cd ~/vpn-project
sudo apt-get update
sudo apt-get install -y iptables curl
sudo install -d -m 700 /var/lib/pyvpn
```

All clients must use these updated files too. Protocol v3 cannot connect to v2. Use the **new state paths below once**; older databases are bound to the previous configuration format. Do not overwrite or roll back old databases to reuse keys. Keep the same strong PSK privately if it has not been exposed.

## 2. Configure Google Cloud once

Allow **Ingress UDP 5555** from **0.0.0.0/0** in the VM's VPC firewall. Use your existing tag-free target choice if appropriate. If a guest firewall is enabled, permit that UDP port there as well. There is no inbound client firewall rule or router port forwarding to configure for the normal client-initiated setup.

The server omits --peer-ip, so its application does not restrict clients to a single public IP. Supplying --peer-ip on the server deliberately re-enables a source-IP filter. The PSK is still required: an open firewall is not anonymous VPN access. Every PSK holder is a trusted group member; there is no individual account/revocation mechanism.

Use a reserved/static external IP for the VM if you need its endpoint address to remain stable between VM stops. Automatic client port selection cannot discover a server whose address changed.

## 3. Enter the shared PSK

On each endpoint, in Bash:

```bash
read -rsp "Shared PSK: " VPN_PSK
```

Paste the identical PSK and press Enter. For Fish users, run `bash` by itself first and wait for a fresh prompt. Run the launch command from that same shell. The PSK is not stored automatically in the state database.

## 4. Server command — no home IP or port arguments

From the cloud project directory:

```bash
sudo env VPN_PSK="$VPN_PSK" .venv/bin/python vpn.py --mode server --state-file /var/lib/pyvpn/server-multi.sqlite --internet --verbose
```

The server displays “Multi-client server ready on UDP 5555”. Leave it running in tmux. Every authenticated device gets a separate session, replay window, and virtual address, starting at 10.8.0.2, then 10.8.0.3, and so on. The server stays at 10.8.0.1. The pool has 253 device identities. Allocations are retained for stable reconnection, so it is not an unlimited public service.

## 5. Same client command on every Linux device

In each device's own project directory:

```bash
sudo install -d -m 700 /var/lib/pyvpn
sudo env VPN_PSK="$VPN_PSK" .venv/bin/python vpn.py --mode client --peer-ip VM_EXTERNAL_IP --state-file /var/lib/pyvpn/client-multi.sqlite --internet --verbose
```

Replace VM_EXTERNAL_IP with the actual numeric cloud address. No --port or --local-port argument is needed. The default destination is UDP 5555, and source port 0 requests automatic assignment. If you intentionally customize the server listener, only then do clients need its matching --port.

**Create the client state independently on every device. Do not copy it between devices.** The saved random seed identifies the device, and the saved counters protect nonce/replay safety. Devices can use the same filename on their separate disks; they must not share the file contents. A copied state file impersonates the same identity and can break nonce safety. With separate state, reconnecting one client replaces only that client's previous endpoint, leaving the others connected.

The client log reports its assigned tunnel address after authentication. On new handshakes it updates its TUN address and IPv4 internet routes to the assigned address. No manual tunnel-IP selection is needed.

Without --state-file, the client has a new device identity on reconnect, so its assigned IP can change and retained leases consume the finite pool. Persistence is recommended for a multi-device demo.

## 6. Verify two devices at once

On both devices, in separate test terminals:

```bash
ip -4 addr show tun0
ping -c 5 -W 2 10.8.0.1
curl --noproxy '*' -4 --max-time 30 https://api.ipify.org
echo
```

Expect different tunnel addresses, successful server ping, and the same cloud external IPv4 as the internet exit for both devices. On the VM:

```bash
curl --max-time 3 http://127.0.0.1:5000/stats
```

The server dashboard includes active_clients and a clients list with each device's tunnel IP, learned UDP endpoint, and packet counters. These are simultaneous clients, not multiple copies of one process on the same laptop. Each machine normally has its own tun0 and dashboard port 5000.

The server checks each decrypted IPv4 source against its assigned lease before writing it to TUN. Returning packets are encrypted for the client whose leased address matches their destination. NAT covers 10.8.0.0/24, enabling all assigned devices to use the gateway. Client-to-client connectivity is not the demonstrated contract; test against 10.8.0.1 and the internet.

## 7. Download an ordinary public file through the gateway

On either connected client:

```bash
mkdir -p results
.venv/bin/python file_transfer.py download --url https://www.rfc-editor.org/rfc/rfc791.txt --output results/rfc791.txt
```

This downloads a normal public HTTP/HTTPS file without needing our /manifest endpoint. It prints the byte count and computed SHA-256. If the publisher supplies an expected hash, add `--sha256 EXPECTED_64_HEX_DIGEST`; the tool verifies it before publishing the output. Without an expected hash the printed digest is an identifier, not independent verification. Existing output files are never overwritten; choose another filename for another run.

The download tool forces IPv4 connections and preserves normal HTTPS certificate verification. It uses the current routes; it does not create a tunnel by itself. Check `ip route get 1.1.1.1` and the exit-IP result first. Other applications may still use native IPv6 or local DNS outside the gateway. An equivalent curl command is:

```bash
curl --noproxy '*' -4 -fL https://www.rfc-editor.org/rfc/rfc791.txt -o results/rfc791-v4.txt
```

For a checksum-verified server-to-client transfer, use file_transfer.py serve on 10.8.0.1 and file_transfer.py receive on any assigned device as described in [INTERNET_DEMO.md](INTERNET_DEMO.md). This no longer assumes that every client is 10.8.0.2. To serve a laptop file, bind to that laptop's actual assigned address.

## 8. Validation and limits

Twenty-seven automated tests pass, including two real simultaneous local UDP clients, distinct IP/port assignment, reply isolation, reconnect with the same lease, server lease persistence, rejection of forged startup messages, source-IP spoof rejection, routing rollback, and file-download checksum checks. Local UDP tests do not require root and do not exercise privileged TUN/NAT forwarding. Repeat the cloud checks above to validate the deployment; no new cloud throughput or public-download result is claimed.

The server accepts IPv4 devices running this Linux Python client, not native Android/iPhone VPN clients. PSK authentication uses a fresh challenge at each connection; each device gets separately derived traffic keys even though the PSK is shared. Internet forwarding is opt-in on both sides and remains IPv4-only. Periodic rekeying, per-device credentials, automatic server discovery, and independent protocol security review remain future work.
