# Team setup and demonstration guide

**For current simultaneous-device deployment use [MULTI_DEVICE.md](MULTI_DEVICE.md) first.** It replaces the original one-client setup below: server peer-IP filtering is optional, client ports and tunnel IPs are automatic, and v3 requires new state paths once.

Start here if you are setting up or presenting **Secure Overlay VPN with Live Monitoring Dashboard**. The detailed implementation description is in [README.md](README.md). For the new optional IPv4 internet gateway and file-transfer presentation, follow [INTERNET_DEMO.md](INTERNET_DEMO.md).

## 1. Choose your role before running anything

| Role | Where commands run | Responsibility |
| --- | --- | --- |
| Server operator | Google Cloud VM, through SSH | Start server, inspect server stats, capture traffic, run attack tests and iperf listener |
| Client operator | Linux laptop on home Wi-Fi | Start client, generate ping and iperf traffic, display local dashboard |
| Evidence/presentation operator | Separate terminals/browser | Record results, save screenshots, explain architecture and test outcomes |

The server supports multiple simultaneous devices with separate state files. Follow MULTI_DEVICE.md to omit the server peer-IP filter and allow the shared UDP listener from any IPv4 source. Each client receives its own virtual address.

Use three terminals: server VPN, laptop VPN, and tests. Open extra SSH windows as needed. Leave VPN terminals running while issuing test commands elsewhere.

## 2. Obtain repository access

The repository is private. Satvik must add each teammate as a collaborator in GitHub **Settings → Collaborators**, and each teammate must accept the invitation. Never share a personal access token or account password.

On your Linux laptop, after configuring your own GitHub access:

```bash
git clone https://github.com/satviksinha12/Secureoveralyvpn.git
cd Secureoveralyvpn
```

An HTTPS password prompt requires a GitHub token, not your account password. Alternatively, use your own authenticated GitHub CLI or SSH setup. For an existing checkout, enter its directory and run `git pull --ff-only` before starting the VPN. Stop the program before updating its files.

## 3. Install prerequisites

The client and server need Linux, Python 3.10+, sudo access, and /dev/net/tun. Windows and macOS cannot run this Linux TUN implementation directly. A browser alone is not a VPN client.

### Ubuntu/Debian: run on each applicable machine

```bash
sudo apt-get update
sudo apt-get install -y git python3-venv python3-pip iproute2 iputils-ping tcpdump iperf3 curl tmux
```

### Garuda/Arch: run on the laptop if applicable

```bash
sudo pacman -S --needed git python python-pip iproute2 iputils tcpdump iperf3 curl tmux
```

From the project directory on **both endpoints**:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
sudo modprobe tun
ls -l /dev/net/tun
```

If `modprobe` fails but the TUN device exists, support may already be built in. If the device is absent, fix host TUN support before continuing. Do not create a Python virtual environment as root.

On the VM, either clone with your own authorized GitHub credentials or upload the files through SSH-in-browser. Keep vpn.py, internet.py, file_transfer.py, requirements.txt, and tests/ together in the project directory. An upload of vpn.py alone is insufficient for the security tests.

## 4. Record the correct addresses

On the **laptop**:

```bash
curl -4 https://api.ipify.org
echo
```

This is HOME_PUBLIC_IP. It is different from a local Wi-Fi address such as 192.168.1.50.

In Google Cloud **Compute Engine → VM instances**, copy the VM's **External IP** as VM_EXTERNAL_IP. Do not use its internal 10.x.x.x address for a home client.

| Setting | Correct address |
| --- | --- |
| Server --peer-ip | Laptop network's HOME_PUBLIC_IP |
| Client --peer-ip | VM_EXTERNAL_IP |
| VPC ingress source range | HOME_PUBLIC_IP/32 |
| Ping destination | 10.8.0.1 |

The original demo addresses may change. Obtain the current values instead of copying old screenshots.

## 5. Configure the cloud firewall

Use a VPC firewall rule on the VM's network with **Ingress**, **Allow**, source **HOME_PUBLIC_IP/32**, and **UDP 5555**. Our tag-free setup uses **All instances in the network** as the target, so this allowance applies across that VPC. If a guest firewall is active, it must also permit this UDP traffic.

Keep the existing SSH access configuration. Dashboard port 5000 need not be publicly exposed. No home-router port forwarding is needed for the tested client-initiated connection: the server learns the client's NAT-translated UDP port after authenticating startup.

Do not run setup_ns.sh on the cloud VM for this deployment. Those scripts are for the optional single-machine namespace demo only.

## 6. Enter the SAME shared secret on both machines

Coordinate one random PSK privately. Never commit it, paste it into GitHub issues, or include its value in screenshots. Generate a new demo PSK rather than reusing a secret previously exposed in a screenshot.

Generate once on either machine:

```bash
python3 -c 'import secrets; print(secrets.token_hex(32))'
```

On each endpoint, use **Bash**. If your terminal uses Fish, run this command **by itself**, then wait for the new prompt:

```bash
bash
```

Next, run this command separately on each endpoint:

```bash
read -rsp "Paste shared PSK: " VPN_PSK
```

Paste the identical secret and press Enter. It remains invisible. Run `echo` afterward to move to a fresh line. The launch commands below explicitly pass the variable to sudo, so `export` is not required.

Keep using that shell. Opening another shell may lose the variable; re-enter it if necessary. Do not generate different PSKs on the two machines.

## 7. Start the server — CLOUD VM ONLY

Use the VM project directory containing vpn.py and .venv. For an uploaded project this may be `~/vpn-project`; for a clone it is `~/Secureoveralyvpn`.

To protect the process from a browser disconnect, start `tmux new -s vpn` **before entering the PSK**, then enter the PSK inside tmux using step 6. If a session already exists, attach using `tmux attach -t vpn` and inspect it before starting another server.

Replace HOME_PUBLIC_IP in this command with the numeric address from step 4:

```bash
sudo env VPN_PSK="$VPN_PSK" .venv/bin/python vpn.py --mode server --peer-ip HOME_PUBLIC_IP --handshake-timeout 600 --verbose
```

“Waiting for authenticated peer” is expected until the laptop starts. Each startup round has a ten-minute timeout and retries automatically. Do not run `--mode client` on the cloud VM for this demo.

Detach tmux with **Ctrl+B**, release, then **D**. This leaves the server running. **Ctrl+Z suspends the process and breaks the demo.**

## 8. Start the client — LAPTOP ONLY

In the laptop's project directory, in the shell where you entered its PSK, replace VM_EXTERNAL_IP:

```bash
sudo env VPN_PSK="$VPN_PSK" .venv/bin/python vpn.py --mode client --peer-ip VM_EXTERNAL_IP --handshake-timeout 600 --verbose
```

The server displays **Multi-client server ready**; each client displays **Tunnel ready** after receiving its address. Leave forwarding processes running; run only one client process per device.

## 9. Verify connectivity and show the dashboard

In a **separate laptop terminal**:

```bash
ip -4 addr show tun0
ip route get 10.8.0.1
ping -c 10 -W 2 10.8.0.1
```

Expect tun0 with 10.8.0.2 and a route using tun0. The server interface should have 10.8.0.1. Open **http://127.0.0.1:5000** in the laptop browser. Run `ping 10.8.0.1` to demonstrate increasing counters; stop only that ping with Ctrl+C.

For JSON stats, run on either endpoint:

```bash
curl --max-time 3 http://127.0.0.1:5000/stats
```

Each dashboard shows its own endpoint's counters. `last_seen` is a Unix timestamp, and byte counters measure inner IP traffic. A local browser page is not the cloud dashboard. To inspect cloud stats, use curl through SSH or an SSH port-forward.

## 10. Capture encrypted packets — CLOUD VM

In a **separate SSH terminal**, find the physical interface using `ip route show default`. The original VM used ens4. Replace that name below if needed:

```bash
mkdir -p ~/vpn-project/results
sudo timeout 20 tcpdump -ni ens4 -s 0 -w ~/vpn-project/results/cloud-tunnel.pcap 'udp port 5555'
```

Use your actual VM project path if it differs. Immediately run a ten-packet ping on the laptop. After the capture ends, read the file **on the VM**:

```bash
sudo tcpdump -nn -XX -r ~/vpn-project/results/cloud-tunnel.pcap -c 4
```

Save the pcap and screenshot. Outer addresses, sequence numbers, and nonces are visible; the inner IP packet is encrypted. Hex output alone is not a security proof. In Wireshark, inspect the outer UDP stream rather than a capture on tun0, which intentionally exposes decrypted traffic.

## 11. Replay and tamper rejection — CLOUD VM + LAPTOP

In the VM's project directory, replace the interface and home address as necessary:

```bash
sudo .venv/bin/python tests/attack.py --interface ens4 --peer-ip HOME_PUBLIC_IP
```

Within 30 seconds, generate traffic on the laptop:

```bash
ping -c 5 -W 2 10.8.0.1
```

Expect the script to report PASS with increased dropped_replay and dropped_auth values. It captures an actual encrypted packet, injects a duplicate, then injects a modified copy. Save the before/after output. A capture timeout means no suitable data packet was observed during that interval; repeat with ping running. These tests use root raw sockets and should only target our own demonstration server.

## 12. TCP throughput through the VPN

In a VM test terminal:

```bash
iperf3 -s -B 10.8.0.1 -p 5202
```

In a laptop test terminal:

```bash
iperf3 -c 10.8.0.1 -p 5202 -t 10
```

Record the final **receiver** throughput. No public TCP 5202 opening is required for this tunnel test.

For a direct comparison, stop the iperf listener with Ctrl+C **in its own terminal**, then start on the VM:

```bash
iperf3 -s -p 5202
```

Temporarily allow **TCP 5202 from HOME_PUBLIC_IP/32** in the cloud VPC and guest firewall if applicable. On the laptop:

```bash
iperf3 -c VM_EXTERNAL_IP -p 5202 -t 10
```

Remove the temporary TCP firewall allowance and stop the iperf server afterward. Keep the UDP 5555 rule if the VPN is still needed. Compare receiver summaries consistently. This measures the same internet path directly and through the VPN; it is not the direct-veth namespace benchmark.

## 13. Original demonstration results

| Check | Recorded result |
| --- | --- |
| Ten-packet ping | 10 received, 0% loss, average RTT 294.573 ms |
| Replay test | dropped_replay: 0 → 1 |
| Tamper test | dropped_auth: 0 → 1 |
| VPN TCP receiver throughput | 13.2 Mbit/s |
| Direct TCP receiver throughput | 20.6 Mbit/s |

These are earlier user-run measurements. Record your own results if you repeat the demo. The VPN achieved approximately 64% of direct throughput in those single runs; that difference includes network variability and does not isolate encryption cost.

## 14. Common problems

| Symptom | What to do |
| --- | --- |
| `.venv/bin/python: No such file` | Enter the project directory, then create/install the venv if missing. Use `pwd` and `ls .venv/bin/python vpn.py`. |
| `read: -rsp: unknown option` | You are likely in Fish. Run `bash` alone, then enter the PSK separately. |
| PSK must be at least 16 bytes | Secret is empty/too short in this shell. Re-enter the same generated PSK without printing it. |
| Address already in use before waiting log | Check existing UDP sockets with `sudo ss -uanp 'sport = :5555'`. Do not launch more copies. |
| Address already in use after handshake | Check dashboard TCP port with `sudo ss -ltnp 'sport = :5000'`. |
| Process says Stopped | Ctrl+Z suspended it. In its original shell run `jobs`, then `fg %1` for job 1; use the actual job number if different. |
| Waiting for authenticated peer | Check both roles, matching PSKs, current public IPs, UDP firewall, and identical code versions. Do not ping until both are ready. |
| tun0 missing / dashboard offline | Inspect the VPN terminal for an exit/error. Ping cannot use this tunnel while the process is down. |
| Route to 10.8.0.1 uses Wi-Fi | TUN is absent or a route conflicts; inspect interface and VPN startup first. |
| `Connection refused` in VPN terminal | The process now retries transient UDP errors automatically. Watch connection_state and both logs; check firewall and peer availability if it keeps retrying. |
| Only one packet in pcap | Repeat capture while fresh tunnel ping traffic is actively flowing. |
| iperf address in use | Inspect `sudo ss -ltnp 'sport = :5202'` for an earlier listener before starting another. |
| Browser SSH closes | Reconnect and attach tmux; check server stats before launching another server. |

When diagnosing port conflicts, use **ss -uanp**, not only ss -lunp: connected UDP sockets may be missed by a listening-only check. Verify a PID belongs to this project's process before stopping it.

### Stopping safely

Use Ctrl+C in each original VPN terminal. Ctrl+C/SIGTERM cancels both an active session and a waiting handshake. Do not use Ctrl+Z, which suspends a process while leaving its ports occupied. If diagnosing an older frozen process, verify its PID with `ss` and `ps -p PID -o pid,args` before stopping that specific process. Never kill all Python processes indiscriminately.

### Reconnection and retained traffic keys

Update **both endpoints** before using this version; protocol v3 is incompatible with earlier versions. Automatic reconnect and encrypted keepalives are enabled without additional flags. A process restart still requires relaunching its command, but the other endpoint can remain running and retry.

For keys to survive process restarts, create a private state directory on each machine:

```bash
sudo install -d -m 700 /var/lib/pyvpn
```

Add `--state-file /var/lib/pyvpn/server.sqlite` to the cloud command and `--state-file /var/lib/pyvpn/client.sqlite` to the laptop command. Keep using those same local files and the same PSK. Enter the PSK again when starting a new shell; it is not saved by this option.

State saves the derivation seed, reserved send-counter ranges, and receive replay window. Never share, copy, or restore an older state database: rolling it back can break nonce/replay safety. After restoring a VM snapshot, rotate the PSK and use new state paths on both peers. State filenames are ignored by Git. See [README.md](README.md#automatic-reconnect-and-restart-safe-sessions-protocol-v3) for details.

To demonstrate recovery, keep ping running, stop one VPN process with Ctrl+C, then restart it with the same command, PSK, and state path. The survivor should retry and reconnect. Default keepalives run every 5 seconds, peer timeout is 20 seconds, and retry delay is 2 seconds. This is not guaranteed to recover instantly, and packets may be lost during the outage. Watch `connection_state` and `reconnects` on the dashboard. Repeat the test with the opposite endpoint.

## 15. What each teammate should be able to explain

- How TUN supplies inner IP packets and UDP transports encrypted datagrams.
- Why AES-GCM provides authentication as well as encryption.
- How the PSK-authenticated random exchange derives different directional keys.
- Why a counter nonce is safe only with nonrepeating counters under each key.
- Why the replay window changes only after authentication succeeds.
- How NAT port discovery permits a home Wi-Fi client to initiate the connection.
- What each dashboard counter means, and how replay/tamper tests change it.
- Why cloud measurements vary and how the optional IPv4 NAT gateway extends the basic endpoint overlay.

For presentation preparation, split report/test-results writing, architecture slides, and demo rehearsal among the team. Each person should reproduce one check and explain its outcome rather than only reading screenshots.
