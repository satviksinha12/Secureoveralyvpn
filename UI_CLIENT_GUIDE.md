# Client UI integration guide

Build a UI around the existing Python backend. Do not reimplement TUN, encryption, handshake, routing, replay protection, or persistent counters in the frontend. The backend runs on Linux with Python 3.10+ and cryptography; the GUI framework is your choice and is separate from backend dependencies.

The objective is: a teammate enters the cloud server address and shared PSK, connects, sees the assigned tunnel address and traffic counters, and demonstrates that IPv4 internet traffic exits through the cloud VM. Multiple devices can connect simultaneously with their own state files.

## 1. What to build

| UI element | Required behavior |
| --- | --- |
| Server IPv4 | Numeric VM external IPv4, editable, no home public IP input |
| Shared secret | Masked PSK input, at least 16 UTF-8 bytes; no logging or URL parameters |
| Route IPv4 internet through VPN | Default on for the internet demonstration; controls --internet |
| Connect | Start one backend for the selected profile through the privilege mechanism |
| Disconnect | Gracefully stop that backend and wait for its cleanup |
| Connection status | Disconnected, starting, connecting, connected, reconnecting, error |
| Assigned tunnel IP | Actual dynamically assigned IP; do not hardcode 10.8.0.2 |
| Traffic | Sent/received bytes and packet counts, refreshed every two seconds |
| Security counters | Authentication, replay, and malformed drops |
| Exit IPv4 | Fetch a fresh IPv4-only public-IP result after connecting |
| Logs | Nonblocking display of stderr messages with secrets redacted |
| Public download | URL and destination input; invoke the existing download tool |

Do not require users to configure client source ports or home-router forwarding. Default server port is 5555; each client uses an ephemeral local UDP port automatically. Optional advanced settings may expose destination port and dashboard port, but they need not be on the main screen.

## 2. Files and installation

Keep these files together:

```text
vpn.py
multi_server.py
internet.py
file_transfer.py
requirements.txt
```

Backend setup from the project directory:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
sudo modprobe tun
sudo install -d -m 700 /var/lib/pyvpn
```

Linux iproute2 is needed on the client. The server needs iptables for internet gateway mode. Refer to [TEAM_SETUP.md](TEAM_SETUP.md) for distro-specific package installation.

Update all devices to protocol v3. Use new multi-device state files once when migrating from earlier versions. Existing state files are not a user-facing key/password store: the PSK must still be supplied. Never copy, reset, or roll back a state database just to work around a UI error.

## 3. Prove the backend works before connecting the UI

Have the server operator run the server command in the README and keep it running. Set its VPC rule to allow UDP 5555 from any IPv4 source for roaming/multiple devices. Do not start a cloud server from the laptop UI.

On the laptop, in Bash from the project directory:

```bash
read -rsp "Shared PSK: " VPN_PSK
```

Then launch the client, replacing VM_EXTERNAL_IP:

```bash
sudo env VPN_PSK="$VPN_PSK" .venv/bin/python vpn.py --mode client --peer-ip VM_EXTERNAL_IP --state-file /var/lib/pyvpn/client-multi.sqlite --internet --verbose
```

Expect Tunnel ready only after authentication and IP assignment. A TUN interface may exist while startup is still in progress, so its existence alone is not proof of connection.

The server command is:

```bash
sudo env VPN_PSK="$VPN_PSK" .venv/bin/python vpn.py --mode server --state-file /var/lib/pyvpn/server-multi.sqlite --internet --verbose
```

The server deliberately omits --peer-ip to accept any PSK-authenticated client address. Keep server and client configurations separate.

## 4. Launch contract for a managed UI

The command executed by an authorized privileged backend launcher is equivalent to this argument list:

```python
backend_argv = [
    absolute_python_path,  # project's .venv/bin/python
    absolute_vpn_path,
    "--mode", "client",
    "--peer-ip", validated_server_ipv4,
    "--state-file", profile_state_path,
    "--verbose",
]
if route_internet:
    backend_argv.append("--internet")
```

Pass VPN_PSK privately in the backend process environment, rather than adding --psk to arguments. Use absolute executable/script/state paths and an explicit working directory. Construct an argument list; do not interpolate UI values into a shell command or use shell=True. Validate input on the privileged side as well as in the UI.

The state file path should be stable for a profile on that device, inside a root-owned mode-0700 directory. The backend creates a mode-0600 file. A different server address or PSK needs a different profile/state path; show the actual state mismatch error instead of silently deleting data. Two devices may use the same local filename but must create independent file contents.

### Linux privileges are required

An unprivileged browser/desktop process cannot create TUN, change routes, or signal an unrelated root-owned VPN process. Simply spawning sudo with redirected pipes is not a complete privilege integration: password prompting and later disconnect ownership need to work.

For the first UI prototype, start the backend in a terminal as above and make the UI read-only: status, counters, exit IP, logs if available, and downloads. Clearly label Connect/Disconnect as not managed until implemented.

For actual managed Connect/Disconnect, implement a narrow privileged launcher/service (for example, with an OS authorization prompt) that owns the backend process and can signal it. Its interface must validate fixed executable paths, allowed options, and profile state paths. Keep the main UI unprivileged. Do not give the UI unrestricted passwordless sudo access, execute arbitrary user-provided programs as root, or collect/store the user's sudo password in the frontend. This repository currently provides the VPN CLI, not that launcher/service.

### Process lifecycle

Run the backend asynchronously and drain stderr continuously; logging uses stderr. Keep its actual process ID/ownership through the privileged launcher. Disable repeated Connect while a process is running. On Disconnect, request SIGTERM from the owning launcher and wait for exit. The backend restores internet routes on normal shutdown. Show failure if cleanup does not complete; do not use kill -9 for ordinary disconnect.

Automatic recovery happens inside vpn.py. A reconnecting status is not a reason to spawn another client. If the backend exits, display its exit code and last meaningful error. On UI closure, either disconnect cleanly or explicitly keep the background connection running with a visible way to stop it.

## 5. Read the existing stats API

Poll every two seconds:

```text
GET http://127.0.0.1:5000/stats
```

An example client response is:

```json
{
  "bytes_sent": 10432,
  "bytes_received": 3044,
  "packets_sent": 76,
  "packets_received": 40,
  "dropped_auth": 0,
  "dropped_replay": 0,
  "dropped_malformed": 0,
  "last_seen": 1792084736.9516377,
  "connection_state": "connected",
  "reconnects": 1,
  "internet_ipv4": true
}
```

These are example values, not current live state. connecting/connected/reconnecting are backend client values. A transport failure when fetching stats may mean the process has not started, has exited, or the port belongs to another process; use process ownership and lifecycle alongside polling.

last_seen is Unix time for accepted authenticated traffic, including keepalives. It is not a measured round-trip latency. Byte counters describe inner IP data and reset when the process restarts; they are not total outer UDP bytes. Compute display rates from successive byte samples divided by elapsed time, resetting the rate if counters decrease. Label any such rates as UI-derived, not a new backend field.

The client API currently has **no assigned_ip or public_ip field**. Obtain the assigned address from the Tunnel ready log or a read-only `ip -j -4 addr show dev tun0` query. While connecting it can still show a temporary 10.8.0.2 address, so display it as assigned only after connected status. Fetch the public address separately over IPv4. The server API adds active_clients and clients; a laptop should not confuse that server endpoint with its own local client stats.

### Browser-based UI restriction

The current HTTP server serves only the basic dashboard and GET /stats. It does not provide POST /connect, POST /disconnect, downloads, authentication, or CORS headers. A React/Vite page on another origin cannot assume direct fetch access to it.

Use a local application backend to poll the stats and pass them to the UI, or an appropriate same-origin proxy. If adding browser control endpoints, authenticate local requests and protect against cross-site requests; keep privileged process control behind the narrow launcher boundary. Do not expose an unauthenticated root command API on 0.0.0.0. A browser frontend cannot directly spawn the VPN CLI.

## 6. Public exit IP and location demonstration

The UI label should be **IPv4 internet through VPN** or **IPv4 exit-node mode**. --internet on the server enables forwarding/NAT. --internet on the client changes IPv4 routing while keeping the server UDP connection on the physical network.

To fetch the address with an IPv4-only request:

```bash
curl --noproxy '*' -4 --max-time 15 https://api.ipify.org
```

Record the result before connection and fetch it again after connected status. With routing working, the latter should equal the VM's external IPv4. Do not reuse a cached pre-connection result. If lookup fails, keep VPN status based on the backend and report exit-IP lookup unavailable rather than inventing an address.

IP-location websites generally associate that IP with a region; their database can be approximate. The UI does not select a country by itself: the cloud VM placement and its assigned address determine the exit location. A browser may prefer IPv6, use a proxy, or use separate secure DNS, so a browser result alone is not an IPv4 routing test. This implementation does not claim IPv6/DNS leak prevention or a complete kill switch.

## 7. Public internet download command

The download command connects directly over IPv4 and preserves HTTPS certificate checking:

```bash
mkdir -p results
.venv/bin/python file_transfer.py download --url https://www.rfc-editor.org/rfc/rfc791.txt --output results/rfc791.txt
```

For a publisher-provided expected digest:

```bash
.venv/bin/python file_transfer.py download --url HTTPS_FILE_URL --output results/download.bin --sha256 EXPECTED_64_HEX_DIGEST
```

Invoke the download tool as a normal unprivileged process with an argument list. It uses whichever routes are active; connected status plus --internet is needed to send public downloads through the gateway. Do not pass the PSK to the download utility. Reject an already existing destination or let the user choose another filename; downloads never overwrite files. A completed download without an expected hash reports the computed digest but not independent content verification.

The current tool prints its final result; it has no structured progress API. For an initial UI show an indeterminate download indicator and the final bytes/hash/exit status. Do not invent percentage progress from log lines. Choose whether cancel removes temporary files and implement that deliberately if adding cancellation; abrupt process termination does not currently guarantee temporary-file cleanup.

For the controlled integrity demonstration, use the existing serve/receive commands in [INTERNET_DEMO.md](INTERNET_DEMO.md). File serving on 10.8.0.1 needs no public TCP 8000 firewall allowance.

## 8. Acceptance checks for your classmate

- Connect to the running server with the same PSK and show the actual assigned address.
- Connect a second device simultaneously: it must receive a different tunnel address.
- Confirm both devices can ping 10.8.0.1 and reach IPv4 internet through the same cloud exit IP.
- Stop/restart one client and verify that the second client remains connected.
- Show reconnecting while the server is unavailable; do not create duplicate processes.
- Download a public file and display its byte count and SHA-256.
- Demonstrate server-to-client checksum-verified transfer.
- Disconnect cleanly and verify ordinary IPv4 routing returns.
- Display wrong-PSK, port-conflict, missing-TUN, and state-mismatch errors honestly.
- Keep PSKs out of logs, source control, screenshots, frontend storage, and URLs.

An initial UI can work with the current CLI and read-only stats. A polished managed desktop/web app requires the additional lifecycle and privilege integration described above; those APIs do not already exist in this repository.
