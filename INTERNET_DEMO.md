# Public IPv4 internet and file-transfer demonstration

This adds two capabilities: optional client IPv4 internet routing through the cloud server, and a file-transfer demo with SHA-256 verification. File transfer between 10.8.0.1 and 10.8.0.2 also works without internet routing.

## 1. Update your manually uploaded cloud installation

Stop both VPN processes with Ctrl+C. In SSH-in-browser upload these **three** laptop files:

- vpn.py
- internet.py
- file_transfer.py

They must be in the same project folder. On the VM, assuming the uploads landed in your home directory:

```bash
mv ~/vpn.py ~/internet.py ~/file_transfer.py ~/vpn-project/
cd ~/vpn-project
sudo apt-get update
sudo apt-get install -y iptables curl
```

No additional Python package is needed. The laptop already has the updated files if it is the working checkout; otherwise update its checkout or copy all three files there too.

## 2. Start both VPN endpoints with --internet

Keep the current matching PSK and current state paths. **Do not rotate keys or create new state files just for this feature.** Enter the existing PSK again if your shell lost VPN_PSK. For Fish, run `bash` alone first, then `read -rsp "Shared PSK: " VPN_PSK` and paste it invisibly.

On the VM, in its VPN terminal:

```bash
cd ~/vpn-project
sudo env VPN_PSK="$VPN_PSK" .venv/bin/python vpn.py --mode server --peer-ip HOME_PUBLIC_IP --state-file /var/lib/pyvpn/server-v4.sqlite --internet --verbose
```

On the laptop, in its project folder:

```bash
sudo env VPN_PSK="$VPN_PSK" .venv/bin/python vpn.py --mode client --peer-ip VM_EXTERNAL_IP --state-file /var/lib/pyvpn/client-v4.sqlite --internet --verbose
```

Replace the IP placeholders with **current numeric IPv4 addresses**. If your working state files have different names, retain those actual names. The server's expected home IP is the physical Wi-Fi public address, not the VM egress IP you will observe through the tunnel. Identify it before enabling client internet mode.

The VPC rule still permits UDP 5555. Public internet forwarding needs outbound internet access from the VM and a functioning external IPv4 mapping. No inbound TCP 8000 opening is needed for the tunnel file demo.

## 3. Check the public exit address

Once both show Tunnel ready, on the laptop:

```bash
ip route get 1.1.1.1
ip route get VM_EXTERNAL_IP
curl --noproxy '*' -4 --max-time 30 https://api.ipify.org
echo
```

Replace VM_EXTERNAL_IP in the second command. Expect 1.1.1.1 to use tun0 with source 10.8.0.2, but the VM's external IP to use the physical Wi-Fi interface. The curl result should match the VM's external IP, rather than your home public IP. Run that same curl command on the VM to compare.

On the VM:

```bash
sysctl net.ipv4.ip_forward
sudo iptables -t nat -vnL POSTROUTING
sudo iptables -vnL FORWARD
```

The program enables Linux forwarding and installs MASQUERADE for source 10.8.0.2/32 on the physical egress interface. It permits related return traffic and clamps TCP MSS toward TUN. Source NAT replaces the tunnel source with the VM NIC address before packets enter Google Cloud's network. Therefore this specific NAT design does not emit arbitrary 10.8.x.x sources onto the VPC. A deployment without source NAT or one using VPC next-hop routes has different requirements; consult [Google Cloud IP forwarding guidance](https://docs.cloud.google.com/vpc/docs/using-routes#canipforward).

## 4. Transfer a file through the encrypted VPN

Use a separate SSH terminal so the VPN process keeps running. On the VM, create a 5 MiB demonstration file and serve **only that file** on the tunnel address:

```bash
cd ~/vpn-project
mkdir -p results
python3 -c 'from pathlib import Path; import os; Path("results/demo.bin").write_bytes(os.urandom(5 * 1024 * 1024))'
sha256sum results/demo.bin
.venv/bin/python file_transfer.py serve --file results/demo.bin --bind 10.8.0.1 --port 8000
```

On the laptop, from its project directory:

```bash
mkdir -p results
.venv/bin/python file_transfer.py receive --url http://10.8.0.1:8000 --output results/received-demo.bin
sha256sum results/received-demo.bin
```

Expected: `PASS: received 5242880 bytes; SHA-256 ...`, with the same SHA-256 as on the server. The tool downloads into a temporary file, checks both byte count and SHA-256, and creates the chosen output only when verification succeeds. It refuses to overwrite an existing output: choose another filename on subsequent runs.

The file service uses HTTP inside the AES-GCM tunnel, binds only the selected tunnel address, and serves no directory listing. It is a demo utility rather than a general authenticated web upload service. Its /manifest endpoint advertises the filename, length, and SHA-256. Do not change the source file while it is being served.

For a laptop-to-server transfer, serve a laptop file with `--bind 10.8.0.2`; on the VM use `receive --url http://10.8.0.2:8000 --output results/from-laptop.bin`. Both directions use TCP carried by the encrypted VPN. Neither needs public internet mode.

## 5. Download a file from the public internet through the VM

On the laptop while --internet is active:

```bash
curl --noproxy '*' -4 -fL --max-time 120 https://www.rfc-editor.org/rfc/rfc791.txt -o results/rfc791.txt
wc -c results/rfc791.txt
sha256sum results/rfc791.txt
```

The route check and exit-IP check establish the IPv4 egress path. A successful public download and increasing VPN counters demonstrate internet data transfer; the checksum above identifies the downloaded bytes but is not independently verified against a publisher checksum. For a conclusive repeatable file-integrity demo, use the known server file and manifest in step 4.

Collect screenshots of the route/exit IP, file-transfer PASS with matching hashes, dashboard counter growth, and server NAT counters. A physical-interface capture on the laptop shows encrypted UDP to the VM, while the server egress carries ordinary forwarded traffic (HTTPS remains encrypted by TLS).

## 6. Cleanup and limitations

Stop file_transfer.py with Ctrl+C in its own terminal. Stop the VPN processes with Ctrl+C when finished. Graceful shutdown removes only the route/firewall entries created by this process and restores the previous ip_forward value if it changed it. Normal reconnection keeps client internet routes installed, so IPv4 internet may pause during tunnel outages instead of falling back automatically.

The client preserves its normal default route and adds two more-specific /1 routes through TUN. A /32 exception keeps the UDP server endpoint on the original physical route. Existing more-specific routes, including the local LAN, still win. Existing TCP connections may need restarting because their source address was chosen before enabling the tunnel. Routes are in the main IPv4 table; other VPN software and custom policy routing can interfere.

This is **IPv4 internet routing**, not an IPv6 or DNS leak-prevention product. Use curl -4 for the demo; native IPv6 and local-LAN DNS can still use the physical network. The program does not rewrite resolver configuration. If DNS fails, inspect the existing resolver; a local Wi-Fi DNS address may be reached directly by its more-specific LAN route. No IPv6 internet gateway is configured.

Do not use kill -9 or Ctrl+Z for normal shutdown: abrupt termination can leave firewall rules and /1 routes behind. Reboot clears these nonpersistent changes, or inspect/remove the exact entries created by this feature:

```bash
# Laptop only, after the VPN has stopped:
sudo ip -4 route del 0.0.0.0/1 dev tun0
sudo ip -4 route del 128.0.0.0/1 dev tun0
# Inspect any leftover endpoint host route before removing it:
ip -4 route show

# VM: inspect rules tagged pyvpn-internet (never flush the whole firewall):
sudo iptables-save | grep pyvpn-internet
```

Missing routes during cleanup are harmless. On the VM, delete only the tagged entries with iptables -D and the corresponding table/chain/rule arguments. Account for other services before changing ip_forward; do not disable it if another service uses forwarding. Uninstalling the VPN is not a reason to clear unrelated firewall rules.

## 7. Validation status

Automated checks cover routing command ordering, preservation of existing endpoint routes, rollback after partial setup failure, narrow NAT rules and restoration, actual local HTTP transfer of a 1 MiB file, and rejection of a bad checksum. These use mocked routing commands; they do not alter the test host's routes.

For privileged, isolated integration testing:

```bash
sudo env PATH="$PWD/.venv/bin:$PATH" bash tests/internet_demo.sh
```

It creates client_ns, server_ns, and public_ns, refusing existing namespace names. The external namespace has no return route to 10.8.0.0/24, so successful file transfer tests server NAT as well as tunneling. It cleans up its namespaces on exit and tests client route removal. The host default route is not changed. This is a simulated external network, not a live public internet/cloud measurement. The privileged integration test was attempted in development but sudo required a password, so it was not executed. Cloud exit-IP and actual public downloads still need to be demonstrated on your VM.
