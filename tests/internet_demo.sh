#!/usr/bin/env bash
# Privileged, isolated gateway/NAT/file-transfer test; no host default-route changes.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $EUID -eq 0 ]] || { echo 'Run with sudo'; exit 1; }
for tool in ip iptables curl python3; do command -v "$tool" >/dev/null || { echo "Missing: $tool"; exit 1; }; done
python3 -c 'import cryptography'
if ip netns list | cut -d' ' -f1 | grep -qx public_ns; then echo 'public_ns exists; choose a clean test environment'; exit 1; fi
mkdir -p results
bash setup_ns.sh
created_public=0
cleanup() {
  bash teardown_ns.sh
  if [[ $created_public -eq 1 ]]; then
    pids=$(ip netns pids public_ns)
    if [[ -n "$pids" ]]; then kill $pids 2>/dev/null || true; fi
    ip netns del public_ns
  fi
}
trap cleanup EXIT
ip netns add public_ns
created_public=1
ip link add vpn_wan type veth peer name vpn_web
ip link set vpn_wan netns server_ns
ip link set vpn_web netns public_ns
ip -n server_ns addr add 203.0.113.1/24 dev vpn_wan
ip -n public_ns addr add 203.0.113.2/24 dev vpn_web
ip -n server_ns link set vpn_wan up
ip -n public_ns link set vpn_web up
ip -n public_ns link set lo up
ip -n server_ns route add default via 203.0.113.2
export VPN_PSK=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
python3 -c 'from pathlib import Path; import os; Path("results/gateway-source.bin").write_bytes(os.urandom(1024*1024))'
ip netns exec server_ns python3 vpn.py --mode server --peer-ip 192.0.2.2 --internet >results/gateway-server.log 2>&1 &
ip netns exec client_ns python3 vpn.py --mode client --peer-ip 192.0.2.1 --internet >results/gateway-client.log 2>&1 &
ready=0
for _ in {1..150}; do
  if ip -n client_ns route show exact 0.0.0.0/1 | grep -q tun0; then ready=1; break; fi
  sleep 0.1
done
[[ $ready -eq 1 ]] || { cat results/gateway-server.log results/gateway-client.log; exit 1; }
ip netns exec public_ns python3 file_transfer.py serve --file results/gateway-source.bin --bind 203.0.113.2 >results/gateway-file.log 2>&1 &
for _ in {1..50}; do
  if ip netns exec client_ns curl --noproxy '*' -fsS --max-time 1 http://203.0.113.2:8000/manifest >results/gateway-manifest.json; then break; fi
  sleep 0.1
done
# Test through tunnel -> server FORWARD -> MASQUERADE -> external namespace.
# public_ns has no route to 10.8.0.0/24, so the return path requires NAT.
ip netns exec client_ns python3 file_transfer.py receive --url http://203.0.113.2:8000 --output "results/gateway-received-$$.bin" | tee results/gateway-transfer.txt
cmp results/gateway-source.bin "results/gateway-received-$$.bin"
ip netns exec client_ns ping -c 3 -W 2 10.8.0.1
# Graceful shutdown must restore the client's /1 routes and server ip_forward.
client_pid=$(ip netns pids client_ns | head -1)
kill -TERM "$client_pid"
for _ in {1..50}; do
  if [[ -z $(ip -n client_ns route show exact 0.0.0.0/1) ]]; then break; fi
  sleep 0.1
done
[[ -z $(ip -n client_ns route show exact 0.0.0.0/1) ]]
[[ -z $(ip -n client_ns route show exact 128.0.0.0/1) ]]
echo 'PASS: isolated IPv4 gateway, NAT, checksum-verified external file transfer, and client route cleanup'
