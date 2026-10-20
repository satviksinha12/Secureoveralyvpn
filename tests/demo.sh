#!/usr/bin/env bash
# Uses namespaces dedicated to this project; cleans them up on exit.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $EUID -eq 0 ]] || { echo 'Run with sudo'; exit 1; }
for tool in ip python3 tcpdump iperf3; do command -v "$tool" >/dev/null || { echo "Missing: $tool"; exit 1; }; done
python3 -c 'import cryptography'
mkdir -p results
bash setup_ns.sh
trap 'bash teardown_ns.sh' EXIT
export VPN_PSK=${VPN_PSK:-$(python3 -c 'import secrets; print(secrets.token_hex(32))')}
ip netns exec server_ns python3 vpn.py --mode server --peer-ip 192.0.2.2 --verbose >results/server.log 2>&1 &
ip netns exec client_ns python3 vpn.py --mode client --peer-ip 192.0.2.1 --verbose >results/client.log 2>&1 &
ready=0
for _ in {1..100}; do
  if ip -n client_ns addr show tun0 >/dev/null 2>&1 && ip -n server_ns addr show tun0 >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.1
done
[[ $ready -eq 1 ]] || { cat results/server.log results/client.log; exit 1; }
ip netns exec server_ns tcpdump -U -i veth_s -w results/tunnel.pcap 'udp port 5555' >results/tcpdump.log 2>&1 &
capture_pid=$!
ip netns exec server_ns python3 tests/attack.py >results/attacks.json 2>&1 &
attack_pid=$!
sleep 1
ip netns exec client_ns ping -c 5 -W 2 10.8.0.1 | tee results/ping.txt
wait "$attack_pid"
ip netns exec server_ns iperf3 -s >results/iperf-server.log 2>&1 &
sleep 0.3
ip netns exec client_ns iperf3 -c 192.0.2.1 -t 5 -J >results/direct.json
ip netns exec client_ns iperf3 -c 10.8.0.1 -t 5 -J >results/tunnel.json
kill -INT "$capture_pid"
wait "$capture_pid" || true
python3 tests/report.py
cat results/benchmark.md
cat results/attacks.json
