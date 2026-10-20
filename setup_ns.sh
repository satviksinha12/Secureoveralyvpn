#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run with sudo'; exit 1; }
[[ -c /dev/net/tun ]] || { echo '/dev/net/tun missing: load tun module on the host'; exit 1; }
for ns in client_ns server_ns; do
  if ip netns list | cut -d' ' -f1 | grep -qx "$ns"; then
    echo "$ns already exists; run teardown_ns.sh first"; exit 1
  fi
done
trap 'bash "$(dirname "$0")/teardown_ns.sh"' ERR
ip netns add client_ns
ip netns add server_ns
ip link add veth_c type veth peer name veth_s
ip link set veth_c netns client_ns
ip link set veth_s netns server_ns
ip -n client_ns addr add 192.0.2.2/24 dev veth_c
ip -n server_ns addr add 192.0.2.1/24 dev veth_s
for ns in client_ns server_ns; do ip -n "$ns" link set lo up; done
ip -n client_ns link set veth_c up
ip -n server_ns link set veth_s up
