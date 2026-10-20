#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run with sudo'; exit 1; }
for ns in client_ns server_ns; do
  if ip netns list | cut -d' ' -f1 | grep -qx "$ns"; then
    pids=$(ip netns pids "$ns")
    if [[ -n "$pids" ]]; then kill $pids 2>/dev/null || true; fi
    ip netns del "$ns"
  fi
done
