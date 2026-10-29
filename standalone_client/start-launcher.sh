#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
[[ -x .venv/bin/python ]] || { echo 'First run: python3 -m venv .venv, then .venv/bin/python -m pip install -r requirements.txt'; exit 1; }
exec sudo .venv/bin/python launcher.py "$@"
