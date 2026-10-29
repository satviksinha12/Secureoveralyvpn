# UI client

A local web UI for the Secure Overlay VPN client, built to [UI_CLIENT_GUIDE.md](../UI_CLIENT_GUIDE.md).
It adds no dependencies beyond the backend's `cryptography`: the UI service uses only the Python
standard library and the frontend is plain HTML/CSS/JS with no build step.

```text
Browser (127.0.0.1:8765)
   │  cookie + X-PyVPN-UI header, same-origin only
   ▼
ui/app.py            unprivileged; serves the page, polls the backend's /stats, looks up the exit IPv4,
   │                 runs file_transfer.py downloads
   │  Unix socket, one JSON line per request, peer UID checked
   ▼
ui/launcher.py       root; owns exactly one `vpn.py --mode client` process, validates every field,
   │                 redacts logs, stops it with SIGTERM (never SIGKILL)
   ▼
vpn.py               unchanged backend
```

`vpn.py`, `multi_server.py`, `internet.py` and `file_transfer.py` are untouched.

## Run it (Linux)

Backend prerequisites are those in [TEAM_SETUP.md](../TEAM_SETUP.md) (iproute2, TUN, Python 3.10+).

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
sudo modprobe tun
```

Terminal 1, the privileged launcher. It asks for your sudo password here, never in the UI:

```bash
sudo .venv/bin/python ui/launcher.py
```

Terminal 2, the UI as your normal user. It prints a one-time URL and opens your browser:

```bash
.venv/bin/python ui/app.py
```

Enter the VM's external IPv4 and the shared PSK, then press **Connect**. The server operator starts the
server first, as in the guide; UDP 5555 must be reachable.

Without the launcher the UI still works as a **read-only monitor** and downloader, and Connect/Disconnect are
labelled *not managed*. It also detects and monitors a client you started by hand
(`sudo env VPN_PSK=... .venv/bin/python vpn.py --mode client ...`) on the dashboard port.

On macOS/Windows the UI starts, but there is no TUN backend, so only the not-managed/read-only view and
downloads are usable.

### Options

| Command | Option | Purpose |
| --- | --- | --- |
| `ui/app.py` | `--port 8765` | UI port (loopback only; non-loopback binds are refused) |
| | `--launcher-socket PATH` | Default `/run/pyvpn-ui/launcher.sock` |
| | `--keep-connection` | Leave a connection running when the UI exits (default: disconnect first) |
| | `--ip-service URL` | IPv4 lookup endpoint, default `https://api.ipify.org` |
| | `--no-browser` | Do not open a browser |
| `ui/launcher.py` | `--uid N` | User allowed to use it (default: `SUDO_UID`/`PKEXEC_UID`) |
| | `--strict` | Refuse to run unless the backend files are root-owned |
| | `--state-dir DIR` | Default `/var/lib/pyvpn` (created `0700`) |

Stopping the launcher with Ctrl+C also disconnects, waiting for route cleanup.

## What the guide asked for, and where it lives

| Guide requirement | Implementation |
| --- | --- |
| Server IPv4, masked PSK ≥ 16 bytes, no logging or URL parameters | Form validates in the browser, `app.py`, and again in the launcher. The PSK travels in a POST body, then the backend's environment; it is cleared from the page after submit and never stored. |
| Route IPv4 internet (`--internet`), default on | Checkbox, on by default. |
| Connect / Disconnect through a privilege mechanism | `launcher.py`. Repeat Connect is refused while a process exists. Disconnect sends SIGTERM and waits; if cleanup stalls the UI says so and does not kill -9. |
| Status: disconnected, starting, connecting, connected, reconnecting, error | Derived from launcher process state plus the backend's `connection_state`. A transient *disconnecting* state is also shown. |
| Real assigned tunnel IP, only once connected | Read from `ip -j -4 addr show dev tun0`, falling back to the `Tunnel ready` log line. Never hardcoded. |
| Traffic, 2 s refresh, UI-derived rates | Polled every 2 s; rates computed in the browser and reset when counters decrease. |
| Auth / replay / malformed counters | Shown, highlighted when non-zero. |
| Fresh IPv4-only exit IP, baseline before connecting | Baseline recorded just before Connect; a new lookup runs once per connection. Lookup failure is reported and does not alter VPN status. |
| Non-blocking, redacted logs | Launcher drains stderr on a thread into a bounded buffer and redacts the PSK. |
| Public download, existing tool, argument list, no PSK, no overwrite | `file_transfer.py download` as the user, with `VPN_PSK` removed from its environment. Indeterminate progress; final bytes and SHA-256; Cancel sends SIGINT so the tool deletes its temp file. The *File served over the VPN* mode runs the existing `receive` command (checksum-verified against the server manifest). |
| No client port or router configuration | Ephemeral client port is the backend default; advanced panel exposes only server port and dashboard port. |
| Honest errors (state mismatch, port conflict, TUN) | Backend's last `ERROR` line and exit code are shown; a busy dashboard port is reported before launching. Nothing is deleted or reset to hide an error. |
| Disconnect or visibly keep running when the UI closes | Default: UI disconnects before exiting. `--keep-connection` leaves it running and shows a Disconnect control next time. |

## Security model

* The UI binds to loopback and requires a random per-run token (set as an `HttpOnly`, `SameSite=Strict` cookie, then
  removed from the address bar). Requests need a matching `Host`, a same-origin `Origin`, and a custom
  `X-PyVPN-UI` header, which blocks DNS rebinding and cross-site requests. Responses carry a restrictive CSP.
* The launcher socket is `0600`, owned by the invoking user, and the peer UID is checked. It accepts only
  `status`, `start`, `stop` and `logs`. `start` builds a fixed argument list (project `.venv/bin/python`, `vpn.py`,
  validated IPv4 and ports) and a state path of the form `/var/lib/pyvpn/client-<ip>.sqlite` computed by the
  launcher, never supplied by the UI. No shell, no arbitrary executable, minimal environment.
* The PSK is never in argv, status replies, or logs.
* **Residual risk:** the launcher runs project files as root. It refuses files writable by group/others and warns if
  they are owned by a non-root user, because that user could edit `vpn.py` and then use the launcher. This is the same
  trust you already extend by running `sudo .venv/bin/python vpn.py`, but only while the launcher is running. For a
  persistent service install the project root-owned and use `--strict`.
* Changing the PSK for the same server address hits the backend's *State belongs to another mode, peer, or PSK*
  error, as the guide intends. Use the server's matching PSK, or a different server address (a different state file).

## Tests

```bash
.venv/bin/python -m unittest discover -s tests -v
```

`tests/test_ui.py` covers validation, redaction, the launcher lifecycle against `tests/fake_vpn.py` (a stand-in
backend that needs neither root nor TUN), access control, the full app + launcher stack, and downloads including
cancel. On macOS seven pre-existing tests (`test_recovery`, `test_multi`) error with *database is locked*: this
happens on an untouched checkout too and is a macOS flock/SQLite interaction. They pass on Linux.

## Known limitations

* Managed Connect needs Linux, root (via the launcher), and a running server; it cannot be exercised on macOS.
* `file_transfer.py download` cannot detect a truncated body unless you give an expected SHA-256 (it only checks
  length when a size is supplied). Supply the publisher's hash for independent verification.
* The UI does not claim IPv6/DNS leak protection or a kill switch; neither exists in the backend.
* Exit-IP matching assumes the VM's egress address equals its external address; clouds with a separate NAT address
  will show "differs from before connecting" instead of a match.
