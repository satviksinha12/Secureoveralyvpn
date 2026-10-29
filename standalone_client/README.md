# Secure VPN Desktop Client — standalone project

This folder is independent of the original ui/ folder. Copy the **entire standalone_client folder**, or extract the supplied ZIP, onto another machine. It contains its own UI, Linux launcher, VPN backend, download tool, and static assets. No files in the parent project are required.

## Platform support

| Feature | Linux | Windows |
| --- | --- | --- |
| Local browser interface | Yes | Yes, Python 3.10+ |
| Public IPv4 file downloads | Yes | Yes |
| Public-IP lookup | Yes | Yes |
| Native VPN Connect/Disconnect | Yes, with privileged launcher | Not yet implemented |
| Download cancellation | Yes | Disabled in preview |

**Windows UI support is not native Windows VPN support.** TUN, iproute2, and the privileged launcher are Linux-specific. Windows displays an explicit preview banner and disables VPN controls. Public downloads there use the ordinary Windows network connection. The server's custom protocol is not a Windows built-in VPN profile; WSL also does not automatically tunnel the Windows host's browser traffic.

The interface uses the standard library and ordinary HTML/CSS/JS; no Node build or GUI toolkit install is required. Only Linux VPN operations require cryptography. The application binds to loopback and opens an authenticated, per-run browser URL.

## Windows: run the interface

1. Install Python 3.10 or newer if absent.
2. Extract the standalone client ZIP into a folder you can write to.
3. Double-click **start-client.cmd**. Keep the console open.
4. The browser opens automatically. If it does not, copy the complete URL printed in the console, including its token. Do not share that token.

Or run in PowerShell from this folder:

```powershell
py -3 app.py
```

To open the browser yourself:

```powershell
py -3 app.py --no-browser
```

No sudo, Linux virtual environment, cloud upload, or shared VPN secret is needed for Windows preview. Do not copy a Linux .venv to Windows. The .cmd file uses a local Windows virtual environment when present, otherwise the installed Python.

## Linux: actual VPN client

First stop any client previously launched from the original UI/terminal. Both copies would otherwise compete for tun0 and the backend dashboard port.

From **this folder**:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
sudo modprobe tun
```

Open terminal 1 here and run:

```bash
bash start-launcher.sh
```

Open terminal 2 here and run:

```bash
bash start-client.sh
```

The launcher requests sudo authorization in terminal 1. The interface stays unprivileged. It uses its own launcher socket `/run/pyvpn-desktop/launcher.sock`, state directory `/var/lib/pyvpn-desktop`, and UI port **8876**. The underlying TUN and dashboard port 5000 still require one client instance per machine.

Enter the running cloud server's numeric external IPv4 and matching PSK. Keep IPv4 internet through VPN checked for exit-node routing. Click Connect. The cloud server must already run the compatible protocol-v3 multi-client backend; no standalone client files need uploading to it.

The launcher derives a private state filename per server address. Reuse the same PSK for future starts; changing a PSK intentionally produces a state mismatch and requires an explicit new profile/state directory. Never copy state files between devices, restore old state snapshots, or delete them merely to hide an error. The server assigns each device its own tunnel IP and learns its source UDP port automatically.

Without the launcher, Linux can use read-only monitoring and downloads. The app does not silently request unrestricted sudo privileges. For a permanent installation, use a root-owned copy and the launcher's --strict option as described in its --help output.

## Download a file

Use the Download card with a public HTTPS URL. A filename without an absolute path is saved under this folder's results/ directory. Existing files are never overwritten. Supplying a trusted publisher's SHA-256 enables independent checksum verification.

On Linux with --internet routing active, the download uses the VPN's IPv4 path. In Windows preview, no VPN routes are created, so it uses normal internet access. The download tool forces IPv4 and retains HTTPS certificate verification. Wait for completion before closing Windows preview; cancellation there is deliberately disabled until Windows process-lifecycle support is implemented.

## Troubleshooting

- **Invalid token:** close old tabs and use the newest complete URL from the currently running app. Tokens change on restart.
- **Page waiting:** start with --no-browser and open the printed URL yourself. The server starts before invoking the desktop browser helper.
- **Port 8876 busy:** stop the earlier app, or run app.py --port 8877.
- **Linux dashboard port busy:** stop the original VPN client before starting this separate client.
- **Connected but websites fail:** verify DNS separately; this IPv4 backend does not automatically configure a resolver. Do not assume connected means internet/DNS is healthy.
- **IPv6/local location still visible:** native IPv6 and local DNS can bypass the IPv4 tunnel. This is not complete leak protection.
- **Windows Connect disabled:** expected. A Windows tunnel adapter/driver, privileged service, and routing integration are future work.

## Before adding native Windows VPN support

Implement a Windows-specific transport behind the existing launcher contract: validated start/status/logs/stop operations, a Windows TUN adapter, protocol-v3 sessions, durable nonce/replay state, IPv4 routing/NAT endpoint exceptions, resolver policy, and reliable cleanup. Use the existing cryptography library; do not create new ciphers. Named pipes or another authenticated local IPC mechanism should replace the Linux-only launcher socket and UID check.

Current tests simulate Windows capability reporting and separately verify the standalone folder's HTTP interface on Linux. Actual Windows execution and native Windows routing have not been tested from this Linux environment.

## Source relationship

Backend files were copied from the current reviewed project; the interface and launcher were adapted to this folder's paths and explicit platform capabilities. The original ui/ folder is unchanged. This is now a separate copy: later backend changes must be synchronized deliberately and retested before publishing a new client ZIP.
