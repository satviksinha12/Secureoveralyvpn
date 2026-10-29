'use strict';
const $ = (id) => document.getElementById(id);
const LABELS = { disconnected: 'Disconnected', starting: 'Starting', connecting: 'Connecting', connected: 'Connected',
  reconnecting: 'Reconnecting', disconnecting: 'Disconnecting', error: 'Error' };
const RUNNING = ['starting', 'connecting', 'connected', 'reconnecting'];
const LAUNCHER_CMD = 'sudo .venv/bin/python launcher.py';

let last = null;          // last status payload
let busy = false;         // a Connect/Disconnect request is in flight
let logSeq = 0;
let sample = null;        // previous traffic sample for UI-derived rates
const history = [];       // [tx, rx] bytes/s
const HISTORY = 60;

async function api(path, body) {
  const options = body === undefined ? {} : {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-PyVPN-UI': '1' }, body: JSON.stringify(body) };
  const controller = new AbortController();
  options.signal = controller.signal;
  const timer = setTimeout(() => controller.abort(), 30000);
  let response;
  try {
    response = await fetch(path, options);
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('Local service timed out. Check the app terminal and try again.');
    throw error;
  } finally {
    clearTimeout(timer);
  }
  let data = {};
  try { data = await response.json(); } catch (e) { /* non-JSON error page */ }
  if (!response.ok) {
    const error = new Error(data.error || (response.status === 401 || response.status === 403
      ? 'Session expired. Reopen the URL printed by app.py.' : 'Request failed (' + response.status + ')'));
    error.status = response.status;
    throw error;
  }
  return data;
}

function fmtBytes(n) {
  if (!Number.isFinite(n)) return '–';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? String(Math.round(n)) : n.toFixed(n < 10 ? 2 : 1)) + ' ' + units[i];
}
const fmtRate = (n) => fmtBytes(n) + '/s';
const fmtInt = (n) => Number(n).toLocaleString();

function show(el, visible) { el.hidden = !visible; }

function setError(el, message) { el.textContent = message || ''; show(el, !!message); }

function banner(kind, title, text, code) {
  const div = document.createElement('div');
  div.className = 'banner ' + kind;
  const strong = document.createElement('strong');
  strong.textContent = title;
  div.appendChild(strong);
  div.appendChild(document.createTextNode(text));
  if (code) {
    div.appendChild(document.createElement('br'));
    const c = document.createElement('code');
    c.textContent = code;
    div.appendChild(c);
  }
  return div;
}

function renderBanners(s) {
  const box = $('banners');
  box.replaceChildren();
  if (s.native_vpn_supported === false) {
    box.appendChild(banner('info', 'Windows / macOS interface preview',
      'The interface and public file downloads work here. Native VPN connection is currently Linux-only; a Windows tunnel backend must be added before Windows traffic can use this VPN.'));
  } else if (s.mode === 'none') {
    box.appendChild(banner('warn', 'Connect and Disconnect are not managed',
      'The privileged launcher is not running, so this UI can only monitor and download. Start it in a terminal (it asks for your sudo password there, never here):',
      LAUNCHER_CMD));
  } else if (s.mode === 'external') {
    box.appendChild(banner('info', 'Read-only monitoring',
      'A VPN client started outside this UI is running. Connect and Disconnect are not managed for it; stop it in the terminal that started it.'));
  }
  if (s.status === 'error' && s.last_error) {
    const code = s.exit_code === null || s.exit_code === undefined ? '' : ' (exit code ' + s.exit_code + ')';
    box.appendChild(banner('error', 'Connection failed' + code, s.last_error));
  } else if (s.last_error && s.status === 'disconnecting') {
    box.appendChild(banner('error', 'Disconnect incomplete', s.last_error));
  }
}

function renderForm(s) {
  const managed = s.mode === 'managed';
  const active = RUNNING.includes(s.status) || s.status === 'disconnecting';
  const locked = active || !managed || busy;
  for (const id of ['server', 'psk', 'internet', 'port', 'dport']) $(id).disabled = locked;
  if (s.server_ip && !$('server').value && document.activeElement !== $('server')) $('server').value = s.server_ip;
  $('connect').disabled = locked;
  $('disconnect').disabled = !managed || busy || !(RUNNING.includes(s.status) || s.status === 'disconnecting');
  $('connect').textContent = !managed ? 'Connect (not managed)' : s.status === 'starting' ? 'Starting…' : 'Connect';
  $('disconnect').textContent = !managed ? 'Disconnect (not managed)' : s.status === 'disconnecting' ? 'Disconnect again' : 'Disconnect';
  if (s.status === 'disconnecting') $('disconnect').disabled = busy;
  const note = $('unmanaged');
  note.textContent = managed ? '' : s.native_vpn_supported === false ? 'VPN connection requires the future native backend on this platform.' : 'Start the launcher to enable these controls.';
  show(note, !managed);
}

function renderTunnel(s) {
  const pill = $('pill');
  pill.className = 'pill s-' + s.status;
  $('pill-text').textContent = LABELS[s.status] || s.status;
  $('t-status').textContent = LABELS[s.status] || s.status;
  // The backend only exposes the real address after authentication, so show it when connected.
  $('t-ip').textContent = s.status === 'connected' && s.assigned_ip ? s.assigned_ip
    : s.status === 'connected' ? 'unknown' : '–';
  $('t-server').textContent = s.server_ip || '–';
  $('t-routing').textContent = s.internet === null || s.internet === undefined ? (s.stats ? (s.stats.internet_ipv4 ? 'IPv4 internet through VPN' : 'Tunnel only') : '–')
    : s.internet ? 'IPv4 internet through VPN' : 'Tunnel only (10.8.0.0/24)';
  const st = s.stats;
  $('t-reconnects').textContent = st && st.reconnects !== undefined ? String(st.reconnects) : '–';
  if (st && st.last_seen) {
    const age = Math.max(0, Math.round(Date.now() / 1000 - st.last_seen));
    $('t-seen').textContent = age + ' s ago';
  } else {
    $('t-seen').textContent = '–';
  }
  $('detail').textContent = s.detail || '';
}

function renderTraffic(s) {
  const st = s.stats;
  if (!st) {
    sample = null;
    history.length = 0;
    for (const id of ['bytes-sent', 'bytes-recv']) $(id).textContent = '0 B';
    $('pkts-sent').textContent = $('pkts-recv').textContent = '0 packets';
    $('rate-sent').textContent = $('rate-recv').textContent = '–';
    for (const id of ['d-auth', 'd-replay', 'd-mal']) $(id).textContent = '0';
    drawSpark();
    return;
  }
  $('bytes-sent').textContent = fmtBytes(st.bytes_sent);
  $('bytes-recv').textContent = fmtBytes(st.bytes_received);
  $('pkts-sent').textContent = fmtInt(st.packets_sent) + ' packets';
  $('pkts-recv').textContent = fmtInt(st.packets_received) + ' packets';
  const now = performance.now();
  if (sample && st.bytes_sent >= sample.tx && st.bytes_received >= sample.rx && now > sample.t) {
    const dt = (now - sample.t) / 1000;
    const tx = (st.bytes_sent - sample.tx) / dt, rx = (st.bytes_received - sample.rx) / dt;
    $('rate-sent').textContent = fmtRate(tx);
    $('rate-recv').textContent = fmtRate(rx);
    history.push([tx, rx]);
  } else {
    // Counters reset (new backend process): start the rate series over.
    history.length = 0;
    $('rate-sent').textContent = $('rate-recv').textContent = '–';
  }
  if (history.length > HISTORY) history.shift();
  sample = { t: now, tx: st.bytes_sent, rx: st.bytes_received };
  for (const [id, key] of [['d-auth', 'dropped_auth'], ['d-replay', 'dropped_replay'], ['d-mal', 'dropped_malformed']]) {
    $(id).textContent = fmtInt(st[key]);
    $(id).parentElement.classList.toggle('bad', st[key] > 0);
  }
  drawSpark();
}

function drawSpark() {
  const svg = $('spark');
  svg.replaceChildren();
  if (history.length < 2) return;
  const peak = Math.max(1, ...history.flat());
  [['tx', 0], ['rx', 1]].forEach(([cls, index]) => {
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
    line.setAttribute('class', cls);
    line.setAttribute('points', history.map((v, i) =>
      (i / (HISTORY - 1) * 300).toFixed(1) + ',' + (56 - v[index] / peak * 52).toFixed(1)).join(' '));
    svg.appendChild(line);
  });
}

function ipText(entry, empty) {
  if (!entry || entry.state === 'idle') return empty;
  if (entry.state === 'loading') return 'checking…';
  if (entry.state === 'ok') return entry.ip;
  return 'unavailable';
}

function renderExit(s) {
  const x = s.exit_ip;
  $('x-before').textContent = ipText(x.baseline, '–');
  $('x-now').textContent = s.status === 'connected' ? ipText(x.current, '–') : '–';
  $('x-before').title = x.baseline.state === 'error' ? x.baseline.error : '';
  $('x-now').title = x.current.state === 'error' ? x.current.error : '';
  const verdict = $('x-verdict');
  verdict.className = 'verdict';
  verdict.textContent = '';
  if (s.status === 'connected' && x.current.state === 'ok') {
    if (s.server_ip && x.current.ip === s.server_ip) {
      verdict.textContent = 'Matches the VPN server: IPv4 traffic exits through the cloud VM.';
      verdict.classList.add('ok');
    } else if (x.baseline.state === 'ok' && x.current.ip === x.baseline.ip) {
      verdict.textContent = s.internet === false ? 'Internet routing is off, so this is your normal address.'
        : 'Same as before connecting: traffic is not exiting through the VPN.';
      verdict.classList.add('warn');
    } else {
      verdict.textContent = 'Differs from before connecting, but does not equal the server address (the VM may use a different egress IP).';
    }
  } else if (s.status === 'connected' && x.current.state === 'error') {
    verdict.textContent = x.current.error + '. VPN status is unaffected.';
    verdict.classList.add('warn');
  } else if (x.baseline.state === 'error') {
    verdict.textContent = x.baseline.error;
    verdict.classList.add('warn');
  }
  const loading = x.baseline.state === 'loading' || x.current.state === 'loading';
  $('x-refresh').disabled = loading || !['connected', 'disconnected', 'error'].includes(s.status);
  $('x-refresh').textContent = s.status === 'connected' ? 'Refresh exit IP' : 'Check current IP';
}

function renderDownload(s) {
  const job = s.download;
  const running = !!job && job.state === 'running';
  $('dl-start').disabled = running;
  $('dl-cancel').disabled = s.download_cancel_supported === false || !running || !!job.cancel_requested;
  $('dl-cancel').title = s.download_cancel_supported === false ? 'Cancellation is unavailable in the Windows preview' : '';
  show($('dl-progress'), running);
  const box = $('dl-result');
  if (!job || running) { show(box, false); return; }
  box.className = 'result ' + (job.state === 'done' ? 'ok' : job.state === 'error' ? 'bad' : '');
  box.replaceChildren();
  const first = document.createElement('div');
  first.textContent = job.state === 'done' ? 'Downloaded ' + fmtInt(job.bytes) + ' bytes' : job.message;
  box.appendChild(first);
  if (job.state === 'done') {
    for (const text of [job.message, 'SHA-256 ' + job.sha256, 'Saved to ' + job.output]) {
      const line = document.createElement('div');
      line.textContent = text;
      if (text.startsWith('SHA-256')) line.className = 'mono';
      box.appendChild(line);
    }
  }
  show(box, true);
}

function render(s) {
  last = s;
  renderBanners(s);
  renderForm(s);
  renderTunnel(s);
  renderTraffic(s);
  renderExit(s);
  renderDownload(s);
}

function appendLogs(lines) {
  if (!lines.length) return;
  const pre = $('logs');
  for (const entry of lines) {
    const span = document.createElement('div');
    span.textContent = entry.line;
    if (/\bERROR\b|Traceback|error:/.test(entry.line)) span.className = 'e';
    else if (/\bWARNING\b/.test(entry.line)) span.className = 'w';
    else if (entry.line.startsWith('[launcher]')) span.className = 'l';
    pre.appendChild(span);
  }
  while (pre.childElementCount > 600) pre.firstElementChild.remove();
  if ($('autoscroll').checked) pre.scrollTop = pre.scrollHeight;
}

async function refresh() {
  try {
    const s = await api('/api/status');
    if (s.log_seq < logSeq) { $('logs').replaceChildren(); logSeq = 0; }  // a new connection restarted the log
    render(s);
    const logs = await api('/api/logs?since=' + logSeq);
    logSeq = logs.seq;
    appendLogs(logs.lines);
  } catch (error) {
    $('pill').className = 'pill s-error';
    $('pill-text').textContent = 'UI offline';
    $('banners').replaceChildren(banner('error', 'Cannot reach the local UI service', error.message));
  }
}

function schedule() { setTimeout(async () => { await refresh(); schedule(); }, 2000); }

$('form').addEventListener('submit', async (event) => {
  event.preventDefault();
  setError($('form-error'), '');
  if (busy || !last || last.mode !== 'managed') return;
  const server = $('server').value.trim();
  const psk = $('psk').value;
  if (!/^(\d{1,3})(\.\d{1,3}){3}$/.test(server) || server.split('.').some((p) => Number(p) > 255)) {
    return setError($('form-error'), 'Enter the VM external address as a numeric IPv4 address.');
  }
  if (new TextEncoder().encode(psk).length < 16) {
    return setError($('form-error'), 'The shared secret must be at least 16 bytes.');
  }
  busy = true;
  renderForm(last);
  $('connect').textContent = 'Connecting…';
  try {
    await api('/api/connect', { server_ip: server, psk, internet: $('internet').checked,
      port: Number($('port').value), dashboard_port: Number($('dport').value) });
    $('psk').value = '';      // the secret is never kept in the page after submission
    logSeq = 0;
    $('logs').replaceChildren();
  } catch (error) {
    setError($('form-error'), error.message);
  } finally {
    busy = false;
    await refresh();
  }
});

$('disconnect').addEventListener('click', async () => {
  setError($('form-error'), '');
  busy = true;
  renderForm(last);
  try { await api('/api/disconnect', {}); } catch (error) { setError($('form-error'), error.message); }
  busy = false;
  await refresh();
});

$('x-refresh').addEventListener('click', async () => {
  try { await api('/api/exit-ip', {}); } catch (error) { setError($('form-error'), error.message); }
  await refresh();
});

$('dl-mode').addEventListener('change', () => {
  const vpn = $('dl-mode').value === 'vpn';
  show($('dl-hash-wrap'), !vpn);
  $('dl-url').placeholder = vpn ? 'http://10.8.0.1:8000' : 'https://www.rfc-editor.org/rfc/rfc791.txt';
});

$('dl-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  setError($('dl-error'), '');
  try {
    await api('/api/download', { mode: $('dl-mode').value, url: $('dl-url').value, destination: $('dl-dest').value,
      sha256: $('dl-mode').value === 'vpn' ? '' : $('dl-hash').value });
  } catch (error) { setError($('dl-error'), error.message); }
  await refresh();
});

$('dl-cancel').addEventListener('click', async () => {
  try { await api('/api/download/cancel', {}); } catch (error) { setError($('dl-error'), error.message); }
  await refresh();
});

$('clear-logs').addEventListener('click', () => $('logs').replaceChildren());

refresh().then(schedule);
