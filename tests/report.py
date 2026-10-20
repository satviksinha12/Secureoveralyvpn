#!/usr/bin/env python3
import json
from pathlib import Path

lines = ['| Path | TCP receive throughput (Mbit/s) |', '| --- | ---: |']
for path in ('direct', 'tunnel'):
    data = json.loads(Path(f'results/{path}.json').read_text())
    rate = data['end']['sum_received']['bits_per_second'] / 1e6
    lines.append(f'| {path} | {rate:.2f} |')
Path('results/benchmark.md').write_text('\n'.join(lines) + '\n')
