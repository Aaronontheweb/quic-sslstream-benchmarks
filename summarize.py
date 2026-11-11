#!/usr/bin/env python3
"""Audit terminal paired blocks before aggregating; never infer success from partial rows."""
import hashlib
import json
import math
import statistics
import subprocess
import sys
from pathlib import Path
from run_spike import validate_progress

ROOT = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def log_records(path, kind):
    return [json.loads(line[len(kind) + 1:]) for line in path.read_text().splitlines() if line.startswith(kind + ' ')]


def audit(path):
    manifest = json.loads((path / 'manifest.json').read_text())
    complete = json.loads((path / 'complete.json').read_text())
    rows = [json.loads(line) for line in (path / 'runs.jsonl').read_text().splitlines()]
    args = manifest['arguments']
    expected = 2 * args['rounds']
    if manifest['mode'] != 'run' or complete != {'state': 'complete', 'attempts': expected} or len(rows) != expected:
        raise ValueError('Incomplete or unexpected attempt coverage: ' + str(path))
    for name, digest in manifest['source_sha256'].items():
        source = subprocess.check_output(['git', 'show', manifest['revision'] + ':' + name], cwd=ROOT)
        if hashlib.sha256(source).hexdigest() != digest:
            raise ValueError('Uncommitted or mismatched controller source: ' + name)
    build = Path(args['build'])
    if not build.is_absolute():
        build = ROOT / build
    if sha(build) != manifest['binary_sha256']:
        raise ValueError('Changed application binary')
    for row, index in zip(rows, range(expected)):
        order = ('quic', 'tls') if index // 2 % 2 == 0 else ('tls', 'quic')
        if (row['index'], row['transport'], row['status'], row['client_exit'], row['server_exit']) != (index, order[index % 2], 'valid', 0, 0):
            raise ValueError('Invalid attempt or ordering')
        for name, digest in row['artifact_sha256'].items():
            if sha(path / f"{index:02d}-{row['transport']}" / name) != digest:
                raise ValueError('Changed process log')
        for native, digest in row['native_sha256'].items():
            if sha(Path(native)) != digest:
                raise ValueError('Changed native library')
        for side in ('client', 'server'):
            if len(row['phases'][side]) != 2 or [r['phase'] for r in row['phases'][side]] != [0, 1]:
                raise ValueError('Missing phase witness')
            log = path / f"{index:02d}-{row['transport']}" / (side + '.log')
            derived = {'deliveredFramesPerSecond', 'deliveredPayloadBytesPerSecond', 'combinedCpuNanosecondsPerFrame', 'combinedManagedBytesPerFrame'} if side == 'client' else set()
            exported = [{key: value for key, value in phase.items() if key not in derived} for phase in row['phases'][side]]
            if exported != log_records(log, 'PHASE') or row['security'][side] != log_records(log, 'SECURITY'):
                raise ValueError('Exported witnesses differ from raw process log')
        for client, server in zip(row['phases']['client'], row['phases']['server']):
            for endpoint in (client,server):
                validate_progress(endpoint,args.get('progress_diagnostics',False),args.get('progress_sample_every',64),endpoint is client,
                                  'ProgressCounters.cs' in manifest.get('frozen_build',{}).get('source_sha256',{}))
            if not client['complete'] or not server['complete'] or client['frames'] <= 0 or client['frames'] != server['frames'] or client['dataBytes'] != server['dataBytes']:
                raise ValueError('Incomplete peer consumption')
            rate = client['frames'] / client['elapsedSeconds']
            computed = {
                'deliveredFramesPerSecond': rate,
                'deliveredPayloadBytesPerSecond': rate * client['payloadBytes'],
                'combinedCpuNanosecondsPerFrame': (client['cpuMilliseconds'] + server['cpuMilliseconds']) * 1e6 / client['frames'],
                'combinedManagedBytesPerFrame': None if client['allocatedBytes'] is None else (client['allocatedBytes'] + server['allocatedBytes']) / client['frames']
            }
            for key, value in computed.items():
                if value is None:
                    if client[key] is not None or server['allocatedBytes'] is not None:
                        raise ValueError('Unexpected allocation measurement')
                elif not math.isfinite(value) or value < 0 or not math.isclose(value, client[key], rel_tol=1e-12):
                    raise ValueError('Invalid metric calculation: ' + key)
    result = {'cell': path.name, 'attempts': expected, 'manifestSha256': sha(path / 'manifest.json'), 'runsSha256': sha(path / 'runs.jsonl'), 'settings': args, 'transports': {}, 'pairs': []}
    for transport in ('quic', 'tls'):
        selected = [r for r in rows if r['transport'] == transport]
        clients = [r['phases']['client'][1] for r in selected]
        metrics = {}
        for key in ('deliveredFramesPerSecond', 'deliveredPayloadBytesPerSecond', 'combinedCpuNanosecondsPerFrame', 'combinedManagedBytesPerFrame', 'p50Us', 'p95Us', 'p99Us'):
            values = [c[key] for c in clients]
            if all(value is None for value in values):
                metrics[key] = None
            elif any(value is None or not math.isfinite(value) or value < 0 for value in values):
                raise ValueError('Invalid measured value: ' + key)
            else:
                metrics[key] = {'median': statistics.median(values), 'minimum': min(values), 'maximum': max(values), 'values': values}
        metrics['ackRecordsPerFrame'] = [c['ackReads'] / c['frames'] for c in clients]
        metrics['dataReadBytesPerCall'] = [r['phases']['server'][1]['dataBytes'] / r['phases']['server'][1]['dataReads'] for r in selected]
        result['transports'][transport] = metrics
    for index in range(0, expected, 2):
        pair = {r['transport']: r['phases']['client'][1] for r in rows[index:index + 2]}
        result['pairs'].append({'quicThroughputPercentVsTls': 100 * (pair['quic']['deliveredFramesPerSecond'] / pair['tls']['deliveredFramesPerSecond'] - 1), 'quicCpuPercentVsTls': 100 * (pair['quic']['combinedCpuNanosecondsPerFrame'] / pair['tls']['combinedCpuNanosecondsPerFrame'] - 1)})
    return result


if __name__ == '__main__':
    if len(sys.argv) < 2:
        raise SystemExit('Specify one or more completed run directories')
    print(json.dumps([audit(Path(path)) for path in sys.argv[1:]], indent=2))
