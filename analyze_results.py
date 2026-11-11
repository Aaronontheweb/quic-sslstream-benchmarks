#!/usr/bin/env python3
"""Validate the sanitized publication and recompute medians without private artifacts."""
import hashlib
import json
import math
import statistics
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def analyze():
    data = json.loads((ROOT / 'results/measurements.json').read_text())
    environment = json.loads((ROOT / 'results/environment.json').read_text())
    workloads = []
    for tag in ('baseline-workload-v1', 'credit-ack-workload-v1'):
        workloads.append({name: hashlib.sha256(subprocess.check_output(['git', 'show', tag + ':' + name], cwd=ROOT)).hexdigest()
                          for name in ('Program.cs', 'Protocol.cs')})
    summaries = []
    attempts = diagnostic = 0
    ids = set()
    for block in data['blocks']:
        if block['id'] in ids or block['workloadSha256'] not in workloads:
            raise ValueError('Duplicate block or unknown workload source')
        ids.add(block['id'])
        count = 2 * block['settings']['rounds']
        if len(block['runs']) != count or block['completion'] != {'state': 'complete', 'attempts': count}:
            raise ValueError('Incomplete coverage')
        attempts += count
        diagnostic += count if block['settings']['diagnostics'] else 0
        for index, row in enumerate(block['runs']):
            order = ('quic', 'tls') if index // 2 % 2 == 0 else ('tls', 'quic')
            if (row['index'], row['transport'], row['status'], row['clientExit'], row['serverExit']) != (index, order[index % 2], 'valid', 0, 0):
                raise ValueError('Invalid attempt or order')
            for side in ('client', 'server'):
                if [p['phase'] for p in row['phases'][side]] != [0, 1] or len(row['security'][side]) != 1:
                    raise ValueError('Missing phase or security witness')
                security = row['security'][side][0]
                if (security['tls'], security['cipher'], security['alpn'], security['mutual'], security['runtime'], security['serverGc']) != ('Tls13', 'TLS_AES_128_GCM_SHA256', 'transport-spike-v1', True, environment['applicationRuntime'], True):
                    raise ValueError('Security/runtime mismatch')
            for client, server in zip(row['phases']['client'], row['phases']['server']):
                if not client['complete'] or not server['complete'] or client['frames'] <= 0 or client['frames'] != server['frames'] or client['dataBytes'] != server['dataBytes'] or client['dataBytes'] != client['frames'] * client['frameBytes'] or client['ackReads'] != server['ackWrites']:
                    raise ValueError('Invalid delivery counts')
                seconds = client['elapsedSeconds']
                computed = {'deliveredFramesPerSecond': client['frames'] / seconds,
                            'deliveredPayloadBytesPerSecond': client['frames'] * client['payloadBytes'] / seconds,
                            'combinedCpuNanosecondsPerFrame': (client['cpuMilliseconds'] + server['cpuMilliseconds']) * 1e6 / client['frames'],
                            'combinedManagedBytesPerFrame': None if client['allocatedBytes'] is None else (client['allocatedBytes'] + server['allocatedBytes']) / client['frames']}
                for key, value in computed.items():
                    if value is None:
                        if client[key] is not None or server['allocatedBytes'] is not None:
                            raise ValueError('Unexpected allocation evidence')
                    elif not math.isfinite(value) or value < 0 or not math.isclose(value, client[key], rel_tol=1e-12):
                        raise ValueError('Invalid arithmetic: ' + key)
        result = {'id': block['id'], 'settings': block['settings'], 'attempts': count, 'transports': {}, 'pairedQuicThroughputPercentVsTls': []}
        for transport in ('quic', 'tls'):
            phases = [r['phases']['client'][1] for r in block['runs'] if r['transport'] == transport]
            result['transports'][transport] = {}
            for key in ('deliveredFramesPerSecond', 'deliveredPayloadBytesPerSecond', 'combinedCpuNanosecondsPerFrame', 'combinedManagedBytesPerFrame', 'p50Us', 'p95Us', 'p99Us'):
                values = [p[key] for p in phases]
                result['transports'][transport][key] = None if all(v is None for v in values) else {'median': statistics.median(values), 'values': values}
        for index in range(0, count, 2):
            pair = {r['transport']: r['phases']['client'][1] for r in block['runs'][index:index + 2]}
            result['pairedQuicThroughputPercentVsTls'].append(100 * (pair['quic']['deliveredFramesPerSecond'] / pair['tls']['deliveredFramesPerSecond'] - 1))
        summaries.append(result)
    if attempts != environment['performanceAttempts'] or diagnostic != environment['diagnosticAttempts'] or attempts - diagnostic != environment['uninstrumentedAttempts']:
        raise ValueError('Unexpected ledger totals')
    return summaries


if __name__ == '__main__':
    print(json.dumps(analyze(), indent=2))
