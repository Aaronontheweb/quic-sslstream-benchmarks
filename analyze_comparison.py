#!/usr/bin/env python3
"""Audit local matrix witnesses or recompute a sanitized publication; diagnostics stay separate."""
import argparse
import hashlib
import json
import math
import statistics
import subprocess
from pathlib import Path

from run_comparison import ROOT, specifications
from run_spike import digest, records, validate_native


def validate(manifest, rows, complete):
    specs = specifications(manifest['mode'], manifest['rounds'])
    if complete != {'state': 'complete', 'attempts': len(specs)} or len(rows) != len(specs) or manifest['expectedAttempts'] != len(specs):
        raise ValueError('Incomplete matrix coverage')
    for name, variant in manifest['variants'].items():
        build = variant['build']
        runtime = '10.0.14' if name == 'net10-classic' else '11.0.0'
        asynchronous = name == 'net11-runtime-async'
        if (build['sdk'], build['languageVersion'], build['runtimeVersion'], build['applicationAsyncMode']) != ('11.0.100', '15.0', runtime, 'runtime' if asynchronous else 'classic'):
            raise ValueError('Unexpected compiler/runtime identity')
        proof = build['loweringProof']
        keys = [m['name'] if not m['name'].startswith('<RunAsync>g__Guard') else 'Guard' for m in proof['methods']]
        required = {'RunAsync', 'SendData', 'ReadAcks', 'ReadData', 'WriteAcks', 'WriteNumber', 'ExpectNumber', 'Guard'}
        if len(keys) != 8 or set(keys) != required or any(m['runtimeAsync'] != asynchronous or m['compilerStateMachine'] == asynchronous for m in proof['methods']):
            raise ValueError('Missing or invalid method lowering proof')
        pins = {k: v for k, v in variant['nativePins'].items() if not k.startswith('libcoreclr')}
        if pins != manifest['sharedTransportNativeSha256']:
            raise ValueError('Transport native pins differ')
    for index, (row, spec) in enumerate(zip(rows, specs)):
        if row['index'] != index or row['status'] != 'valid' or row['client_exit'] != 0 or row['server_exit'] != 0:
            raise ValueError('Invalid attempt')
        if any(row[key] != spec[key] for key in ('workload', 'round', 'variant', 'variantPosition', 'transport')):
            raise ValueError('Matrix ordering differs')
        options = dict(zip(row['settings'][::2], row['settings'][1::2]))
        expected_options = {'--payload': str(spec['payload']), '--batch': str(spec['batch']), '--window': str(spec['window']), '--ack-boundary': str(spec['ackBoundary']),
                            '--warmup': str(manifest['warmupSeconds']), '--seconds': str(manifest['measurementSeconds']), '--diagnostics': str(manifest['mode'] == 'diagnostic').lower(), '--cancellation': 'operation'}
        if options != expected_options:
            raise ValueError('Requested matrix workload differs')
        variant = manifest['variants'][row['variant']]
        for side in ('client', 'server'):
            if len(row['security'][side]) != 1 or [p['phase'] for p in row['phases'][side]] != [0, 1]:
                raise ValueError('Missing phase/security witnesses')
            security = row['security'][side][0]
            if (security['runtime'], security['tls'], security['cipher'], security['alpn'], security['mutual'], security['serverGc']) != (variant['build']['expectedRuntime'], 'Tls13', 'TLS_AES_128_GCM_SHA256', 'transport-spike-v1', True, True):
                raise ValueError('Runtime or security differs')
            validate_native(row['endpoint_native_sha256'][side], row['transport'], variant['nativePins'])
        for client, server in zip(row['phases']['client'], row['phases']['server']):
            frame = spec['payload'] + 8
            batch = min(spec['window'], 1 if spec['batch'] == 0 else spec['batch'] // frame)
            for endpoint in (client, server):
                if not endpoint['complete'] or (endpoint['payloadBytes'], endpoint['frameBytes'], endpoint['batchFrames'], endpoint['windowFrames'], endpoint['creditBytes'], endpoint['ackBoundaryFrames'], endpoint['diagnostics'], endpoint['cancellation']) != (spec['payload'], frame, batch, spec['window'], spec['window'] * frame, spec['ackBoundary'] or batch, manifest['mode'] == 'diagnostic', 'operation'):
                    raise ValueError('Actual matrix workload differs')
            if client['frames'] <= 0 or client['frames'] != server['frames'] or client['dataBytes'] != server['dataBytes'] or client['dataBytes'] != client['frames'] * frame or client['ackReads'] != server['ackWrites']:
                raise ValueError('Incomplete peer consumption')
            if client['frames'] % batch or client['dataWrites'] != client['frames'] // batch or not 0 < client['maximumInFlight'] <= spec['window']:
                raise ValueError('Batch write count or credit differs')
            quantiles = [client[k] for k in ('p50Us', 'p95Us', 'p99Us')]
            if client['omittedLatencySamples'] or spec['window'] == 1 and (client['latencySamples'] != (client['frames'] + 63) // 64 or any(v is None or not math.isfinite(v) or v <= 0 for v in quantiles) or quantiles != sorted(quantiles)):
                raise ValueError('Invalid serial latency evidence')
            if spec['window'] > 1 and (client['latencySamples'] or any(v is not None for v in quantiles)):
                raise ValueError('Unexpected parallel RTT evidence')
            seconds = client['elapsedSeconds']
            computed = {'deliveredFramesPerSecond': client['frames'] / seconds,
                        'deliveredPayloadBytesPerSecond': client['frames'] * spec['payload'] / seconds,
                        'combinedCpuNanosecondsPerFrame': (client['cpuMilliseconds'] + server['cpuMilliseconds']) * 1e6 / client['frames'],
                        'combinedManagedBytesPerFrame': None if client['allocatedBytes'] is None else (client['allocatedBytes'] + server['allocatedBytes']) / client['frames']}
            for key, value in computed.items():
                if value is None:
                    if client[key] is not None or server['allocatedBytes'] is not None:
                        raise ValueError('Unexpected diagnostic allocation')
                elif not math.isfinite(value) or value < 0 or not math.isclose(value, client[key], rel_tol=1e-12):
                    raise ValueError('Invalid metric calculation: ' + key)
        if row['phases']['client'][1]['elapsedSeconds'] < manifest['measurementSeconds']:
            raise ValueError('Measured phase too short')


def summarize(manifest, rows):
    cells = []
    changes = []
    metrics = ('deliveredFramesPerSecond', 'deliveredPayloadBytesPerSecond', 'combinedCpuNanosecondsPerFrame', 'combinedManagedBytesPerFrame', 'p50Us', 'p95Us', 'p99Us')
    workloads = list(dict.fromkeys(row['workload'] for row in rows))
    for workload in workloads:
        for name in manifest['variants']:
            for transport in ('quic', 'tls'):
                phases = [r['phases']['client'][1] for r in rows if (r['workload'], r['variant'], r['transport']) == (workload, name, transport)]
                cell = {'workload': workload, 'variant': name, 'transport': transport, 'attempts': len(phases)}
                for key in metrics:
                    values = [p[key] for p in phases]
                    cell[key] = None if all(v is None for v in values) else {'median': statistics.median(values), 'values': values}
                cells.append(cell)
        for transport in ('quic', 'tls'):
            for old, new in [('net10-classic', 'net11-classic'), ('net11-classic', 'net11-runtime-async')]:
                ratios = []
                for repetition in range(manifest['rounds']):
                    pair = {r['variant']: r['phases']['client'][1] for r in rows if r['workload'] == workload and r['transport'] == transport and r['round'] == repetition}
                    ratios.append(100 * (pair[new]['deliveredFramesPerSecond'] / pair[old]['deliveredFramesPerSecond'] - 1))
                changes.append({'workload': workload, 'transport': transport, 'baseline': old, 'candidate': new, 'throughputPercentChanges': ratios, 'medianPairedPercentChange': statistics.median(ratios)})
    return {'mode': manifest['mode'], 'attempts': len(rows), 'cells': cells, 'pairedRuntimeChanges': changes}


def audit(directory):
    manifest = json.loads((directory / 'manifest.json').read_text())
    rows = [json.loads(line) for line in (directory / 'runs.jsonl').read_text().splitlines()]
    complete = json.loads((directory / 'complete.json').read_text())
    validate(manifest, rows, complete)
    for name, sha in manifest['source_sha256'].items():
        data = subprocess.check_output(['git', 'show', manifest['revision'] + ':' + name], cwd=ROOT)
        if hashlib.sha256(data).hexdigest() != sha:
            raise ValueError('Source differs from committed comparison revision')
    for row in rows:
        folder = directory / f"{row['index']:03d}-{row['variant']}-{row['transport']}"
        for name, sha in row['artifact_sha256'].items():
            if digest(folder / name) != sha:
                raise ValueError('Changed process log')
        for side in ('client', 'server'):
            derived = set(('deliveredFramesPerSecond', 'deliveredPayloadBytesPerSecond', 'combinedCpuNanosecondsPerFrame', 'combinedManagedBytesPerFrame')) if side == 'client' else set()
            phases = [{k: v for k, v in p.items() if k not in derived} for p in row['phases'][side]]
            if phases != records(folder / (side + '.log'), 'PHASE') or row['security'][side] != records(folder / (side + '.log'), 'SECURITY'):
                raise ValueError('Raw witnesses differ')
        for native, sha in row['native_sha256'].items():
            if digest(Path(native)) != sha:
                raise ValueError('Native library changed')
    for variant in manifest['variants'].values():
        directory = Path(variant['buildPath']).parent
        if digest(directory / 'build.json') != variant['buildDescriptorSha256'] or digest(Path(variant['nativePinsPath'])) != variant['nativePinsSha256']:
            raise ValueError('Build descriptor or pins changed')
        for name, sha in variant['build']['files'].items():
            if digest(directory / name) != sha:
                raise ValueError('Frozen build changed')
    return summarize(manifest, rows)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directories', type=Path, nargs='+')
    parser.add_argument('--published', action='store_true', help='Recompute sanitized exports without private artifacts')
    args = parser.parse_args()
    if args.published:
        result = []
        for path in args.directories:
            data = json.loads(path.read_text())
            if data['schemaVersion'] != 1 or sorted(g['manifest']['mode'] for g in data['groups']) != ['diagnostic', 'primary', 'serial']:
                raise ValueError('Incomplete published experiment groups')
            for group in data['groups']:
                validate(group['manifest'], group['runs'], group['complete'])
                for name, sha in group['manifest']['source_sha256'].items():
                    content = subprocess.check_output(['git', 'show', group['manifest']['revision'] + ':' + name], cwd=ROOT)
                    if hashlib.sha256(content).hexdigest() != sha:
                        raise ValueError('Published source identity differs')
                result.append(summarize(group['manifest'], group['runs']))
    else:
        result = [audit(path) for path in args.directories]
    print(json.dumps(result, indent=2))
