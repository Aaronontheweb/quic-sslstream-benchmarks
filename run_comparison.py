#!/usr/bin/env python3
"""Sequential, balanced runtime/transport matrix over immutable comparison builds."""
import argparse
import json
import os
import subprocess
from pathlib import Path

import run_spike as runner
from build_comparison import VARIANTS

ROOT = runner.ROOT
ORDERS = [(0, 1, 2), (2, 1, 0), (1, 2, 0), (0, 2, 1), (2, 0, 1), (1, 0, 2)]


def specifications(mode, rounds):
    workloads = [('p348', 348, 65536, 1280, 1104), ('p4096', 4096, 65536, 111, 105)] if mode == 'primary' else [('serial-p348', 348, 0, 1, 0)] if mode == 'serial' else [('p348', 348, 65536, 1280, 1104)]
    result = []
    for workload, payload, batch, window, boundary in workloads:
        for repetition in range(rounds):
            for position, variant in enumerate(ORDERS[repetition % len(ORDERS)]):
                for transport in (('quic', 'tls') if repetition % 2 == 0 else ('tls', 'quic')):
                    result.append({'workload': workload, 'round': repetition, 'variant': VARIANTS[variant][0], 'variantPosition': position,
                                   'transport': transport, 'payload': payload, 'batch': batch, 'window': window, 'ackBoundary': boundary})
    return result


def configuration():
    variants = {}
    shared = None
    config = None
    for name, tfm, runtime, feature in VARIANTS:
        directory = ROOT / 'builds' / name
        record = json.loads((directory / 'build.json').read_text())
        expected_mode = 'runtime' if feature == 'on' else 'classic'
        if (record['sdk'], record['languageVersion'], record['targetFramework'], record['runtimeVersion'], record['applicationAsyncMode']) != ('11.0.100', '15.0', tfm, runtime, expected_mode):
            raise RuntimeError('Unexpected comparison build identity: ' + name)
        for file, digest in record['files'].items():
            if runner.digest(directory / file) != digest:
                raise RuntimeError('Frozen build changed: ' + name)
        for file in ('Program.cs', 'Protocol.cs', 'TransportSpike.csproj'):
            if runner.digest(ROOT / file) != record['source_sha256'][file]:
                raise RuntimeError('Compiled application source differs: ' + name)
        proof = record['loweringProof']
        if len(proof['methods']) != 8 or any(method['runtimeAsync'] != (feature == 'on') or method['compilerStateMachine'] != (feature == 'off') for method in proof['methods']):
            raise RuntimeError('Incomplete hot-method lowering proof: ' + name)
        options = json.loads((directory / 'TransportSpike.runtimeconfig.json').read_text())['runtimeOptions']
        if options['tfm'] != tfm or options['framework']['version'] != runtime or options['rollForward'] != 'Disable':
            raise RuntimeError('Runtime selection is not pinned: ' + name)
        properties = options['configProperties']
        if any(properties.get(key) is not True for key in ('System.GC.Server', 'System.Runtime.TieredCompilation', 'System.Runtime.TieredPGO')) or config is not None and properties != config:
            raise RuntimeError('Runtime configuration differs across variants')
        config = properties
        pins_file = ROOT / ('.local/native-pins-net10.json' if tfm == 'net10.0' else '.local/native-pins-net11.json')
        pins = json.loads(pins_file.read_text())
        transport_pins = {key: value for key, value in pins.items() if not key.startswith('libcoreclr')}
        if shared is not None and transport_pins != shared:
            raise RuntimeError('Transport-native libraries differ across variants')
        shared = transport_pins
        variants[name] = {'build': record, 'buildPath': str(directory / 'TransportSpike.dll'), 'buildDescriptorSha256': runner.digest(directory / 'build.json'),
                          'nativePinsPath': str(pins_file), 'nativePinsSha256': runner.digest(pins_file), 'nativePins': pins}
    return variants, shared


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('primary', 'diagnostic', 'serial', 'smoke'))
    parser.add_argument('output', type=Path)
    parser.add_argument('--rounds', type=int)
    parser.add_argument('--warmup', type=float, default=2)
    parser.add_argument('--seconds', type=float, default=6)
    args = parser.parse_args()
    rounds = args.rounds if args.rounds is not None else 6 if args.mode == 'primary' else 2
    if rounds <= 0:
        parser.error('rounds must be positive')
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT).strip():
        raise RuntimeError('Commit comparison source before execution')
    overrides = {key: value for key, value in os.environ.items() if key.startswith('COMPlus_') or key.startswith('DOTNET_') and any(word in key for word in ('Tiered', 'GC', 'ReadyToRun', 'RollForward'))}
    if overrides:
        raise RuntimeError('Unexpected runtime environment overrides: ' + ', '.join(overrides))
    variants, shared = configuration()
    args.output.mkdir(parents=True, exist_ok=False)
    files = subprocess.check_output(['git', 'ls-files'], cwd=ROOT, text=True).splitlines()
    source = {name: runner.digest(ROOT / name) for name in files}
    manifest = {'mode': args.mode, 'rounds': rounds, 'warmupSeconds': args.warmup, 'measurementSeconds': args.seconds,
                'revision': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(), 'source_sha256': source,
                'certificateSha256': runner.digest(runner.IDENTITY / 'loopback.pfx'), 'launcherSha256': runner.digest(runner.LAUNCHER),
                'variants': variants, 'sharedTransportNativeSha256': shared, 'runtimeEnvironmentOverrides': overrides,
                'dotnetInfo': subprocess.check_output([str(runner.LAUNCHER), '--info'], cwd=ROOT, text=True)}
    specs = specifications(args.mode, rounds)
    manifest['expectedAttempts'] = len(specs)
    (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    rows = []
    for index, spec in enumerate(specs):
        variant = variants[spec['variant']]
        runner.BINARY = Path(variant['buildPath'])
        runner.EXPECTED_RUNTIME = variant['build']['expectedRuntime']
        runner.NATIVE_PINS = Path(variant['nativePinsPath'])
        settings = ['--payload', str(spec['payload']), '--batch', str(spec['batch']), '--window', str(spec['window']),
                    '--ack-boundary', str(spec['ackBoundary']), '--warmup', str(args.warmup), '--seconds', str(args.seconds),
                    '--diagnostics', str(args.mode == 'diagnostic').lower(), '--cancellation', 'operation']
        row = runner.cell(args.output / f"{index:03d}-{spec['variant']}-{spec['transport']}", spec['transport'], settings)
        row.update(index=index, workload=spec['workload'], round=spec['round'], variant=spec['variant'], variantPosition=spec['variantPosition'])
        rows.append(row)
        with (args.output / 'runs.jsonl').open('a') as output:
            output.write(json.dumps(row) + '\n')
        print(json.dumps({key: row.get(key) for key in ('index', 'workload', 'round', 'variant', 'transport', 'status', 'error')}), flush=True)
        if row['status'] != 'valid':
            raise RuntimeError('Invalid matrix attempt: ' + str(row.get('error')))
    if runner.digest(runner.IDENTITY / 'loopback.pfx') != manifest['certificateSha256'] or runner.digest(runner.LAUNCHER) != manifest['launcherSha256']:
        raise RuntimeError('Identity or launcher changed during matrix')
    for variant in variants.values():
        directory = Path(variant['buildPath']).parent
        if runner.digest(directory / 'build.json') != variant['buildDescriptorSha256'] or runner.digest(Path(variant['nativePinsPath'])) != variant['nativePinsSha256']:
            raise RuntimeError('Build descriptor or native pins changed')
        for name, digest in variant['build']['files'].items():
            if runner.digest(directory / name) != digest:
                raise RuntimeError('Frozen build changed during matrix')
    for row in rows:
        for name, digest in row['native_sha256'].items():
            if runner.digest(Path(name)) != digest:
                raise RuntimeError('Native library changed during matrix')
    if any(runner.digest(ROOT / name) != digest for name, digest in source.items()):
        raise RuntimeError('Source changed during matrix')
    (args.output / 'complete.json').write_text(json.dumps({'state': 'complete', 'attempts': len(rows)}) + '\n')


if __name__ == '__main__':
    main()
