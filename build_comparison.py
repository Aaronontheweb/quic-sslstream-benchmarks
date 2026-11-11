#!/usr/bin/env python3
"""Freeze identical source under one SDK with explicit target framework and app async mode."""
import argparse
import json
import shutil
import subprocess
from pathlib import Path

from run_spike import ROOT, LAUNCHER, digest

VARIANTS = [('net10-classic', 'net10.0', '10.0.14', 'off'),
            ('net11-classic', 'net11.0', '11.0.0', 'off'),
            ('net11-runtime-async', 'net11.0', '11.0.0', 'on')]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--sdk', default='11.0.100')
    args = parser.parse_args()
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT).strip():
        raise SystemExit('Commit source before building the comparison')
    selector = ROOT / '.local/comparison-sdk'
    selector.mkdir(parents=True, exist_ok=True)
    (selector / 'global.json').write_text(json.dumps({'sdk': {'version': args.sdk, 'rollForward': 'disable', 'allowPrerelease': False}}, indent=2) + '\n')
    actual = subprocess.check_output([str(LAUNCHER), '--version'], cwd=selector, text=True).strip()
    if actual != args.sdk:
        raise RuntimeError('Selected SDK differs from the requested SDK')
    inspector = ROOT / '.local/comparison-inspector'
    subprocess.run([str(LAUNCHER), 'build', str(ROOT / 'tools/InspectBuild/InspectBuild.csproj'), '-c', 'Release', '-o', str(inspector),
                    '-p:RuntimeFrameworkVersion=10.0.14', '-p:RollForward=Disable'], cwd=selector, check=True)
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    source = {str(p.relative_to(ROOT)): digest(p) for p in ROOT.iterdir() if p.suffix in ('.cs', '.csproj', '.py', '.md', '.json')}
    for name, tfm, runtime, mode in VARIANTS:
        target = ROOT / 'builds' / name
        if target.exists():
            raise RuntimeError('Build is already frozen: ' + name)
        intermediate = ROOT / '.local/comparison-obj' / name
        command = [str(LAUNCHER), 'build', str(ROOT / 'TransportSpike.csproj'), '-c', 'Release', '-o', str(target),
                   '-p:ComparisonBuild=true', '-p:ComparisonTargetFramework=' + tfm, '-p:ComparisonRuntimeAsync=' + mode,
                   '-p:RuntimeFrameworkVersion=' + runtime, '-p:BaseIntermediateOutputPath=' + str(intermediate) + '/', '-p:UseAppHost=false']
        subprocess.run(command, cwd=selector, check=True)
        expected = 'runtime' if mode == 'on' else 'classic'
        proof = json.loads(subprocess.check_output([str(LAUNCHER), str(inspector / 'InspectBuild.dll'), str(target / 'TransportSpike.dll'), expected], cwd=selector, text=True))
        record = {'name': name, 'revision': revision, 'source_sha256': source, 'sdk': actual, 'targetFramework': tfm,
                  'runtimeVersion': runtime, 'expectedRuntime': '.NET ' + runtime, 'applicationAsyncMode': expected,
                  'languageVersion': '15.0', 'runtimeAsyncFeature': mode, 'loweringProof': proof,
                  'files': {p.name: digest(p) for p in target.iterdir() if p.is_file()}}
        (target / 'build.json').write_text(json.dumps(record, indent=2) + '\n')
        print('Frozen', name, 'SDK', actual, 'mode', proof['applicationAsyncMode'], 'runtime async methods', proof['runtimeAsyncMethodCount'], flush=True)
    if any(digest(ROOT / p) != sha for p, sha in source.items()):
        raise RuntimeError('Source changed during comparison builds')


if __name__ == '__main__':
    main()
