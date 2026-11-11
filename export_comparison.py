#!/usr/bin/env python3
"""Publish an allowlisted matrix after auditing the complete local evidence."""
import argparse
import hashlib
import json
from pathlib import Path

from analyze_comparison import audit, validate, summarize
from run_comparison import ROOT

PHASE_FIELDS = set('role transport phase frames payloadBytes frameBytes dataBytes batchFrames batchBytes windowFrames creditBytes requestedAckEvery effectiveAckEvery ackAtBatchBoundary ackBoundaryFrames elapsedSeconds cpuMilliseconds allocatedBytes dataWrites dataReads ackWrites ackReads maximumInFlight cancellation diagnostics latencySamples omittedLatencySamples p50Us p95Us p99Us protocol complete deliveredFramesPerSecond deliveredPayloadBytesPerSecond combinedCpuNanosecondsPerFrame combinedManagedBytesPerFrame'.split())
SECURITY_FIELDS = set('role transport tls cipher alpn mutual tcpSendBuffer tcpReceiveBuffer runtime architecture serverGc'.split())
BUILD_FIELDS = set('name revision sdk targetFramework runtimeVersion expectedRuntime applicationAsyncMode languageVersion runtimeAsyncFeature loweringProof files source_sha256'.split())
MANIFEST_FIELDS = set('mode rounds warmupSeconds measurementSeconds revision expectedAttempts source_sha256 sharedTransportNativeSha256'.split())
ROW_FIELDS = set('index workload round variant variantPosition transport status client_exit server_exit settings endpoint_native_sha256 artifact_sha256'.split())


def export(directory):
    summary = audit(directory)
    raw_manifest = json.loads((directory / 'manifest.json').read_text())
    raw_rows = [json.loads(line) for line in (directory / 'runs.jsonl').read_text().splitlines()]
    manifest = {key: value for key, value in raw_manifest.items() if key in MANIFEST_FIELDS}
    manifest['variants'] = {name: {'build': {key: value for key, value in variant['build'].items() if key in BUILD_FIELDS}, 'nativePins': variant['nativePins']}
                            for name, variant in raw_manifest['variants'].items()}
    rows = []
    for raw in raw_rows:
        row = {key: value for key, value in raw.items() if key in ROW_FIELDS}
        row['phases'] = {side: [{key: value for key, value in phase.items() if key in PHASE_FIELDS} for phase in phases] for side, phases in raw['phases'].items()}
        row['security'] = {side: [{key: value for key, value in security.items() if key in SECURITY_FIELDS} for security in witnesses] for side, witnesses in raw['security'].items()}
        rows.append(row)
    complete = json.loads((directory / 'complete.json').read_text())
    validate(manifest, rows, complete)
    if summarize(manifest, rows) != summary:
        raise ValueError('Sanitized results differ from the raw audit')
    return {'manifest': manifest, 'runs': rows, 'complete': complete,
            'originalManifestSha256': hashlib.sha256((directory / 'manifest.json').read_bytes()).hexdigest(),
            'originalRunsSha256': hashlib.sha256((directory / 'runs.jsonl').read_bytes()).hexdigest()}, summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('directories', type=Path, nargs='+')
    parser.add_argument('--output', type=Path, default=ROOT / 'results/runtime-comparison')
    args = parser.parse_args()
    groups = []
    summaries = []
    for directory in args.directories:
        group, summary = export(directory)
        groups.append(group)
        summaries.append(summary)
    modes = [g['manifest']['mode'] for g in groups]
    if sorted(modes) != ['diagnostic', 'primary', 'serial']:
        raise ValueError('Publish exactly one complete primary, diagnostic and serial matrix')
    args.output.mkdir(parents=True, exist_ok=False)
    data = {'schemaVersion': 1, 'scope': 'SDK11-built runtime comparison, separate from the original88 SDK10 measurements', 'groups': groups}
    (args.output / 'measurements.json').write_text(json.dumps(data, indent=2) + '\n')
    (args.output / 'summary.json').write_text(json.dumps(summaries, indent=2) + '\n')
    print('Exported', sum(len(g['runs']) for g in groups), 'attempts with exact raw/sanitized summary agreement')


if __name__ == '__main__':
    main()
