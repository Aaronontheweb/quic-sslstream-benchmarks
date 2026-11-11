#!/usr/bin/env python3
"""Audit private local captures, then export an explicit publication allowlist."""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path

from analyze_causal import BLOCKS, classify_functions, metrics, summary, validate
from summarize import audit

ROOT=Path(__file__).resolve().parent
JOURNAL=ROOT/'.local/causal-journal'
SECURITY='role transport tls cipher alpn mutual tcpSendBuffer tcpReceiveBuffer runtime architecture serverGc processorAffinity processorCount gcLatencyMode'.split()
PHASE='role transport phase frames payloadBytes frameBytes dataBytes batchFrames batchBytes windowFrames creditBytes requestedAckEvery effectiveAckEvery ackAtBatchBoundary ackBoundaryFrames elapsedSeconds cpuMilliseconds allocatedBytes dataWrites dataReads ackWrites ackReads maximumInFlight cancellation diagnostics progressDiagnostics progressSampleEvery progress latencySamples omittedLatencySamples p50Us p95Us p99Us protocol complete'.split()
WORKER='wallSeconds userSeconds systemSeconds percentOfOneCore schedstatRunningSeconds runnableWaitSeconds affinity snapshotMaxSeconds'.split()


def load(path):return json.loads(Path(path).read_text())
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def keep(row,keys):return {k:row[k] for k in keys if k in row}
def save(path,data):path.write_text(json.dumps(data,indent=2)+'\n')


def export_block(experiment,cell):
    name='causal-'+experiment.lower()+'-'+cell
    path=ROOT/'evidence'/name
    if experiment in ['E06','E07','E08']:path=path/'run'
    audit(path)  # Source, native, binary, raw log equality, and arithmetic gates.
    manifest=load(path/'manifest.json');args=manifest['arguments'];build=manifest['frozen_build']
    options=dict(payload=args['payload'],batch=args['batch'],window=args['window'],ackBoundary=args['ack_boundary'],warmup=args['warmup'],seconds=args['seconds'],cancellation=args['cancellation'],diagnostics=args['diagnostics'],progress=args.get('progress_diagnostics',False),sampleEvery=args.get('progress_sample_every',64))
    rows=[json.loads(line) for line in (path/'runs.jsonl').read_text().splitlines()]
    block=dict(experiment=experiment,cell=cell,rounds=args['rounds'],options=options,completion=load(path/'complete.json'),
               rawEvidence=dict(availability='private local-only; hashes do not make artifacts publicly available',manifestSha256=sha(path/'manifest.json'),runsSha256=sha(path/'runs.jsonl')),
               build=dict(codeRef='cbceae8f322ab4da603f7bff6e4419fd78667325' if 'ProgressCounters.cs' in build['source_sha256'] else 'credit-ack-workload-v1',descriptorRevision=build['revision'],workloadSha256={k:v for k,v in build['source_sha256'].items() if k.endswith('.cs')},files=build['files'],binarySha256=manifest['binary_sha256'],progressSchema='ProgressCounters.cs' in build['source_sha256']),
               controllerRevision=manifest['revision'],controllerSourceSha256=manifest['source_sha256'],runtimeconfig=manifest['runtimeconfig'],nativePins=load(Path(args['native_pins'])),runs=[])
    sidecar=JOURNAL/(name+'.json')
    if sidecar.exists():block.update(keep(load(sidecar),['startedUtc','completedUtc','loadBefore','loadAfter']))
    # Commands are reconstructed with public relative paths; private launcher/identity paths are omitted.
    block['reproductionCommand']='python3 run_spike.py run evidence/reproduce-'+name+' --build builds/'+('causal-progress-v1' if block['build']['progressSchema'] else 'original-control')+'/TransportSpike.dll --rounds '+str(args['rounds'])+' --payload 348 --batch '+str(args['batch'])+' --window '+str(args['window'])+' --ack-boundary 1104'+(' --progress-diagnostics' if options['progress'] else '')
    block['measurementClass']='native-diagnostic-and-context' if experiment in ['E06','E07','E08'] else 'progress-diagnostic' if options['progress'] else 'uninstrumented'
    for row in rows:
        r=dict(id=name+'/'+str(row['index']).zfill(2)+'-'+row['transport'],index=row['index'],transport=row['transport'],status=row['status'],clientExit=row['client_exit'],serverExit=row['server_exit'],
               security={side:[keep(w,SECURITY) for w in row['security'][side]] for side in ['client','server']},endpointNativeSha256=row['endpoint_native_sha256'],
               phases={side:[keep(p,PHASE) for p in row['phases'][side]] for side in ['client','server']},rawLogSha256=row['artifact_sha256'])
        r['metrics']=metrics(r);block['runs'].append(r)
    return block,manifest['certificate_sha256']


def export_profile(experiment,transport,side):
    worker=experiment=='E08'
    path=JOURNAL/(f'e08-worker-{side}-symbols.json' if worker else f'e06-{transport}-{side}-symbols-final.json')
    original=load(path);modules=Counter()
    for k,v in original['modules'].items():modules[Path(k).name]+=v
    functions=[dict(module=Path(f['module']).name,**keep(f,['function','resolution','samples','percentage'])) for f in original['functions']]
    p=dict(experiment=experiment,transport=transport,endpoint=side,scope='identified-worker' if worker else 'endpoint',samples=original['total_samples'],modules=dict(modules),functions=functions,
           periodMicroseconds=original['sampling_period_microseconds'],sampledCpuSeconds=original['sampled_cpu_seconds'],unambiguousNamedSamples=original['unambiguous_named_leaf_samples'],
           rawProfileSha256=original['profile_sha256'],symbolFiles={Path(k).name:v for k,v in original['symbol_files'].items()},caveats=original['caveats'],leafNameCategories=classify_functions(functions))
    if worker:
        identity=load(JOURNAL/'e08-worker-identity.json');w=identity['workers'][side]
        p.update(accountedCpuSeconds=w['userSeconds']+w['systemSeconds'],identityVerified=identity['identityProvenSameProcess'],worker=keep(w,WORKER))
    else:
        endpoint=load(ROOT/f'evidence/causal-e06-{transport}/profile-manifest.json')['endpoints'][side]
        start,stop=endpoint['started'],endpoint['stopped']
        p.update(accountedCpuSeconds=sum(stop[k]-start[k] for k in ['userSeconds','systemSeconds']),wallSeconds=stop['monotonicSeconds']-start['monotonicSeconds'])
    return p


def export_native():
    d=load(JOURNAL/'e07-analysis.json')
    out=dict(eventCounts=d['eventCounts'],discardedEvents=0,flowObservedSeconds=d['flowObservedSeconds'],workers={s:keep(w,WORKER) for s,w in d['workers'].items()},
             receiverVirtualWindowBytes=[r['bytes'] for rows in d['growth'].values() for r in rows],lossDeclarations=d['eventCounts']['CLOG_LOSS_DETECTION_C:ConnPacketLost'],flowResults={})
    for side,r in d['flowResults'].items():
        out['flowResults'][side]=keep(r,['writeSizes','timings','edgeQuality','unmatchedRequestsRightEdge','receiveStateEventCounts','datapathSendShapes','sendEvents','sendBytes','receiveEvents','receiveShapes','offeredBytesTotal','acceptedBytesTotal','offeredSizes','acceptedSizes'])
        out['flowResults'][side]['residence']=[keep(x,['kind','windowNs','unknownInitialPercent','statePercent','flagPercent']) for x in r['residence']]
    e=load(JOURNAL/'e08-worker-identity.json')
    out['filteredCapture']=dict(eventCounts=e['eventCounts'],discardedEvents=0,identityVerified=e['identityProvenSameProcess'],lossDeclarations=e['eventCounts']['CLOG_LOSS_DETECTION_C:ConnPacketLost'])
    return out


def export_calibration():
    rows=[]
    for name in ['causal-e06-calibration','causal-e06-calibration2']:
        raw=load(ROOT/'evidence'/name/'manifest.json')
        phases=[json.loads(line[len('PHASE_FINISHED '):]) for line in raw['stdout'].splitlines() if line.startswith('PHASE_FINISHED ')]
        rows.append(dict(id=name,status='collector-startup-guard-rejected' if name.endswith('calibration') else 'passed',targetExit=raw['exitCode'],rawManifestSha256=sha(ROOT/'evidence'/name/'manifest.json'),phases=[keep(p,['phase','wallMilliseconds','processCpuMilliseconds']) for p in phases]))
    raw=load(JOURNAL/'e08-calibration-accepted.json')
    rows.append(dict(id='causal-e08-calibration',status=raw['status'],targetExit=raw['exitCode'],registrarSha256=raw['bridgeSha256'],binarySha256=raw['binarySha256'],sourceSha256=raw['sourceSha256'],gcMode=raw['gcMode'],phases=[keep(p,['phase','wallMilliseconds','processCpuMilliseconds','selectedThreadCpuMilliseconds','profileSha256','samples','sampledCpuSeconds','profileCpuRatio']) for p in raw['phases']]))
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('output',type=Path);args=parser.parse_args()
    if args.output.exists():raise SystemExit('Use a fresh directory; never overwrite published evidence')
    blocks=[];identities=set()
    for experiment,cell in BLOCKS:
        b,identity=export_block(experiment,cell);blocks.append(b);identities.add(identity)
    if len(identities)!=1:raise ValueError('Identity changed within study')
    profiles=[export_profile('E06',t,s) for t in ['quic','tls'] for s in ['client','server']]+[export_profile('E08','quic',s) for s in ['client','server']]
    data=dict(schemaVersion=1,identityFixedAcrossAllBlocks=True,blocks=blocks,profiles=profiles,nativeTrace=export_native(),calibration=export_calibration())
    validate(data)
    args.output.mkdir(parents=True)
    save(args.output/'measurements.json',data);save(args.output/'summary.json',summary(data))
    table=[]
    for b in blocks:
        for r in b['runs']:
            table.append(dict(attempt=r['id'],experiment=b['experiment'],cell=b['cell'],transport=r['transport'],measurementClass=b['measurementClass'],**r['metrics']))
    with (args.output/'attempts.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(table[0]),lineterminator="\n");w.writeheader();w.writerows(table)
    diagnostic=[]
    for b in blocks:
        if b['measurementClass']!='progress-diagnostic':continue
        for r in b['runs']:
            c=r['phases']['client'][1];p=c['progress'];freq=p['clockFrequency']
            point=dict(attempt=r['id'],experiment=b['experiment'],cell=b['cell'],transport=r['transport'],framesPerSecond=r['metrics']['framesPerSecond'],sampleEvery=64,
                       creditEpisodes=p['creditEpisodes'],creditWaitPercent=100*p['creditWait']['totalTicks']/freq/c['elapsedSeconds'],
                       creditChannelReads=p['creditChannelReads'],creditReadsReady=p['creditChannelReadsReady'],creditReadsNotReady=p['creditChannelReadsAwaited'],
                       writes=c['dataWrites'],writesReady=p['dataWritesReady'],writeSamples=p['write']['count'])
            for key in ['write','invocation','remaining']:
                point[key+'MeanUs']=p[key]['totalTicks']/freq*1e6/p[key]['count']
            diagnostic.append(point)
    with (args.output/'progress.csv').open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(diagnostic[0]),lineterminator="\n");w.writeheader();w.writerows(diagnostic)
    env=load(JOURNAL/'e00-environment-private.json')
    environment=dict(capturedUtc=env['capturedUtc'],**keep(env,['kernel','architecture','cpu','affinity','governor','loadAverage']),
        operatingSystem='Ubuntu 24.04.5 LTS',physicalCores=12,logicalProcessors=24,
        sdk='10.0.403',cliHost='11.0.0-rc.3.26522.148',endpointRuntime='.NET 10.0.14',build='Release',serverGc=True,tieredPgo=True,gcLatencyMode='Interactive',
        nativeVersions=dict(msquic='2.6.3',openssl='3.0.13-0ubuntu3.16',glibc='2.39-0ubuntu8.9',gperftools='2.15-3build1'),
        nativePins=load(ROOT/'.local/native-pins.json'),loadedManagedAssemblySha256=load(JOURNAL/'loaded-managed-assembly-hashes.json'),
        network=dict(interface='lo',mtu=65536,interfaceGso=True,interfaceGro=True,txUdpSegmentation=True,nativeTraceGsoGroObserved=True,dominantNativeSegmentBytes=1472,dominantNativeBatchBytes=64768),
        measurementLimits=['Nondedicated desktop; unrelated activity was observed. Per-block load snapshots accompany primary evidence.',
            'Endpoint security/runtime/native maps checked for every attempt; managed assembly hashes separately checked in four E06 endpoints.',
            'Process leader affinity 0-23; diagnostic snapshots also record per-thread affinity. No dedicated CPU isolation.',
            'perf_event_paranoid=4; perf task-clock denied. Userspace per-thread CPU timers provide native and JIT leaf samples; no kernel stacks or complete off-CPU attribution.',
            'Loopback result; no hardware NIC offload, two-host, multiple-stream or impaired-network conclusion.'],
        profiler=dict(originalRegistrarSha256='7f49e224917ff33f32dc1d2ead106aa23d63af8c5f09d184f596f1dffcef8307',filteredRegistrarSha256='bbcbf3868fd4b5c1b7e224a1e902e54249e2da71b988015260e61aeace71a552',librarySha256='4de292cb738a2daebd150b7b16f0e0a69a906152118a5f5d475573074408803f',traceLibrarySha256='bc9dfa228e996d19e4eb70bd5af1128ae345f4d045ace09c6a67a71280391e74'))
    save(args.output/'environment.json',environment)
    print('Exported 80 audited attempts, six profiles, trace summaries, calibration outcomes, and environment')


if __name__=='__main__':main()
