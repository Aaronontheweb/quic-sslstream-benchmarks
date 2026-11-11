#!/usr/bin/env python3
"""Validate/recompute sanitized causal-study evidence. Raw-log checks require local artifacts."""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import subprocess

from run_spike import validate_native, validate_progress

ROOT=Path(__file__).resolve().parent
COMPARISONS={'E02':('old','new'),'E03':('off','on'),'E04':('A','B'),'E05':('B','C')}
BLOCKS=[('E02',c) for c in ['old1','new1','new2','old2']]+[('E03',c) for c in ['off1','on1','on2','off2']]+[('E04',c) for c in ['A1','B1','B2','A2','Bdiag']]+[('E05',c) for c in ['B1','C1','C2','B2','Cdiag']]+[('E06','quic'),('E06','tls'),('E07','native'),('E08','worker')]
METRICS=['framesPerSecond','framedGBPerSecond','payloadGBPerSecond','combinedCpuNsPerFrame','clientCpuMilliseconds','serverCpuMilliseconds','writesPerSecond','readsPerSecond','ackRecordsPerSecond','framesPerActualAck','framedBytesPerRead']
COPY_PATTERN='memcpy|memmove'
ALLOCATOR_PATTERN=r'malloc|calloc|realloc|(^|_)free($|_)'
YIELD_PATTERN='yield|spin'


def metrics(row):
    c,s=(row['phases'][side][1] for side in ['client','server'])
    return dict(framesPerSecond=c['frames']/c['elapsedSeconds'],framedGBPerSecond=c['dataBytes']/c['elapsedSeconds']/1e9,
                payloadGBPerSecond=c['frames']*c['payloadBytes']/c['elapsedSeconds']/1e9,
                combinedCpuNsPerFrame=(c['cpuMilliseconds']+s['cpuMilliseconds'])*1e6/c['frames'],
                clientCpuMilliseconds=c['cpuMilliseconds'],serverCpuMilliseconds=s['cpuMilliseconds'],
                writesPerSecond=c['dataWrites']/c['elapsedSeconds'],readsPerSecond=s['dataReads']/s['elapsedSeconds'],
                ackRecordsPerSecond=c['ackReads']/c['elapsedSeconds'],framesPerActualAck=c['frames']/c['ackReads'],
                framedBytesPerRead=s['dataBytes']/s['dataReads'])


def classify_functions(functions):
    return {'namedCopyMove':sum(r['samples'] for r in functions if re.search(COPY_PATTERN,r['function'],re.I)),
            'libcAllocationFree':sum(r['samples'] for r in functions if r['module']=='libc.so.6' and re.search(ALLOCATOR_PATTERN,r['function'],re.I)),
            'namedYieldSpin':sum(r['samples'] for r in functions if re.search(YIELD_PATTERN,r['function'],re.I)),
            'namedZero':sum(r['samples'] for r in functions if re.search('memset|bzero',r['function'],re.I))}


def validate(data,source_check=True):
    blocks=data['blocks']
    if data['schemaVersion']!=1 or [(b['experiment'],b['cell']) for b in blocks]!=BLOCKS:
        raise ValueError('Incomplete/unexpected block coverage or order')
    seen=set();total=progress=uninstrumented=0
    for block in blocks:
        n=2*block['rounds'];opt=block['options'];batch=min(opt['window'],opt['batch']//356)
        if block['completion']!={'state':'complete','attempts':n} or len(block['runs'])!=n:raise ValueError('Incomplete attempts')
        if (opt['payload'],opt['ackBoundary'],opt['warmup'],opt['seconds'],opt['cancellation'],opt['diagnostics'])!=(348,1104,2,6,'operation',False):raise ValueError('Unexpected common control')
        if block['experiment'] in COMPARISONS and block['rounds']!=2 or block['experiment'] not in COMPARISONS and block['rounds']!=1:raise ValueError('Rounds differ')
        expected_progress=block['cell'] in ['on1','on2','Bdiag','Cdiag']
        expected_batch=131072 if block['cell'].startswith('C') else 65536
        expected_window=5120 if block['experiment'] in ['E06','E07','E08'] or block['experiment']=='E04' and block['cell'].startswith('B') or block['experiment']=='E05' else 1280
        if (opt['progress'],opt['batch'],opt['window'],opt['sampleEvery'])!=(expected_progress,expected_batch,expected_window,64):raise ValueError('Cell control differs')
        required={'Program.cs','Protocol.cs'} | ({'ProgressCounters.cs'} if block['build']['progressSchema'] else set())
        if set(block['build']['workloadSha256'])!=required:raise ValueError('Missing workload source hashes')
        expected_class='native-diagnostic-and-context' if block['experiment'] in ['E06','E07','E08'] else 'progress-diagnostic' if expected_progress else 'uninstrumented'
        if block['measurementClass']!=expected_class:raise ValueError('Measurement classification differs')
        if source_check:
            for name,sha in block['build']['workloadSha256'].items():
                content=subprocess.check_output(['git','show',block['build']['codeRef']+':'+name],cwd=ROOT)
                if hashlib.sha256(content).hexdigest()!=sha:raise ValueError('Workload source differs')
        if block['build']['files']['TransportSpike.dll']!=block['build']['binarySha256']:raise ValueError('Build fingerprint differs')
        for index,row in enumerate(block['runs']):
            total+=1;progress+=int(expected_progress);uninstrumented+=int(block['experiment'] in COMPARISONS and not expected_progress)
            order=('quic','tls') if index//2%2==0 else ('tls','quic')
            if (row['index'],row['transport'],row['status'],row['clientExit'],row['serverExit'])!=(index,order[index%2],'valid',0,0):raise ValueError('Invalid attempt/order')
            if row['id'] in seen:raise ValueError('Duplicate attempt')
            seen.add(row['id'])
            for side in ['client','server']:
                security=row['security'][side]
                if len(security)!=1 or (security[0]['runtime'],security[0]['tls'],security[0]['cipher'],security[0]['alpn'],security[0]['mutual'],security[0]['serverGc'])!=('.NET 10.0.14','Tls13','TLS_AES_128_GCM_SHA256','transport-spike-v1',True,True):raise ValueError('Security/runtime differs')
                validate_native(row['endpointNativeSha256'][side],row['transport'],block['nativePins'])
                if [p['phase'] for p in row['phases'][side]]!=[0,1]:raise ValueError('Phase coverage differs')
            for c,s in zip(row['phases']['client'],row['phases']['server']):
                for endpoint in [c,s]:
                    if not endpoint['complete'] or (endpoint['payloadBytes'],endpoint['frameBytes'],endpoint['batchFrames'],endpoint['batchBytes'],endpoint['windowFrames'],endpoint['creditBytes'],endpoint['ackBoundaryFrames'],endpoint['effectiveAckEvery'],endpoint['cancellation'],endpoint['diagnostics'])!=(348,356,batch,batch*356,opt['window'],opt['window']*356,1104,10,'operation',False):raise ValueError('Reported parameters differ')
                    validate_progress(endpoint,expected_progress,64,endpoint is c,block['build']['progressSchema'])
                if c['frames']<=0 or c['frames']!=s['frames'] or c['dataBytes']!=s['dataBytes'] or c['dataBytes']!=c['frames']*356 or c['ackReads']!=s['ackWrites'] or c['ackReads']<1:raise ValueError('Delivery/ACK counts differ')
                if c['frames']%batch or c['dataWrites']!=c['frames']//batch or not 0<c['maximumInFlight']<=opt['window']:raise ValueError('Write/credit arithmetic differs')
                if c['allocatedBytes'] is not None or s['allocatedBytes'] is not None:raise ValueError('Unexpected allocation diagnostics')
                for endpoint in [c,s]:
                    if endpoint['latencySamples'] or endpoint['omittedLatencySamples'] or any(endpoint[q] is not None for q in ['p50Us','p95Us','p99Us']):raise ValueError('Unexpected latency evidence')
                if c['elapsedSeconds']<(2 if c['phase']==0 else 6) or min(c['cpuMilliseconds'],s['cpuMilliseconds'])<0:raise ValueError('Invalid duration/CPU')
            actual=metrics(row)
            for key,value in actual.items():
                if not math.isfinite(value) or not math.isclose(row['metrics'][key],value,rel_tol=1e-12):raise ValueError('False arithmetic: '+key)
    if (total,progress,uninstrumented)!=(80,16,56):raise ValueError('Study coverage differs')
    expected_profiles=[('E06',t,s,'endpoint') for t in ['quic','tls'] for s in ['client','server']]+[('E08','quic',s,'identified-worker') for s in ['client','server']]
    if [(p['experiment'],p['transport'],p['endpoint'],p['scope']) for p in data['profiles']]!=expected_profiles:raise ValueError('Native profile coverage differs')
    for p in data['profiles']:
        grouped=Counter()
        for f in p['functions']:
            if not isinstance(f['samples'],int) or f['samples']<1 or not math.isclose(f['percentage'],100*f['samples']/p['samples'],rel_tol=1e-12):raise ValueError('Profile function arithmetic differs')
            grouped[f['module']]+=f['samples']
        if dict(grouped)!=p['modules'] or not 0<=p['unambiguousNamedSamples']<=p['samples']:raise ValueError('Profile module/known coverage differs')
        if sum(p['modules'].values())!=p['samples'] or sum(f['samples'] for f in p['functions'])!=p['samples']:raise ValueError('Profile sample coverage differs')
        if not math.isclose(p['sampledCpuSeconds'],p['samples']*p['periodMicroseconds']/1e6,rel_tol=1e-12) or not .95<p['sampledCpuSeconds']/p['accountedCpuSeconds']<1.05:raise ValueError('Profile CPU accounting differs')
        if classify_functions(p['functions'])!=p['leafNameCategories']:raise ValueError('Profile category differs')
        if p['scope']=='identified-worker' and (not p['identityVerified'] or p['leafNameCategories']['namedYieldSpin']!=0):raise ValueError('Worker evidence differs')
    trace=data['nativeTrace']
    if sum(trace['eventCounts'].values())!=117600 or trace['discardedEvents']!=0 or trace['lossDeclarations']!=trace['eventCounts']['CLOG_LOSS_DETECTION_C:ConnPacketLost']:raise ValueError('Native trace coverage differs')
    filtered=trace['filteredCapture']
    if sum(filtered['eventCounts'].values())!=10334 or filtered['discardedEvents']!=0 or not filtered['identityVerified'] or filtered['lossDeclarations']!=filtered['eventCounts']['CLOG_LOSS_DETECTION_C:ConnPacketLost']:raise ValueError('Filtered trace coverage differs')
    if trace['receiverVirtualWindowBytes']!=[131072,262144,524288,1048576,2097152,4194304,8388608] or set(trace['workers'])!={'client','server'}:raise ValueError('Native window/worker evidence differs')
    for side,worker in trace['workers'].items():
        if not math.isclose(worker['percentOfOneCore'],100*(worker['userSeconds']+worker['systemSeconds'])/worker['wallSeconds'],rel_tol=1e-12):raise ValueError('Worker CPU arithmetic differs')
        flow=trace['flowResults'][side]
        for residence in flow['residence']:
            if not math.isclose(sum(residence['statePercent'].values())+residence['unknownInitialPercent'],100,abs_tol=1e-9):raise ValueError('Native state residence differs')
    calibration=data['calibration']
    if [c['id'] for c in calibration]!=['causal-e06-calibration','causal-e06-calibration2','causal-e08-calibration'] or [c['status'] for c in calibration]!=['collector-startup-guard-rejected','passed','complete-accounting-and-symbol-identity-passed'] or any(c['targetExit']!=0 for c in calibration):raise ValueError('Calibration coverage differs')
    for c in calibration:
        expected=['native','managed','sleep','mixed']+(['filtered-native','filtered-managed'] if c is calibration[-1] else [])
        if [p['phase'] for p in c['phases']]!=expected:raise ValueError('Calibration phase coverage differs')
        for p in c['phases']:
            if p['wallMilliseconds']<=0 or p['processCpuMilliseconds']<0:raise ValueError('Calibration duration differs')
            if 'samples' in p:
                cpu=p.get('selectedThreadCpuMilliseconds') if p['phase'].startswith('filtered-') else p['processCpuMilliseconds']
                if not math.isclose(p['sampledCpuSeconds'],p['samples']*.01,abs_tol=1e-12) or not math.isclose(p['profileCpuRatio'],p['sampledCpuSeconds']/(cpu/1000),abs_tol=1e-12):raise ValueError('Calibration CPU arithmetic differs')
    # An allowlist export should already have removed private material; retain a publication guard.
    text=json.dumps(data)
    if any(token in text for token in ['/home/','/tmp/','memory.testlab','peerPin','nativeLibraries','BEGIN CERTIFICATE','PRIVATE KEY']):raise ValueError('Private publication material')


def summary(data):
    result={}
    for experiment,(control,candidate) in COMPARISONS.items():
        rows=[(b,r) for b in data['blocks'] if b['experiment']==experiment and b['cell'] not in ['Bdiag','Cdiag'] for r in b['runs']]
        entry={'arms':{},'nearBlockOrdinalPairedChanges':{},'sameRoundQuicVsTls':{}}
        for arm in [control,candidate]:
            entry['arms'][arm]={}
            selected=[r for b,r in rows if b['cell'] in [arm+'1',arm+'2']]
            for transport in ['quic','tls']:
                points=[r for r in selected if r['transport']==transport]
                entry['arms'][arm][transport]={'count':len(points),'metrics':{key:{'median':statistics.median(r['metrics'][key] for r in points),'minimum':min(r['metrics'][key] for r in points),'maximum':max(r['metrics'][key] for r in points),'values':[r['metrics'][key] for r in points]} for key in METRICS}}
            pairs=[]
            for block in [b for b in data['blocks'] if b['experiment']==experiment and b['cell'] in [arm+'1',arm+'2']]:
                for index in [0,2]:
                    pair={r['transport']:r['metrics']['framesPerSecond'] for r in block['runs'][index:index+2]};pairs.append(100*(pair['quic']/pair['tls']-1))
            entry['sameRoundQuicVsTls'][arm]={'values':pairs,'median':statistics.median(pairs)}
        for transport in ['quic','tls']:
            arms={arm:[r for b,r in rows if b['cell'] in [arm+'1',arm+'2'] and r['transport']==transport] for arm in [control,candidate]}
            entry['nearBlockOrdinalPairedChanges'][transport]={}
            for key in ['framesPerSecond','combinedCpuNsPerFrame']:
                values=[100*(new['metrics'][key]/old['metrics'][key]-1) for new,old in zip(arms[candidate],arms[control])]
                ratio=100*(entry['arms'][candidate][transport]['metrics'][key]['median']/entry['arms'][control][transport]['metrics'][key]['median']-1)
                entry['nearBlockOrdinalPairedChanges'][transport][key]={'values':values,'median':statistics.median(values),'ratioOfIndependentMedians':ratio}
        result[experiment]=entry
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path,nargs='?',default=ROOT/'results/causal-investigation');args=parser.parse_args()
    data=json.loads((args.directory/'measurements.json').read_text());validate(data);computed=summary(data)
    if computed!=json.loads((args.directory/'summary.json').read_text()):raise ValueError('Saved summaries differ')
    print(json.dumps({'attempts':80,'uninstrumented':56,'progressDiagnostic':16,'nativeDiagnosticAndContext':8,'profiles':6,'comparisons':computed},indent=2))


if __name__=='__main__':main()
