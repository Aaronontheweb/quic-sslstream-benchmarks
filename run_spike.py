#!/usr/bin/env python3
"""Paired raw transport controller. All workload processes run sequentially."""
import argparse, hashlib, json, math, os, shutil, signal, subprocess, time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
LAUNCHER=Path(os.environ.get('DOTNET_HOST_PATH') or shutil.which('dotnet') or 'dotnet')
IDENTITY=ROOT/'.local/identity'
NATIVE_PINS=ROOT/'.local/native-pins.json'
EXPECTED_RUNTIME='.NET 10.0.14'
BINARY=ROOT/'bin/Release/net10.0/TransportSpike.dll'

def digest(p):
    with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def validate_native(observed, transport, expected):
    prefixes=('libmsquic','libcoreclr','libssl','libcrypto')
    family=lambda name:next((p for p in prefixes if name.startswith(p)),None)
    required=set(prefixes if transport=='quic' else prefixes[1:])
    families={family(name) for name in observed}
    if not required.issubset(families):raise RuntimeError('Missing pinned native library family')
    for name,sha in observed.items():
        if family(name) is None or name not in expected or expected[name]!=sha:
            raise RuntimeError('Unrecognized or changed native library: '+name)
    for prefix in required:
        if {n for n in observed if family(n)==prefix}!={n for n in expected if family(n)==prefix}:
            raise RuntimeError('Native library versions differ in family: '+prefix)

def records(p,kind):
    return [json.loads(x[len(kind)+1:]) for x in p.read_text().splitlines() if x.startswith(kind+' ')]
def stop(p):
    if p.poll() is None:
        os.killpg(p.pid,signal.SIGKILL)
        p.wait()
def cell(path, transport, settings, client_extra=(), failure=None):
    path.mkdir(parents=True,exist_ok=False)
    common=['--transport',transport,'--cert',str(IDENTITY/'loopback.pfx'),'--pin',(IDENTITY/'thumbprint.txt').read_text().strip(),*settings]
    env={k:v for k,v in os.environ.items() if not k.startswith(('CPUPROFILE','PROFILER_')) and k not in ('LD_PRELOAD','DOTNET_EnableEventPipe','DOTNET_PerfMapEnabled')}
    env['LC_ALL']='C'
    row={'transport':transport,'settings':settings,'client_extra':list(client_extra),'expected_failure':failure,'status':'invalid'}
    server_log=path/'server.log';client_log=path/'client.log'
    with server_log.open('w') as out:
        server=subprocess.Popen([str(LAUNCHER),str(BINARY),'server',*common],stdout=out,stderr=subprocess.STDOUT,stdin=subprocess.PIPE,start_new_session=True,env=env,cwd=ROOT)
        client=None
        try:
            deadline=time.monotonic()+15
            while time.monotonic()<deadline and server.poll() is None:
                ready=records(server_log,'READY')
                if ready:break
                time.sleep(.02)
            else:raise RuntimeError('Server readiness failed')
            native={}
            for line in Path(f'/proc/{server.pid}/maps').read_text().splitlines():
                field=line.split()[-1]
                if field.startswith('/') and Path(field).name.startswith(('libmsquic','libcoreclr','libssl','libcrypto')):
                    native[field]=digest(field)
            with client_log.open('w') as out_client:
                # Later option overrides are explicit through a merged argument map, never duplicate CLI options.
                args=dict(zip(common[::2],common[1::2]));args.update(dict(zip(client_extra[::2],client_extra[1::2])))
                args['--port']=str(ready[-1]['port'])
                flat=[x for pair in args.items() for x in pair]
                client=subprocess.Popen([str(LAUNCHER),str(BINARY),'client',*flat],stdout=out_client,stderr=subprocess.STDOUT,start_new_session=True,env=env,cwd=ROOT)
                client.wait(timeout=80)
            # A successful client has received both phase-confirmation replies; now server may stop.
            server.stdin.close()
            server.wait(timeout=10)
            row.update(client_exit=client.returncode,server_exit=server.returncode,native_sha256=native)
            if failure:
                text=server_log.read_text()+'\n'+client_log.read_text()
                if client.returncode==0 or failure not in text:
                    raise RuntimeError('Expected failure did not reach intended guard: '+failure)
                row['status']='expected-failure'
                return row
            if client.returncode or server.returncode:raise RuntimeError('Nonzero workload process exit')
            phases={name:records(log,'PHASE') for name,log in [('client',client_log),('server',server_log)]}
            security={name:records(log,'SECURITY') for name,log in [('client',client_log),('server',server_log)]}
            for name in phases:
                if len(phases[name])!=2 or [r['phase'] for r in phases[name]]!=[0,1]:raise RuntimeError('Missing/duplicate phase records')
                if len(security[name])!=1:raise RuntimeError('Missing/duplicate security record')
                s=security[name][0]
                if (s['tls']!='Tls13' or s['cipher']!='TLS_AES_128_GCM_SHA256' or s['alpn']!='transport-spike-v1'
                    or s['peerPin']!=common[common.index('--pin')+1] or not s['mutual'] or s['runtime']!=EXPECTED_RUNTIME or not s['serverGc']):raise RuntimeError('Security mismatch')
            expected = dict(zip(settings[::2], settings[1::2]))
            payload = int(expected.get('--payload',348)); frame_bytes = payload+8
            window = int(expected.get('--window',1280)); cap = int(expected.get('--batch',16384))
            batch = min(window, 1 if cap==0 else cap//frame_bytes)
            pinned=json.loads(NATIVE_PINS.read_text())
            endpoint_native={}
            for name in security:
                endpoint_native[name]={Path(file).name:digest(file) for file in security[name][0]['nativeLibraries']}
                validate_native(endpoint_native[name],transport,pinned)
                for file in security[name][0]['nativeLibraries']:native[file]=digest(file)
            row['endpoint_native_sha256']=endpoint_native
            for c,s in zip(phases['client'],phases['server']):
                if not c['complete'] or not s['complete'] or c['frames']<=0 or c['frames']!=s['frames'] or c['dataBytes']!=s['dataBytes']:
                    raise RuntimeError('Incomplete delivery or mismatched validated counts')
                if c['dataBytes']!=c['frames']*c['frameBytes'] or c['maximumInFlight']>c['windowFrames']:
                    raise RuntimeError('Byte count or credit limit differs')
                if int(expected.get('--frames',0)) and c['frames']!=int(expected['--frames']):raise RuntimeError('Fixed count differs from requested frames')
                if (c['payloadBytes'],c['frameBytes'],c['windowFrames'],c['batchFrames'],c['batchBytes'])!=(payload,frame_bytes,window,batch,batch*frame_bytes):raise RuntimeError('Reported workload differs from requested workload')
                if c['ackReads']!=s['ackWrites']:raise RuntimeError('ACK count differs')
                boundary=int(expected.get('--ack-boundary',0))
                for endpoint in (c,s):
                    if endpoint.get('ackBoundaryFrames',batch)!=(boundary or batch) or endpoint['ackAtBatchBoundary']!=(boundary==0):
                        raise RuntimeError('ACK boundary differs from requested policy')
                fragment=int(expected.get('--fragment',0))
                full,tail=divmod(c['frames'],batch)
                calls=full*((batch*frame_bytes+fragment-1)//fragment if fragment else 1)
                if tail:calls+=(tail*frame_bytes+fragment-1)//fragment if fragment else 1
                if c['dataWrites']!=calls:raise RuntimeError('Fixed data batch write count differs')
                if c['maximumInFlight']<1 or s['dataReads']<1:raise RuntimeError('No data work observed')
                if c['ackReads']<1:raise RuntimeError('No peer delivery ACK')
                for k in ('payloadBytes','frameBytes','batchFrames','batchBytes','windowFrames','creditBytes','effectiveAckEvery','diagnostics','cancellation'):
                    if c[k]!=s[k]:raise RuntimeError('Workload mismatch: '+k)
                if c['omittedLatencySamples']:raise RuntimeError('Latency samples truncated')
                quantiles=[c[k] for k in ('p50Us','p95Us','p99Us')]
                if window==1:
                    if c['latencySamples']!=(c['frames']+63)//64 or any(x is None or not math.isfinite(x) or x<=0 for x in quantiles) or quantiles!=sorted(quantiles):
                        raise RuntimeError('Missing or invalid serial RTT samples')
                elif c['latencySamples']!=0 or any(x is not None for x in quantiles):raise RuntimeError('Unexpected parallel RTT samples')
                c['deliveredFramesPerSecond']=c['frames']/c['elapsedSeconds']
                c['deliveredPayloadBytesPerSecond']=c['frames']*c['payloadBytes']/c['elapsedSeconds']
                c['combinedCpuNanosecondsPerFrame']=(c['cpuMilliseconds']+s['cpuMilliseconds'])*1e6/c['frames']
                c['combinedManagedBytesPerFrame']=None if c['allocatedBytes'] is None else (c['allocatedBytes']+s['allocatedBytes'])/c['frames']
            if not '--frames' in settings and phases['client'][1]['elapsedSeconds']<float(settings[settings.index('--seconds')+1]):
                raise RuntimeError('Measured duration too short')
            row.update(status='valid',phases=phases,security=security)
        except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as error:
            row['error']=str(error)
        finally:
            if client:stop(client)
            stop(server)
            row['artifact_sha256']={p.name:digest(p) for p in path.iterdir() if p.is_file()}
    return row

def main():
    global BINARY, EXPECTED_RUNTIME, NATIVE_PINS
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['check','run']);parser.add_argument('output',type=Path)
    parser.add_argument('--build',type=Path,default=BINARY);parser.add_argument('--rounds',type=int,default=2);parser.add_argument('--payload',type=int,default=348)
    parser.add_argument('--batch',type=int,default=16384);parser.add_argument('--window',type=int,default=1280)
    parser.add_argument('--seconds',type=float,default=6);parser.add_argument('--warmup',type=float,default=2)
    parser.add_argument('--diagnostics',action='store_true');parser.add_argument('--cancellation',choices=['operation','lifetime'],default='operation')
    parser.add_argument('--ack-boundary',type=int,default=0)
    parser.add_argument('--expected-runtime',default=EXPECTED_RUNTIME)
    parser.add_argument('--native-pins',type=Path,default=NATIVE_PINS)
    a=parser.parse_args();BINARY=a.build.resolve();EXPECTED_RUNTIME=a.expected_runtime;NATIVE_PINS=a.native_pins.resolve()
    if a.rounds<=0:parser.error('rounds must be positive')
    if not NATIVE_PINS.is_file() or not (IDENTITY/'loopback.pfx').is_file():parser.error('Run prepare.py first')
    a.output.mkdir(parents=True,exist_ok=False)
    sources={str(p.relative_to(ROOT)):digest(p) for p in ROOT.iterdir() if p.suffix in ('.cs','.csproj','.py','.md','.json')}
    manifest=dict(mode=a.mode,arguments=vars(a)|{'output':str(a.output),'build':str(a.build),'native_pins':str(a.native_pins)},source_sha256=sources,binary_sha256=digest(BINARY),runtimeconfig=json.loads(BINARY.with_suffix('.runtimeconfig.json').read_text()),launcher_sha256=digest(LAUNCHER),native_pins_sha256=digest(NATIVE_PINS),certificate_sha256=digest(IDENTITY/'loopback.pfx'),dotnet_info=subprocess.check_output([str(LAUNCHER),'--info'],text=True,cwd=ROOT),revision=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip() if (ROOT/'.git/HEAD').exists() and subprocess.run(['git','rev-parse','--verify','HEAD'],cwd=ROOT,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0 else None)
    build_record=BINARY.parent/'build.json'
    if build_record.exists():
        build=json.loads(build_record.read_text())
        for name,sha in build['files'].items():
            if digest(BINARY.parent/name)!=sha:raise RuntimeError('Frozen build changed before run')
        manifest['frozen_build']=build
    (a.output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    specs=[]
    if a.mode=='check':
        for transport in ('tls','quic'):
            for window,batch,fragment in [(1,16384,0),(46,16384,0),(7,1068,17)]:
                specs.append((transport,['--frames','137','--window',str(window),'--batch',str(batch),'--fragment',str(fragment),'--warmup','.1','--seconds','.1'],[],None))
            for fault in ('sequence','payload'):
                specs.append((transport,['--frames','137','--warmup','.1','--seconds','.1'],['--corrupt',fault],'Frame order or payload corruption'))
            specs.append((transport,['--frames','137','--warmup','.1','--seconds','.1'],['--pin','0'*40],'pin-mismatch'))
    else:
        options=['--payload',str(a.payload),'--batch',str(a.batch),'--window',str(a.window),'--seconds',str(a.seconds),'--warmup',str(a.warmup),'--diagnostics',str(a.diagnostics).lower(),'--cancellation',a.cancellation]
        if a.ack_boundary:options+=['--ack-boundary',str(a.ack_boundary)]
        for n in range(a.rounds):
            for transport in (('quic','tls') if n%2==0 else ('tls','quic')):specs.append((transport,options,[],None))
    if a.mode=='check':
        if a.ack_boundary:
            for transport in ('tls','quic'):
                specs.append((transport,['--frames','137','--window','7','--batch','1068','--fragment','17','--ack-every','100','--ack-boundary','6','--warmup','.1','--seconds','.1'],[],None))
        for transport in ('tls','quic'):
            for cancellation in ('operation','lifetime'):
                specs.append((transport,['--warmup','2','--seconds','2','--cancellation',cancellation],['--abort-after-ms','50'],'ABORT_REQUESTED'))
    rows=[]
    for index,(transport,settings,extra,failure) in enumerate(specs):
        row=cell(a.output/f'{index:02d}-{transport}',transport,settings,extra,failure);row['index']=index
        rows.append(row)
        with (a.output/'runs.jsonl').open('a') as f:f.write(json.dumps(row)+'\n')
        print(json.dumps({'index':index,'transport':transport,'status':row['status'],'error':row.get('error')}),flush=True)
        if row['status']=='invalid':raise RuntimeError(row.get('error','Invalid attempt'))
    if digest(NATIVE_PINS)!=manifest['native_pins_sha256']:raise RuntimeError('Native pins changed during run')
    if digest(IDENTITY/'loopback.pfx')!=manifest['certificate_sha256']:raise RuntimeError('Identity file changed during run')
    for row in rows:
        for file,sha in row.get('native_sha256',{}).items():
            if digest(file)!=sha:raise RuntimeError('Native library changed during run')
    if digest(BINARY)!=manifest['binary_sha256'] or any(digest(ROOT/p)!=sha for p,sha in sources.items()):raise RuntimeError('Source/build changed during run')
    if 'frozen_build' in manifest:
        for name,sha in manifest['frozen_build']['files'].items():
            if digest(BINARY.parent/name)!=sha:raise RuntimeError('Frozen build changed during run')
    (a.output/'complete.json').write_text(json.dumps({'state':'complete','attempts':len(rows)})+'\n')
if __name__=='__main__':main()
