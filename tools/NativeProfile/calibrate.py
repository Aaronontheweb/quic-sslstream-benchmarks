#!/usr/bin/env python3
"""Known-CPU/sleep and selected-thread controls; run before native capture, never during timing."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('capture',ROOT/'profile_spike.py')
capture=importlib.util.module_from_spec(spec);spec.loader.exec_module(capture)
spec=importlib.util.spec_from_file_location('resolver',Path(__file__).with_name('resolve_profile.py'))
resolver=importlib.util.module_from_spec(spec);spec.loader.exec_module(resolver)
sha=lambda path:hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    parser.add_argument('--dotnet-launcher',type=Path,required=True)
    parser.add_argument('--bridge',type=Path,required=True)
    parser.add_argument('--build',type=Path,required=True)
    args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    os.mkfifo(out/'control.fifo',0o600)
    env={k:v for k,v in os.environ.items() if not k.startswith(('CPUPROFILE','PROFILER_')) and k not in ['LD_PRELOAD','DOTNET_PerfMapEnabled','DOTNET_EnableEventPipe']}
    env.update(LD_PRELOAD=str(args.bridge.resolve()),QSS_PROFILE_BRIDGE=str(args.bridge.resolve()),
               CPUPROFILE_PER_THREAD_TIMERS='1',CPUPROFILE_FREQUENCY='100',DOTNET_PerfMapEnabled='3',
               PROFILER_OUTPUT_ROOT=str(out),PROFILER_CONTROL_FIFO=str(out/'control.fifo'),
               PROFILER_CONTROL_ACK=str(out/'control.ack'),PROFILER_THREAD_AUDIT=str(out/'threads.log'))
    argv=[str(args.dotnet_launcher.resolve()),str(args.build.resolve())]
    record=dict(status='incomplete',command=argv,bridgeSha256=sha(args.bridge),binarySha256=sha(args.build),
                sourceSha256=sha(__file__),snapshots=[],gcMode='calibration project default; benchmark ServerGC is separate')
    with (out/'target.log').open('w') as log:
        p=subprocess.Popen(argv,stdout=log,stderr=subprocess.STDOUT,stdin=subprocess.PIPE,env=env,cwd=ROOT,start_new_session=True)
        start=time.monotonic();last=0
        try:
            while p.poll() is None:
                text=(out/'target.log').read_text()
                if 'COMPLETE_WAITING_FOR_MAP_COPY' in text:
                    shutil.copyfile(f'/tmp/perf-{p.pid}.map',out/'managed-perf.map')
                    maps=Path(f'/proc/{p.pid}/maps').read_text();(out/'maps.txt').write_text(maps)
                    record['mappedLibrarySha256']={file:sha(file) for file in {line.split()[-1] for line in maps.splitlines()} if file.startswith('/') and '.so' in file and Path(file).is_file()}
                    if str(args.bridge.resolve()) not in record['mappedLibrarySha256']:raise RuntimeError('Selected bridge is not mapped')
                    p.communicate(b'exit\n',timeout=5)
                    break
                if time.monotonic()-last>.2:
                    snap=capture.snapshot(p.pid);snap['afterPhaseStartedWitness']='PHASE_STARTED' in text
                    record['snapshots'].append(snap);last=time.monotonic()
                if time.monotonic()-start>25:raise TimeoutError('Calibration exceeded25s')
                time.sleep(.02)
        finally:
            if p.poll() is None:p.kill();p.wait()
            record.update(exitCode=p.returncode,stdout=(out/'target.log').read_text())
            (out/'manifest.json').write_text(json.dumps(record,indent=2)+'\n')
    if p.returncode!=0 or 'CONTROL_JOINED' not in record['stdout'] or 'EXIT_ACKNOWLEDGED' not in record['stdout']:
        raise RuntimeError('Calibration did not exit cleanly')
    registered={int(line.split()[1]) for line in (out/'threads.log').read_text().splitlines()}
    for snap in record['snapshots']:
        live={int(tid) for tid in snap['stableTaskIds'] if not snap['tasks'][tid].get('exitedDuringSnapshot')}
        snap['missingRegistered']=sorted(live-registered);snap['missingTimers']=sorted(live-set(snap['timerTargets']))
        if snap['afterPhaseStartedWitness'] and (snap['missingRegistered'] or snap['missingTimers'] or snap['duplicateTimerTargets']):
            raise RuntimeError('Registration/timer coverage failed')
    header=json.loads(record['stdout'].splitlines()[0])
    if 'libprofiler' not in header['signal27Owner'] or header['signal12Owner']!='default':raise RuntimeError('Signal ownership differs')
    acks=(out/'control.ack').read_text().splitlines()
    phases=[]
    for line in record['stdout'].splitlines():
        if not line.startswith('PHASE_FINISHED '):continue
        row=json.loads(line[len('PHASE_FINISHED '):]);profile=out/(row['phase']+'.prof')
        period,leaves,*_=resolver.read_profile(profile);sampled=sum(leaves.values())*period/1e6
        cpu=(row['selectedThreadCpuMilliseconds'] if row['selectedThreadId'] is not None else row['processCpuMilliseconds'])/1000
        row.update(profileSha256=sha(profile),samples=sum(leaves.values()),sampledCpuSeconds=sampled,profileCpuRatio=sampled/cpu)
        if row['phase']=='sleep':
            if sampled>.1:raise RuntimeError('Sleeping negative control sampled too muchCPU')
        elif not .8<sampled/cpu<1.2:raise RuntimeError('CPU calibration sample accounting differs')
        if row['selectedThreadId'] is not None:
            if not any(a.startswith('SELECTED_TID '+str(row['selectedThreadId'])+' ') for a in acks):raise RuntimeError('Missing selected-TID acknowledgement')
            if row['processCpuMilliseconds']<1800:raise RuntimeError('Concurrent distractor did not consume expectedCPU')
        phases.append(row)
    if len(phases)!=6:raise RuntimeError('Missing calibration phase')
    if sha(args.bridge)!=record['bridgeSha256'] or sha(args.build)!=record['binarySha256']:raise RuntimeError('Calibration binary changed')
    record.update(status='accounting-passed-awaiting-symbol-identity-check',phases=phases)
    (out/'manifest.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(status=record['status'],phases=phases),indent=2))


if __name__=='__main__':
    main()
