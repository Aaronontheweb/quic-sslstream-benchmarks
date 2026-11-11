#!/usr/bin/env python3
"""Separate, native-aware diagnostic captures through the normal paired controller.

Requires a built per-thread registrar and gperftools libprofiler. Never primary timing.
No analysis, symbol resolution or remote operations run while a target is active.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def snapshot(pid):
    proc = Path(f'/proc/{pid}')
    timers = (proc/'timers').read_text()
    targets = [int(tid) for tid in re.findall(r'notify:\s+signal/tid\.(\d+)', timers)]
    tasks = {}
    for task in (proc/'task').iterdir():
        try:
            fields = (task/'stat').read_text().rsplit(')', 1)[1].split()
            status = (task/'status').read_text()
            tasks[task.name] = dict(name=(task/'comm').read_text().strip(), userTicks=int(fields[11]),
                                   systemTicks=int(fields[12]), startTicks=int(fields[19]),
                                   schedstat=[int(x) for x in (task/'schedstat').read_text().split()],
                                   affinity=re.search(r'^Cpus_allowed_list:\s+(.*)$', status, re.M).group(1))
        except FileNotFoundError:
            # A thread exiting during a /proc snapshot is explicitly unobservable.
            tasks[task.name] = dict(exitedDuringSnapshot=True)
    return dict(monotonicSeconds=time.monotonic(), tasks=tasks, timerTargets=targets,
                duplicateTimerTargets=sorted(tid for tid in set(targets) if targets.count(tid)>1),
                rawTimers=timers, io=(proc/'io').read_text(), status=(proc/'status').read_text())


def command(endpoint, message, state, profile, process):
    deadline = time.monotonic() + 2
    fd = os.open(endpoint/'control.fifo', os.O_WRONLY | os.O_NONBLOCK)
    try:
        data = (message+'\n').encode()
        if len(data)>4096 or os.write(fd,data)!=len(data):
            raise RuntimeError('Partial/oversized profiler command')
    finally:
        os.close(fd)
    while time.monotonic()<deadline:
        if process.poll() is not None:
            raise RuntimeError('Controller exited before profiler acknowledgement')
        for line in (endpoint/'control.ack').read_text().splitlines():
            fields = line.split()
            if len(fields)==5 and fields[:2]==[state,str(profile)]:
                return dict(state=state, path=fields[1], monotonicSeconds=float(fields[2]),
                            userSeconds=float(fields[3]), systemSeconds=float(fields[4]))
        time.sleep(.01)
    raise TimeoutError('Profiler control acknowledgement missing')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    parser.add_argument('--transport',choices=['quic','tls'],required=True)
    parser.add_argument('--build',type=Path,required=True)
    parser.add_argument('--dotnet-launcher',type=Path,required=True)
    parser.add_argument('--registrar',type=Path,required=True)
    parser.add_argument('--profiler',type=Path,required=True)
    args=parser.parse_args()
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    for role in ['server','client']:
        endpoint=out/role;endpoint.mkdir();os.mkfifo(endpoint/'control.fifo',0o600)
    launcher=out/'launcher.py'
    config=dict(output=str(out),transport=args.transport,original=str(args.dotnet_launcher.resolve()),
                registrar=str(args.registrar.resolve()))
    # repr serializes Python literals; no shell interpolation of paths/arguments.
    launcher.write_text('#!/usr/bin/env python3\nimport json,os,sys\nfrom pathlib import Path\n'
        +f'config={config!r}\n'
        +'env=os.environ.copy()\n'
        +'if len(sys.argv)>2 and sys.argv[2] in ("server","client"):\n'
        +' role=sys.argv[2]; opts=dict(zip(sys.argv[3::2],sys.argv[4::2]))\n'
        +' if opts.get("--transport")==config["transport"]:\n'
        +'  endpoint=Path(config["output"])/role\n'
        +'  (endpoint/"pid.json").write_text(json.dumps({"pid":os.getpid(),"role":role}))\n'
        +'  env.update(LD_PRELOAD=config["registrar"],CPUPROFILE_PER_THREAD_TIMERS="1",CPUPROFILE_FREQUENCY="100",DOTNET_PerfMapEnabled="3",PROFILER_THREAD_AUDIT=str(endpoint/"threads.log"),PROFILER_CONTROL_FIFO=str(endpoint/"control.fifo"),PROFILER_CONTROL_ACK=str(endpoint/"control.ack"))\n'
        +'os.execve(config["original"],[config["original"],*sys.argv[1:]],env)\n')
    launcher.chmod(0o700)
    env={k:v for k,v in os.environ.items() if not k.startswith(('CPUPROFILE','PROFILER_')) and k not in ['LD_PRELOAD','DOTNET_PerfMapEnabled','DOTNET_EnableEventPipe']}
    env['DOTNET_HOST_PATH']=str(launcher)
    argv=['python3','run_spike.py','run',str(out/'run'),'--build',str(args.build.resolve()),
          '--rounds','1','--payload','348','--batch','65536','--window','5120','--ack-boundary','1104']
    record=dict(status='incomplete',command=argv,profileTransport=args.transport,profileHz=100,
                registrarSha256=sha(args.registrar),profilerSha256=sha(args.profiler),
                controllerSha256=sha(__file__),launcherSha256=sha(launcher),dotnetLauncherSha256=sha(args.dotnet_launcher),
                clockTicks=os.sysconf('SC_CLK_TCK'),startedUnixSeconds=time.time(),endpoints={})
    (out/'profile-manifest.json').write_text(json.dumps(record,indent=2)+'\n')
    with (out/'controller.log').open('w') as log:
        controller=subprocess.Popen(argv,cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        try:
            index=0 if args.transport=='quic' else 1
            client_log=out/'run'/f'{index:02d}-{args.transport}'/'client.log'
            deadline=time.monotonic()+30
            while time.monotonic()<deadline:
                if controller.poll() is not None:raise RuntimeError('Controller stopped before warmup witness')
                if client_log.exists() and any(line.startswith('PHASE ') for line in client_log.read_text().splitlines()):break
                time.sleep(.02)
            else:raise TimeoutError('Warmup witness missing')
            record['warmupWitnessObservedMonotonic']=time.monotonic()
            time.sleep(.5)
            for role in ['server','client']:
                endpoint=out/role;pid=json.loads((endpoint/'pid.json').read_text())['pid']
                info=dict(pid=pid,profile=str(endpoint/'cpu.prof'))
                record['endpoints'][role]=info
                info['started']=command(endpoint,'START '+info['profile'],'STARTED',info['profile'],controller)
                info['startSnapshot']=snapshot(pid)
            time.sleep(4)
            for role in ['client','server']:
                endpoint=out/role;info=record['endpoints'][role]
                info['endSnapshot']=snapshot(info['pid'])
                info['stopped']=command(endpoint,'STOP','STOPPED',info['profile'],controller)
            if len([l for l in client_log.read_text().splitlines() if l.startswith('PHASE ')])!=1:
                raise RuntimeError('Profile extended beyond measurement phase witness')
            record['stoppedBeforeMeasuredPhaseWitness']=True
            for role in ['client','server']:
                endpoint=out/role;info=record['endpoints'][role];pid=info['pid']
                shutil.copyfile(f'/tmp/perf-{pid}.map',endpoint/'managed-perf.map')
                maps=Path(f'/proc/{pid}/maps').read_text()
                (endpoint/'maps.txt').write_text(maps)
                loaded={line.split()[-1] for line in maps.splitlines() if line.split()[-1].startswith('/')}
                for expected in [args.registrar,args.profiler]:
                    if not any(Path(file).resolve()==expected.resolve() and sha(file)==sha(expected) for file in loaded):
                        raise RuntimeError('Pinned profiling instrumentation not mapped')
                info['quit']=command(endpoint,'QUIT','QUITTED','-',controller)
                registered={int(line.split()[1]) for line in (endpoint/'threads.log').read_text().splitlines()}
                for name in ['startSnapshot','endSnapshot']:
                    snap=info[name]; live={int(tid) for tid,row in snap['tasks'].items() if 'exitedDuringSnapshot' not in row}
                    snap['missingRegisteredThreads']=sorted(live-registered)
                    snap['missingTimerThreads']=sorted(live-set(snap['timerTargets']))
                    if snap['missingRegisteredThreads'] or snap['missingTimerThreads'] or snap['duplicateTimerTargets']:
                        raise RuntimeError('Thread/timer registration coverage failed')
            controller.wait(timeout=40)
            if controller.returncode:raise RuntimeError('Controller failed')
            record.update(status='complete',controllerExit=controller.returncode,completedUnixSeconds=time.time())
        finally:
            if controller.poll() is None:
                # SIGINT lets cell() run its finally block for both separate child sessions.
                children=Path(f'/proc/{controller.pid}/task/{controller.pid}/children').read_text().split()
                controller.send_signal(signal.SIGINT)
                try:controller.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    for pid in children:
                        try:os.kill(int(pid),signal.SIGKILL)
                        except ProcessLookupError:pass
                    controller.kill();controller.wait()
            for role in ['client','server']:
                record.setdefault('artifactSha256',{})[role]={p.name:sha(p) for p in (out/role).iterdir() if p.is_file()}
            (out/'profile-manifest.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(output=str(out),status=record['status'],transport=args.transport)))


if __name__=='__main__':
    main()
