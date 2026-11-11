#!/usr/bin/env python3
"""Portable transcription of the recorded fixed-cell native capture recipe.

The measured private recorder hashes remain in the published provenance. This
version substitutes explicit toolchain paths; raw captures stay local/ignored.
"""
import grp,hashlib,importlib.util,json,os,re,signal,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
import argparse
parser=argparse.ArgumentParser(description="Bounded native diagnostic through the normal controller; never primary timing.")
parser.add_argument('output',type=Path)
parser.add_argument('--runtime-root',type=Path,required=True)
parser.add_argument('--native-directory',type=Path,required=True)
parser.add_argument('--lttng-root',type=Path,required=True)
parser.add_argument('--trace-library',type=Path,required=True)
parser.add_argument('--build',type=Path,required=True)
parser.add_argument('--registrar',type=Path,required=True)
parser.add_argument('--profiler',type=Path,required=True)
args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
runtime=str(args.runtime_root.resolve());native=str(args.native_directory.resolve())
lttng=args.lttng_root.resolve();libs=str(lttng/'usr/lib/x86_64-linux-gnu')
config={'root':str(lttng),'env':{'LD_LIBRARY_PATH':libs+':/usr/lib/x86_64-linux-gnu','LTTNG_NETWORK_SOCKET_TIMEOUT':'3000','LTTNG_SESSION_CONFIG_XSD_PATH':str(lttng/'usr/share/xml/lttng')},'command':[str(lttng/'usr/bin/lttng-sessiond'),'--no-kernel','--consumerd64-path='+str(lttng/'usr/lib/x86_64-linux-gnu/lttng/libexec/lttng-consumerd'),'--consumerd64-libdir='+libs,'--group='+grp.getgrgid(os.getgid()).gr_name]}

env={k:v for k,v in os.environ.items() if not k.startswith(('CPUPROFILE','PROFILER_')) and k not in ['LD_PRELOAD','DOTNET_PerfMapEnabled','DOTNET_EnableEventPipe']};env.update(config['env']);env.update(LTTNG_HOME=tempfile.mkdtemp(prefix='qss-lttng-'),DOTNET_ROOT=runtime,LD_LIBRARY_PATH=native.split(':')[0]+':'+config['env']['LD_LIBRARY_PATH'])
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
traceLib=args.trace_library.resolve();pins=json.loads((ROOT/'.local/native-pins.json').read_text());pins[traceLib.name]=sha(traceLib);(out/'native-pins.json').write_text(json.dumps(pins,indent=2)+'\n')
for role in ['client','server']:(out/role).mkdir()
launcher=out/'launcher.py'; launcher.write_text('#!/usr/bin/env python3\nimport json,os,sys\nfrom pathlib import Path\n'+f'out=Path({str(out)!r});dotnet={str(Path(runtime)/"dotnet")!r}\n'+'if len(sys.argv)>2 and sys.argv[2] in ["client","server"]:\n opts=dict(zip(sys.argv[3::2],sys.argv[4::2]))\n if opts.get("--transport")=="quic":(out/sys.argv[2]/"pid.json").write_text(json.dumps({"pid":os.getpid()}))\n'+'os.execve(dotnet,[dotnet,*sys.argv[1:]],os.environ)\n');launcher.chmod(0o700)
filterRegistrar=args.registrar.resolve()
profilerLibrary=args.profiler.resolve()
for side in ['client','server']:os.mkfifo(out/side/'control.fifo',0o600)
launcher.write_text('#!/usr/bin/env python3\nimport json,os,sys\nfrom pathlib import Path\n'+f'out=Path({str(out)!r});dotnet={str(Path(runtime)/"dotnet")!r};registrar={str(filterRegistrar)!r}\n'+'env=os.environ.copy()\nif len(sys.argv)>2 and sys.argv[2] in ["client","server"]:\n side=sys.argv[2];opts=dict(zip(sys.argv[3::2],sys.argv[4::2]))\n if opts.get("--transport")=="quic":\n  endpoint=out/side\n  (endpoint/"pid.json").write_text(json.dumps({"pid":os.getpid()}))\n  env.update(LD_PRELOAD=registrar,CPUPROFILE_PER_THREAD_TIMERS="1",CPUPROFILE_FREQUENCY="100",DOTNET_PerfMapEnabled="3",PROFILER_THREAD_AUDIT=str(endpoint/"threads.log"),PROFILER_CONTROL_FIFO=str(endpoint/"control.fifo"),PROFILER_CONTROL_ACK=str(endpoint/"control.ack"))\n'+'os.execve(dotnet,[dotnet,*sys.argv[1:]],env)\n')
record={'status':'incomplete','commands':[],'nativePins':pins,'traceLibSha256':sha(traceLib),'sourceSha256':sha(__file__),'profile':True,'purpose':'Filtered identified connection worker CPU; no primary timing claim','filterRegistrarSha256':sha(filterRegistrar),'profilerSha256':sha(profilerLibrary),'hostLoadBefore':os.getloadavg(),'startedUnix':time.time()}
cliBase=[config['root']+'/usr/bin/lttng','--group='+grp.getgrgid(os.getgid()).gr_name]
save=lambda:(out/'trace-manifest.json').write_text(json.dumps(record,indent=2)+'\n')
def cli(*args):
 r={'command':cliBase+list(args),'beforeUnixNs':time.time_ns(),'beforeMonotonic':time.monotonic()};p=subprocess.run(r['command'],env=env,capture_output=True,text=True,timeout=10);r.update(exit=p.returncode,stdout=p.stdout,stderr=p.stderr,afterUnixNs=time.time_ns(),afterMonotonic=time.monotonic());record['commands'].append(r);save()
 if p.returncode:raise RuntimeError(r)
 return r
spec=importlib.util.spec_from_file_location('profile',ROOT/'profile_spike.py');profile=importlib.util.module_from_spec(spec);spec.loader.exec_module(profile)
daemon=None;controller=None;session=None
try:
 with (out/'sessiond.log').open('w') as log:daemon=subprocess.Popen(config['command'],env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
 deadline=time.monotonic()+5
 while not (Path(env['LTTNG_HOME'])/'.lttng/client-lttng-sessiond').exists():
  if daemon.poll() is not None or time.monotonic()>deadline:raise RuntimeError('Private sessiond readiness failed')
  time.sleep(.02)
 session='qss-e08';cli('create',session,'--output='+str(out/'trace'))
 for channel,n in [('identity',4),('mapping',4),('flow',8)]:
  cli('enable-channel','--userspace','--buffers-pid','--discard','--subbuf-size=256K','--num-subbuf='+str(n),channel);cli('add-context','--userspace','--channel='+channel,'--type=vpid','--type=vtid')
 identity=['CLOG_STREAM_C:StreamCreated','CLOG_STREAM_C:StreamDestroyed','CLOG_WORKER_C:ConnAssignWorker','CLOG_WORKER_C:WorkerCreated','CLOG_LIBRARY_C:LibraryVersion','CLOG_STREAM_RECV_C:IncreaseRxBuffer','CLOG_LOSS_DETECTION_C:ConnPacketLost']
 mapping=['CLOG_STREAM_SEND_C:SendQueued']
 flow=['CLOG_STREAM_SEND_C:SendQueued','CLOG_STREAM_SEND_C:IndicateSendComplete','CLOG_STREAM_H:StreamOutFlowBlocked','CLOG_STREAM_C:StreamOutFlowBlocked','CLOG_CONNECTION_H:ConnOutFlowBlocked','CLOG_WORKER_C:ConnScheduleState','CLOG_DATAPATH_EPOLL_C:DatapathSend','CLOG_DATAPATH_EPOLL_C:DatapathRecv','CLOG_STREAM_RECV_C:StreamRecvState','CLOG_STREAM_RECV_C:FlowControlExhausted','CLOG_STREAM_RECV_C:ReceiveBeyondFlowControl','CLOG_STREAM_RECV_C:StreamAppReceive','CLOG_STREAM_RECV_C:StreamAppReceiveComplete']
 for channel,events in [('identity',identity),('mapping',mapping),('flow',flow)]:cli('enable-event','--userspace','--channel='+channel,','.join(events))
 cli('enable-event','--userspace','--channel=flow','CLOG_API_C:ApiEnter','--filter=arg2 == 22')
 cli('disable-channel','--userspace','mapping');cli('disable-channel','--userspace','flow');cli('start',session)
 runEnv=env.copy();runEnv['DOTNET_HOST_PATH']=str(launcher)
 argv=['python3','run_spike.py','run',str(out/'run'),'--build',str(args.build.resolve()),'--rounds','1','--payload','348','--batch','65536','--window','5120','--ack-boundary','1104','--native-pins',str(out/'native-pins.json')];record['controllerCommand']=argv
 with (out/'controller.log').open('w') as log:controller=subprocess.Popen(argv,cwd=ROOT,env=runEnv,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
 logPath=out/'run/00-quic/client.log';deadline=time.monotonic()+25
 while True:
  if controller.poll() is not None:raise RuntimeError('Controller stopped before warmup witness: '+(out/'controller.log').read_text())
  if logPath.exists() and any(l.startswith('PHASE ') for l in logPath.read_text().splitlines()):break
  if time.monotonic()>deadline:raise TimeoutError('warmup witness missing')
  time.sleep(.02)
 record['warmupWitnessMonotonic']=time.monotonic();pids={side:json.loads((out/side/'pid.json').read_text())['pid'] for side in ['client','server']};record['pids']=pids
 time.sleep(.1)
 record['mapping1Start']=cli('enable-channel','--userspace','mapping');time.sleep(.06);record['mapping1Stop']=cli('disable-channel','--userspace','mapping')
 record['quietChannelStatus']=cli('list',session)
 record['selectionStart']={side:profile.snapshot(pid) for side,pid in pids.items()};time.sleep(.2);record['selectionStop']={side:profile.snapshot(pid) for side,pid in pids.items()}
 record['selectedTids']={};record['workerProfiles']={}
 for side in ['server','client']:
  before=record['selectionStart'][side];after=record['selectionStop'][side];candidates=[]
  for tid,new in after['tasks'].items():
   old=before['tasks'].get(tid)
   if old and 'startTicks' in old and 'startTicks' in new and old['startTicks']==new['startTicks'] and new['name']=='dotnet':
    cpu=(new['userTicks']+new['systemTicks']-old['userTicks']-old['systemTicks'])/os.sysconf('SC_CLK_TCK');candidates.append((cpu,int(tid)))
  if not candidates:raise RuntimeError('No native thread candidates')
  cpu,tid=max(candidates)
  if cpu/(after['monotonicSeconds']-before['monotonicSeconds'])<.5:raise RuntimeError('No clearly hot native thread')
  record['selectedTids'][side]=tid;endpoint=out/side;profileFile=endpoint/'cpu.prof'
  info={'tid':tid,'profile':str(profileFile)};record['workerProfiles'][side]=info
  info['startAck']=profile.command(endpoint,f'START_TID {tid} {profileFile}','STARTED',profileFile,controller)
  info['startSnapshot']=profile.snapshot(pids[side])
 time.sleep(4)
 for side in ['client','server']:
  endpoint=out/side;info=record['workerProfiles'][side]
  info['endSnapshot']=profile.snapshot(pids[side]);info['stopAck']=profile.command(endpoint,'STOP','STOPPED',info['profile'],controller)
 record['cpuStart']={side:info['startSnapshot'] for side,info in record['workerProfiles'].items()};record['cpuStop']={side:info['endSnapshot'] for side,info in record['workerProfiles'].items()}
 for side in ['client','server']:
  endpoint=out/side;info=record['workerProfiles'][side];pid=pids[side]
  import shutil
  shutil.copyfile(f'/tmp/perf-{pid}.map',endpoint/'managed-perf.map')
  info['quitAck']=profile.command(endpoint,'QUIT','QUITTED','-',controller)
  if not any(l.startswith('SELECTED_TID '+str(info['tid'])+' ') for l in (endpoint/'control.ack').read_text().splitlines()):raise RuntimeError('Missing selected TID acknowledgement')
 record['mapping2Start']=cli('enable-channel','--userspace','mapping');time.sleep(.06);record['mapping2Stop']=cli('disable-channel','--userspace','mapping')
 if len([l for l in logPath.read_text().splitlines() if l.startswith('PHASE ')])!=1:raise RuntimeError('Worker profile exceeded approximate phase1 interior')
 record['availableEvents']=cli('list','--userspace')
 for side,pid in pids.items():
  maps=Path(f'/proc/{pid}/maps').read_text();(out/side/'maps.txt').write_text(maps)
  loaded={line.split()[-1] for line in maps.splitlines() if line.split()[-1].startswith('/')}
  for file,expected in [(filterRegistrar,record['filterRegistrarSha256']),(profilerLibrary,record['profilerSha256'])]:
   if not any(Path(path).resolve()==file.resolve() and sha(path)==expected for path in loaded):raise RuntimeError('Filtered instrumentation mapping differs')
  registered={int(line.split()[1]) for line in (out/side/'threads.log').read_text().splitlines()}
  for name in ['startSnapshot','endSnapshot']:
   snap=record['workerProfiles'][side][name];live={int(t) for t in snap['stableTaskIds'] if not snap['tasks'][t].get('exitedDuringSnapshot')}
   if live-registered or live-set(snap['timerTargets']) or snap['duplicateTimerTargets']:raise RuntimeError('Filtered thread/timer coverage failed')
 cli('stop',session);record['finalSession']=cli('list',session);cli('destroy',session);session=None
 controller.wait(timeout=30)
 if controller.returncode:raise RuntimeError('Controller failed')
 record.update(status='captured-awaiting-decode',controllerExit=controller.returncode,completedUnix=time.time(),hostLoadAfter=os.getloadavg())
 if sha(filterRegistrar)!=record['filterRegistrarSha256'] or sha(profilerLibrary)!=record['profilerSha256']:raise RuntimeError('Filtered profiling binaries changed')
except BaseException as e:record.update(status='failed',errorType=type(e).__name__,error=str(e));raise
finally:
 if controller and controller.poll() is None:
  child_file=Path(f'/proc/{controller.pid}/task/{controller.pid}/children')
  children=child_file.read_text().split() if child_file.exists() else []
  controller.send_signal(signal.SIGINT)
  try:controller.wait(timeout=5)
  except subprocess.TimeoutExpired:
   for child in children:
    try:os.killpg(int(child),signal.SIGKILL)
    except ProcessLookupError:pass
   controller.kill();controller.wait()
 if session is not None:
  try:cli('destroy',session)
  except Exception as e:record['sessionCleanupError']=str(e)
 if daemon and daemon.poll() is None:
  daemon.terminate();daemon.wait(timeout=10);record['sessiondExit']=daemon.returncode
 record['artifactSha256']={str(p.relative_to(out)):sha(p) for p in out.rglob('*') if p.is_file() and p.name!='trace-manifest.json'};save()
print(json.dumps({'output':str(out),'status':record['status']}))
