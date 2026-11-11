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
args=parser.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
runtime=str(args.runtime_root.resolve());native=str(args.native_directory.resolve())
lttng=args.lttng_root.resolve();libs=str(lttng/'usr/lib/x86_64-linux-gnu')
config={'root':str(lttng),'env':{'LD_LIBRARY_PATH':libs+':/usr/lib/x86_64-linux-gnu','LTTNG_NETWORK_SOCKET_TIMEOUT':'3000','LTTNG_SESSION_CONFIG_XSD_PATH':str(lttng/'usr/share/xml/lttng')},'command':[str(lttng/'usr/bin/lttng-sessiond'),'--no-kernel','--consumerd64-path='+str(lttng/'usr/lib/x86_64-linux-gnu/lttng/libexec/lttng-consumerd'),'--consumerd64-libdir='+libs,'--group='+grp.getgrgid(os.getgid()).gr_name]}

env={k:v for k,v in os.environ.items() if not k.startswith(('CPUPROFILE','PROFILER_')) and k not in ['LD_PRELOAD','DOTNET_PerfMapEnabled','DOTNET_EnableEventPipe']};env.update(config['env']);env.update(LTTNG_HOME=tempfile.mkdtemp(prefix='qss-lttng-'),DOTNET_ROOT=runtime,LD_LIBRARY_PATH=native.split(':')[0]+':'+config['env']['LD_LIBRARY_PATH'])
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
traceLib=args.trace_library.resolve();pins=json.loads((ROOT/'.local/native-pins.json').read_text());pins[traceLib.name]=sha(traceLib);(out/'native-pins.json').write_text(json.dumps(pins,indent=2)+'\n')
for role in ['client','server']:(out/role).mkdir()
launcher=out/'launcher.py'; launcher.write_text('#!/usr/bin/env python3\nimport json,os,sys\nfrom pathlib import Path\n'+f'out=Path({str(out)!r});dotnet={str(Path(runtime)/"dotnet")!r}\n'+'if len(sys.argv)>2 and sys.argv[2] in ["client","server"]:\n opts=dict(zip(sys.argv[3::2],sys.argv[4::2]))\n if opts.get("--transport")=="quic":(out/sys.argv[2]/"pid.json").write_text(json.dumps({"pid":os.getpid()}))\n'+'os.execve(dotnet,[dotnet,*sys.argv[1:]],os.environ)\n');launcher.chmod(0o700)
record={'status':'incomplete','commands':[],'nativePins':pins,'traceLibSha256':sha(traceLib),'sourceSha256':sha(__file__),'profile':False,'purpose':'Native identity/flow diagnostic; no primary timing claim','startedUnix':time.time()}
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
 session='qss-e07';cli('create',session,'--output='+str(out/'trace'))
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
 time.sleep(.25)
 record['mapping1Start']=cli('enable-channel','--userspace','mapping');time.sleep(.06);record['mapping1Stop']=cli('disable-channel','--userspace','mapping')
 record['quietChannelStatus']=cli('list',session);time.sleep(.05);record['cpuStart']={s:profile.snapshot(pid) for s,pid in pids.items()};time.sleep(2);record['cpuStop']={s:profile.snapshot(pid) for s,pid in pids.items()}
 record['mapping2Start']=cli('enable-channel','--userspace','mapping');time.sleep(.06);record['mapping2Stop']=cli('disable-channel','--userspace','mapping')
 record['flowStart']=cli('enable-channel','--userspace','flow');time.sleep(.15);record['flowStop']=cli('disable-channel','--userspace','flow')
 if len([l for l in logPath.read_text().splitlines() if l.startswith('PHASE ')])!=1:raise RuntimeError('Native trace exceeded approximate phase1 window')
 record['availableEvents']=cli('list','--userspace')
 for side,pid in pids.items():(out/side/'maps.txt').write_text(Path(f'/proc/{pid}/maps').read_text())
 cli('stop',session);record['finalSession']=cli('list',session);cli('destroy',session);session=None
 controller.wait(timeout=30)
 if controller.returncode:raise RuntimeError('Controller failed')
 record.update(status='captured-awaiting-decode',controllerExit=controller.returncode,completedUnix=time.time())
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
