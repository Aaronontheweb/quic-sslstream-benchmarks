#!/usr/bin/env python3
"""Decode retained native events; requires matching Babeltrace2 plugins and Python binding."""
import bt2,collections,json,math,os,re,statistics
from pathlib import Path
import argparse
parser=argparse.ArgumentParser(description='Prove selected worker identity and timer coverage; output remains private.')
parser.add_argument('capture',type=Path);parser.add_argument('output',type=Path);args=parser.parse_args()
root=Path(__file__).resolve().parents[2];out=args.capture.resolve();m=json.loads((out/'trace-manifest.json').read_text());pids=set(m['pids'].values());counts=collections.Counter();allPids=set();assignments={};changes=[];streams={};growth=collections.defaultdict(list);loss=[];mapping=[collections.defaultdict(collections.Counter),collections.defaultdict(collections.Counter)];mappingWorkers=[collections.defaultdict(set),collections.defaultdict(set)];flow=[];eventCatalog=m['availableEvents']['stdout']
# Revalidate immutable artifacts and normal-controller source/security/results before decoding.
import hashlib,sys
sys.path.insert(0,str(root))
from summarize import audit
if not m['artifactSha256']:raise ValueError('Missing artifact hashes')
for name,digest in m['artifactSha256'].items():
 file=(out/name).resolve()
 if not file.is_relative_to(out) or hashlib.sha256(file.read_bytes()).hexdigest()!=digest:raise ValueError('Changed capture artifact: '+name)
audit(out/'run')
assert m['controllerExit']==m['sessiondExit']==0
assert re.findall(r'Discarded events: (\d+)',m['finalSession']['stdout'])==['0','0','0']
assert '- mapping: [disabled]' in m['quietChannelStatus']['stdout'] and '- flow: [disabled]' in m['quietChannelStatus']['stdout']
for msg in bt2.TraceCollectionMessageIterator(str(out/'trace')):
 if isinstance(msg,(bt2._DiscardedEventsMessageConst,bt2._DiscardedPacketsMessageConst)):raise RuntimeError('Discarded CTF data')
 if not isinstance(msg,bt2._EventMessageConst):continue
 e=msg.event;name=e.name;ts=msg.default_clock_snapshot.ns_from_origin;pid=int(e.common_context_field['vpid']);tid=int(e.common_context_field['vtid']);p=e.payload_field;allPids.add(pid);counts[name]+=1
 if name.endswith(':ConnAssignWorker'):
  key=(pid,int(p['arg2']));assignments[key]=int(p['arg3']);changes.append((ts,key,int(p['arg3'])))
 if name.endswith(':StreamCreated'):
  key=(pid,int(p['arg2']));assert key not in streams;streams[key]={'pid':pid,'stream':key[1],'connection':int(p['arg3']),'streamId':int(p['arg4']),'local':bool(int(p['arg5'])),'created':ts}
 if name.endswith(':IncreaseRxBuffer'):growth[pid].append({'timestampNs':ts,'stream':int(p['arg1']),'bytes':int(p['arg3'])})
 if name.endswith(':ConnPacketLost'):loss.append({'timestampNs':ts,'pid':pid,'connection':int(p['arg2']),'packet':int(p['arg3']),'type':int(p['arg4']),'reason':int(p['arg5'])})
 if name.endswith(':SendQueued'):
  key=(pid,int(p['arg1']));conn=(pid,streams[key]['connection']);assert conn in assignments
  for i in [0,1]:
   a=m[f'mapping{i+1}Start']['beforeUnixNs'];b=m[f'mapping{i+1}Stop']['afterUnixNs']
   if a<=ts<=b:mapping[i][pid][tid]+=int(p['arg4']);mappingWorkers[i][pid].add(assignments[conn])
  assert not m['mapping1Stop']['afterUnixNs']<=ts<=m['mapping2Start']['beforeUnixNs'],'HotmappingeventinsidequietCPUwindow'
assert allPids==pids,(allPids,pids)
workerResults={}
for side,pid in m['pids'].items():
 assert len(mapping[0][pid])==len(mapping[1][pid])==1 and set(mapping[0][pid])==set(mapping[1][pid]);assert len(mappingWorkers[0][pid])==1 and mappingWorkers[0][pid]==mappingWorkers[1][pid]
 tid=str(next(iter(mapping[0][pid])));a=m['cpuStart'][side];b=m['cpuStop'][side];old=a['tasks'][tid];new=b['tasks'][tid];assert old['startTicks']==new['startTicks'];wall=b['monotonicSeconds']-a['monotonicSeconds'];user=(new['userTicks']-old['userTicks'])/os.sysconf('SC_CLK_TCK');system=(new['systemTicks']-old['systemTicks'])/os.sysconf('SC_CLK_TCK')
 conn=next(v['connection'] for (p,s),v in streams.items() if p==pid)
 assert not any(m['mapping1Stop']['afterUnixNs']<ts<m['mapping2Start']['beforeUnixNs'] and key==(pid,conn) for ts,key,w in changes)
 workerResults[side]={'pid':pid,'tid':int(tid),'workerPointer':next(iter(mappingWorkers[0][pid])),'wallSeconds':wall,'userSeconds':user,'systemSeconds':system,'percentOfOneCore':100*(user+system)/wall,'schedstatRunningSeconds':(new['schedstat'][0]-old['schedstat'][0])/1e9,'runnableWaitSeconds':(new['schedstat'][1]-old['schedstat'][1])/1e9,'affinity':new['affinity'],'mappingBytesBefore':mapping[0][pid][int(tid)],'mappingBytesAfter':mapping[1][pid][int(tid)],'snapshotMaxSeconds':max(s['monotonicSeconds']-s['snapshotStartedMonotonic'] for s in [a,b])}

for side,row in workerResults.items():
 assert row['tid']==m['selectedTids'][side], 'Selected TID not actual connection worker'
 info=m['workerProfiles'][side]
 assert m['mapping1Stop']['afterMonotonic']<info['startSnapshot']['snapshotStartedMonotonic']<info['endSnapshot']['monotonicSeconds']<m['mapping2Start']['beforeMonotonic']
 for stage in ['startSnapshot','endSnapshot']:
  snap=info[stage];registered={int(l.split()[1]) for l in (out/side/'threads.log').read_text().splitlines()};live={int(t) for t in snap['stableTaskIds'] if not snap['tasks'][t].get('exitedDuringSnapshot')};assert not live-registered and not live-set(snap['timerTargets']) and not snap['duplicateTimerTargets']
 row['startAck']=info['startAck'];row['stopAck']=info['stopAck']
result={'status':'identity-and-timer-guards-passed-awaiting-symbols','workers':workerResults,'eventCounts':dict(counts),'identityProvenSameProcess':True,'artifactSha256':m['artifactSha256'],'sourceSha256':m['sourceSha256'],'registrarSha256':m['filterRegistrarSha256'],'profilerSha256':m['profilerSha256'],'hostLoadBefore':m['hostLoadBefore'],'hostLoadAfter':m['hostLoadAfter']}
args.output.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k!='artifactSha256'},indent=2))
