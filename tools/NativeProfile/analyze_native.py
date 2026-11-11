#!/usr/bin/env python3
"""Decode retained native events; requires matching Babeltrace2 plugins and Python binding."""
import bt2,collections,json,math,os,re,statistics
from pathlib import Path
import argparse
parser=argparse.ArgumentParser(description='Decode a native diagnostic capture; output remains private until sanitized.')
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
 if m['flowStart']['beforeUnixNs']<=ts<=m['flowStop']['afterUnixNs']:
  flow.append((ts,pid,tid,name,{str(k):int(v) for k,v in p.items() if isinstance(v,(bt2._SignedIntegerFieldConst,bt2._UnsignedIntegerFieldConst))}))
assert allPids==pids,(allPids,pids)
workerResults={}
for side,pid in m['pids'].items():
 assert len(mapping[0][pid])==len(mapping[1][pid])==1 and set(mapping[0][pid])==set(mapping[1][pid]);assert len(mappingWorkers[0][pid])==1 and mappingWorkers[0][pid]==mappingWorkers[1][pid]
 tid=str(next(iter(mapping[0][pid])));a=m['cpuStart'][side];b=m['cpuStop'][side];old=a['tasks'][tid];new=b['tasks'][tid];assert old['startTicks']==new['startTicks'];wall=b['monotonicSeconds']-a['monotonicSeconds'];user=(new['userTicks']-old['userTicks'])/os.sysconf('SC_CLK_TCK');system=(new['systemTicks']-old['systemTicks'])/os.sysconf('SC_CLK_TCK')
 conn=next(v['connection'] for (p,s),v in streams.items() if p==pid)
 assert not any(m['mapping1Stop']['afterUnixNs']<ts<m['mapping2Start']['beforeUnixNs'] and key==(pid,conn) for ts,key,w in changes)
 workerResults[side]={'pid':pid,'tid':int(tid),'workerPointer':next(iter(mappingWorkers[0][pid])),'wallSeconds':wall,'userSeconds':user,'systemSeconds':system,'percentOfOneCore':100*(user+system)/wall,'schedstatRunningSeconds':(new['schedstat'][0]-old['schedstat'][0])/1e9,'runnableWaitSeconds':(new['schedstat'][1]-old['schedstat'][1])/1e9,'affinity':new['affinity'],'mappingBytesBefore':mapping[0][pid][int(tid)],'mappingBytesAfter':mapping[1][pid][int(tid)],'snapshotMaxSeconds':max(s['monotonicSeconds']-s['snapshotStartedMonotonic'] for s in [a,b])}
flowCounts=collections.Counter(row[3] for row in flow);start=min(ts for ts,pid,tid,name,p in flow);end=max(ts for ts,pid,tid,name,p in flow);duration=end-start
flags={1:'scheduling',2:'pacing',4:'amplification',8:'congestion',16:'connectionCredit',32:'streamIdCredit',64:'streamCredit',128:'application'}
flowResults={}
def summarize(values):
 if not values:return {'count':0}
 values=sorted(values);return {'count':len(values),'meanUs':sum(values)/len(values)/1000,'p50Us':values[math.ceil(len(values)*.5)-1]/1000,'p99Us':values[math.ceil(len(values)*.99)-1]/1000,'maximumUs':max(values)/1000}
for side,pid in m['pids'].items():
 states={};totals=collections.defaultdict(collections.Counter);first={};lastapi={};requests={};lastcomplete={};timings=collections.defaultdict(list);quality=collections.Counter();send=collections.Counter();recv=collections.Counter();writeSizes=collections.Counter();offered=[];accepted=[];recvStates=collections.Counter()
 for ts,p,tid,name,f in flow:
  if p!=pid:continue
  if name.endswith(':ApiEnter'):
   assert f['arg2']==22;key=f['arg3']
   if key in lastapi:quality['overwrittenApi']+=1
   lastapi[key]=(ts,tid)
   if key in lastcomplete:timings['completeToNextApi'].append(ts-lastcomplete.pop(key))
  elif name.endswith(':SendQueued'):
   key=f['arg1'];writeSizes[f['arg4']]+=1
   if key in lastapi:timings['apiToNativeQueue'].append(ts-lastapi.pop(key)[0])
   else:quality['queuedWithoutApiLeftEdge']+=1
   req=(key,f['arg3']);assert req not in requests;requests[req]=ts
  elif name.endswith(':IndicateSendComplete'):
   key=f['arg1'];req=(key,f['arg3']);lastcomplete[key]=ts
   if req in requests:timings['nativeQueueToComplete'].append(ts-requests.pop(req))
   else:quality['completeWithoutQueueLeftEdge']+=1
  elif name.endswith(':DatapathSend'):send[(f['arg3'],f['arg4'],f['arg5'])]+=1
  elif name.endswith(':DatapathRecv'):recv[(f['arg3'],f['arg4'])]+=1
  elif name.endswith(':StreamAppReceive'):offered.append(f['arg3'])
  elif name.endswith(':StreamAppReceiveComplete'):accepted.append(f['arg3'])
  key=None;state=None
  if name.endswith(':StreamOutFlowBlocked'):key=('stream',f['arg2']);state=f['arg3']
  elif name.endswith(':ConnOutFlowBlocked'):key=('connection',f['arg2']);state=f['arg3']
  elif name.endswith(':ConnScheduleState'):key=('schedule',f['arg2']);state=f['arg3']
  elif name.endswith(':StreamRecvState'):key=('receive',f['arg2']);state=f['arg3'];recvStates[state]+=1
  if key is not None:
   first.setdefault(key,ts)
   if key in states:
    old,prev=states[key];totals[key][old]+=ts-prev
   states[key]=(state,ts)
 for key,(state,ts) in states.items():totals[key][state]+=end-ts
 residence=[]
 for key,total in totals.items():
  assert sum(total.values())+first[key]-start==duration
  row={'kind':key[0],'pointer':key[1],'windowNs':duration,'unknownInitialPercent':100*(first[key]-start)/duration,'statePercent':{str(k):100*v/duration for k,v in total.items()}}
  if key[0] in ['stream','connection']:row['flagPercent']={name:100*sum(n for mask,n in total.items() if mask&bit)/duration for bit,name in flags.items()}
  residence.append(row)
 flowResults[side]={'writeSizes':dict(writeSizes),'timings':{k:summarize(v) for k,v in timings.items()},'edgeQuality':dict(quality),'unmatchedRequestsRightEdge':len(requests),'receiveStateEventCounts':dict(recvStates),'residence':residence,'datapathSendShapes':[{'bytes':b,'buffers':n,'segmentBytes':s,'events':count} for (b,n,s),count in send.most_common(8)],'sendEvents':sum(send.values()),'sendBytes':sum(b*n for (b,buf,seg),n in send.items()),'receiveEvents':sum(recv.values()),'receiveShapes':[{'bytes':b,'segmentBytes':s,'events':count} for (b,s),count in recv.most_common(8)],'offeredBytesTotal':sum(offered),'acceptedBytesTotal':sum(accepted),'offeredSizes':collections.Counter(offered).most_common(6),'acceptedSizes':collections.Counter(accepted).most_common(6)}
result={'eventCounts':dict(counts),'flowEventCounts':dict(flowCounts),'flowObservedSeconds':duration/1e9,'workers':workerResults,'growth':dict(growth),'lossCountsByPidAndReason':{str((p,r)):sum(1 for l in loss if l['pid']==p and l['reason']==r) for p in pids for r in {l['reason'] for l in loss}},'lossEvents':loss,'flowResults':flowResults,'traceArtifactSha256':m['artifactSha256'],'decoderPluginPathRequired':True}
args.output.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ['traceArtifactSha256','lossEvents','growth']},indent=2));print('growthBytes',{p:[x['bytes'] for x in rows] for p,rows in growth.items()})
