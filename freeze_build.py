#!/usr/bin/env python3
import hashlib,json,shutil,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
name=sys.argv[1]
if Path(name).name!=name:raise ValueError('Simple build name required')
target=ROOT/'builds'/name
if target.exists():raise ValueError('Build already frozen')
if subprocess.check_output(['git','status','--porcelain'],cwd=ROOT).strip():raise ValueError('Commit source before freezing')
source=ROOT/'bin/Release/net10.0'
shutil.copytree(source,target)
record={'name':name,'revision':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'source_sha256':{p.name:sha(p) for p in ROOT.iterdir() if p.suffix in ('.cs','.csproj','.py','.md','.json')},
        'files':{p.name:sha(p) for p in target.iterdir() if p.is_file()}}
(target/'build.json').write_text(json.dumps(record,indent=2)+'\n')
print('Frozen',name,record['revision'])
