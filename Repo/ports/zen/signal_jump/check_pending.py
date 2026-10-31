#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,subprocess
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
manifest=json.loads((HERE/'pending.json').read_text());assert manifest['applied'] is False
for entry in manifest['files']:
 assert hashlib.sha256((ROOT/entry['path']).read_bytes()).hexdigest()==entry['before'],'active changed: '+entry['path']
 assert hashlib.sha256((HERE/'pending'/entry['path']).read_bytes()).hexdigest()==entry['after'],'staged changed: '+entry['path']
subprocess.run(['git','apply','--check',str(HERE/'signal-jump.pending.patch')],cwd=ROOT.parent,check=True)
print('Signal-jump provenance and patch applicability: PASS',len(manifest['files']),'files')
