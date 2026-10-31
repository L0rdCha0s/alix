#!/usr/bin/env python3
"""Verify review artifact provenance without changing active files."""
from pathlib import Path
import hashlib,json,subprocess
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
manifest=json.loads((HERE/'pending.json').read_text())
assert manifest['applied'] is False
for record in manifest['files']:
    active=ROOT/record['path'];pending=HERE/'pending'/record['path']
    actual=hashlib.sha256(active.read_bytes()).hexdigest() if active.exists() else None
    assert actual==record['base_sha256'], 'Active source changed: '+record['path']
    assert hashlib.sha256(pending.read_bytes()).hexdigest()==record['pending_sha256'], 'Pending source changed: '+record['path']
subprocess.run(['git','apply','--check',str(HERE/'signals.pending.patch')],cwd=ROOT.parent,check=True)
print(f"Pending signal provenance and patch applicability: PASS {len(manifest['files'])} files; no active changes")
