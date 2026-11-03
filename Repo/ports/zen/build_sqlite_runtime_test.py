#!/usr/bin/env python3
"""Build the actual configured Gecko SQLite DSO and its native API consumer."""
from pathlib import Path
import subprocess
import hashlib
import json

ROOT=Path(__file__).resolve().parents[2]
OBJ=ROOT/'ports/zen/upstream/obj-gecko-alix/config/external/sqlite'
ENGINE=ROOT/'ports/zen/upstream/firefox-159.0'
subprocess.run(['make','-C',str(OBJ),'-j2','compile'],check=True)
library=ROOT/'ports/zen/upstream/obj-gecko-alix/dist/bin/libmozsqlite3.so'
objects=[ROOT/'ports/zen/upstream/obj-gecko-alix/third_party/sqlite3'/directory/name for directory,name in
    (('src','sqlite3.o'),('ext','fts5.o'),('ext','sqlite-vec.o'))]
elf=ROOT/'build/user/sqlite_runtime_test.elf'
subprocess.run([str(ROOT/'ports/zen/toolchain/alix-clang'),'-std=c11','-O2','-g',
    '-I'+str(ENGINE/'third_party/sqlite3/src'),str(ROOT/'tests/sqlite_runtime_test.c'),'-o',str(elf)],check=True)
digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
(ROOT/'build/ports/zen/sqlite-native-link.json').write_text(json.dumps({
    'scope':'Actual configured libmozsqlite3.so, including FTS5/vector objects; guest execution separate',
    'library':str(library),'library_sha256':digest(library),'objects':{str(p):digest(p)for p in objects},
    'elf':str(elf),'elf_sha256':digest(elf),
},indent=2)+'\n')
print('Actual configured SQLite native acceptance ELF:',elf)
