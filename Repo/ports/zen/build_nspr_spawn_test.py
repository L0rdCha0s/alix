#!/usr/bin/env python3
"""Build the actual native NSPR spawn helper with configured upstream headers."""
import json
from pathlib import Path
import shlex
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests'))
from audio_stream_contract_test import function_definition
from audio_hda_state_test import typedef

def main():
    source=(ROOT/'ports/zen/upstream/firefox-159.0/nsprpub/pr/src/md/unix/uxproces.c').read_text()
    out=ROOT/'build/ports/zen/nspr-spawn';out.mkdir(parents=True,exist_ok=True)
    probe=out/'native.c'
    probe.write_text('''#include "primpl.h"
#include <spawn.h>
#include <alix_process.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
'''+typedef(source,'AlixSpawnState')+'\n'+function_definition(source,'static int\n_MD_alix_spawn(')+'\n'+(ROOT/'tests/nspr_spawn_test.c').read_text())
    entries=json.loads((ROOT/'ports/zen/upstream/obj-gecko-alix/clangd/compile_commands.json').read_text())
    entry=next(e for e in entries if e['file'].endswith('/nsprpub/pr/src/md/unix/uxproces.c'))
    argv=list(entry.get('arguments') or shlex.split(entry['command']));argv[argv.index('-o')+1]=str(out/'native.o');argv[argv.index(entry['file'])]=str(probe)
    subprocess.run(argv,cwd=entry['directory'],check=True)
    elf=ROOT/'build/user/nspr_spawn_test.elf'
    subprocess.run([str(ROOT/'ports/zen/toolchain/alix-clang'),str(out/'native.o'),'-Wl,--gc-sections','-o',str(elf)],cwd=ROOT,check=True)
    if subprocess.check_output(['x86_64-elf-nm','-u',str(elf)],text=True).strip():raise RuntimeError('unresolved NSPR spawn fixture symbols')
    print('Actual native NSPR spawn helper linked:',elf)
    print('Scope: actual helper/headers and native OS launch/wait; full NSPR initialization/daemon remains unverified.')

if __name__=='__main__':main()
