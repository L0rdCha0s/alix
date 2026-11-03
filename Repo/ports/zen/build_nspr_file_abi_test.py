#!/usr/bin/env python3
"""Compile native NSPR metadata/open code with its real configured headers."""
import json
from pathlib import Path
import shlex
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
from audio_stream_contract_test import function_definition

def main():
    source = (ROOT / "ports/zen/upstream/firefox-159.0/nsprpub/pr/src/md/unix/unix.c").read_text()
    seconds = source[source.index('#elif defined(_PR_STAT_HAS_ONLY_ST_ATIME)'):]
    functions = [function_definition(seconds, 'static void\n_MD_set_fileinfo_times('),
                 function_definition(seconds, 'static void\n_MD_set_fileinfo64_times('),
                 function_definition(source, 'static int\n_MD_alix_stat_times_valid('),
                 function_definition(source, 'static int\n_MD_convert_stat_to_fileinfo('),
                 function_definition(source, 'static int\n_MD_convert_stat64_to_fileinfo64(')]
    io_source = (ROOT / "ports/zen/upstream/firefox-159.0/nsprpub/pr/src/pthreads/ptio.c").read_text()
    start = io_source.index('#if defined(ALIX) || defined(SOLARIS) || defined(LINUX) || defined(__GNU__) ||')
    functions.append(io_source[start:io_source.index('/*\n * Put a Unix file descriptor', start)])
    functions.append(function_definition(io_source, 'static void\npt_MakeFdNonblock('))
    for name in ('void*\n_MD_MemMap(', 'PRStatus\n_MD_MemUnmap(', 'PRStatus\n_MD_SyncMemMap('):
        functions.append(function_definition(source, name))
    out = ROOT / "build/ports/zen/nspr-file-abi"
    out.mkdir(parents=True, exist_ok=True)
    probe = out / "native.c"
    probe.write_text('''#include "primpl.h"
#include "fcntl.h"
#include "stdio.h"
#include "serial.h"
#include "sys/mman.h"
#include "obsolete/probslet.h"
static PRErrorCode captured_error;
static PRInt32 captured_os_error;
/* Instrument the error sink; no NSPR runtime initialization is claimed. */
PR_IMPLEMENT(void) PR_SetError(PRErrorCode code, PRInt32 os_error) {
    captured_error=code;captured_os_error=os_error;
}
_Static_assert(__builtin_types_compatible_p(_MD_Open64,__typeof__(&open)), "native NSPR open ABI");
''' + '\n'.join(functions) + '\n' + (ROOT / "tests/nspr_file_abi_test.c").read_text())
    commands = json.loads((ROOT / "ports/zen/upstream/obj-gecko-alix/clangd/compile_commands.json").read_text())
    entry = next(e for e in commands if e['file'].endswith('/nsprpub/pr/src/md/unix/unix.c'))
    argv = entry.get('arguments') or shlex.split(entry['command'])
    argv[argv.index('-o') + 1] = str(out / "native.o")
    argv[argv.index(entry['file'])] = str(probe)
    subprocess.run(argv, cwd=entry['directory'], check=True)
    io_entry = next(e for e in commands if e['file'].endswith('/nsprpub/pr/src/pthreads/ptio.c'))
    io_argv = list(io_entry.get('arguments') or shlex.split(io_entry['command']))
    io_argv[io_argv.index('-o') + 1] = str(out / "ptio.o")
    subprocess.run(io_argv, cwd=io_entry['directory'], check=True)
    errors_entry = next(e for e in commands if e['file'].endswith('/nsprpub/pr/src/md/unix/unix_errors.c'))
    errors_argv = list(errors_entry.get('arguments') or shlex.split(errors_entry['command']))
    errors_argv[errors_argv.index('-o') + 1] = str(out / 'unix_errors.o')
    subprocess.run(errors_argv, cwd=errors_entry['directory'], check=True)
    # Keep this component archive out of the executable's dynamic exports so
    # section GC retains the tested APIs without rooting every NSPR subsystem.
    archive = out / 'libnspr-fixture.a'
    subprocess.run(['x86_64-elf-ar', 'rcs', str(archive), str(out / 'ptio.o'), str(out / 'unix_errors.o')], check=True)
    output = ROOT / "build/user/nspr_file_abi_test.elf"
    subprocess.run([str(ROOT / "ports/zen/toolchain/alix-clang"), str(out / "native.o"), str(archive),
                    '-Wl,--gc-sections', '-Wl,--exclude-libs,libnspr-fixture.a', '-o', str(output)], cwd=ROOT, check=True)
    print('Native NSPR metadata/open ABI consumer compiled:', output)
    print('Scope: actual extracted file/map helpers and configured headers; full NSPR linking/startup remains unverified.')

if __name__ == "__main__":
    main()
