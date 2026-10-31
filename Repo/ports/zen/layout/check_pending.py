#!/usr/bin/env python3
"""Validate the staged C/linker/VM contract without applying or booting it."""
from pathlib import Path
import hashlib
import json
import os
import runpy
import shlex
import struct
import subprocess
import sys
import tempfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
PENDING=HERE/"pending"
sys.dont_write_bytecode=True

FIELDS={
    "pointer_base":"USER_DEFAULT_POINTER_BASE",
    "pointer_limit":"USER_DEFAULT_POINTER_LIMIT",
    "stack_top":"USER_DEFAULT_POINTER_BASE+USER_DEFAULT_STACK_TOP_OFFSET",
    "stack_size":"USER_DEFAULT_STACK_SIZE",
    "stack_guard_size":"USER_DEFAULT_STACK_GUARD_SIZE",
    "image_end":"USER_DEFAULT_IMAGE_END",
    "heap_base":"USER_DEFAULT_POINTER_BASE+USER_DEFAULT_HEAP_BASE_OFFSET",
    "heap_size":"USER_DEFAULT_HEAP_SIZE",
    "vm_heap_gap":"USER_DEFAULT_VM_HEAP_GAP",
    "thread_pool_size":"USER_DEFAULT_THREAD_POOL_SIZE",
    "stub_code_base":"USER_DEFAULT_POINTER_LIMIT+1-8192",
    "vm_start":"USER_DEFAULT_POINTER_BASE+USER_DEFAULT_HEAP_BASE_OFFSET+USER_DEFAULT_HEAP_SIZE+USER_DEFAULT_VM_HEAP_GAP",
    "vm_end":"USER_DEFAULT_POINTER_LIMIT+1-8192-USER_DEFAULT_THREAD_POOL_SIZE",
}

def run(command,**kwargs): return subprocess.run(list(map(str,command)),check=True,**kwargs)

def check_baseline():
    manifest=json.loads((HERE/"pending.json").read_text())
    for item in manifest["files"]:
        active=ROOT/item["path"]
        if item["base_sha256"] is None:
            if active.exists(): raise RuntimeError("new pending path already exists: "+item["path"])
        elif hashlib.sha256(active.read_bytes()).hexdigest()!=item["base_sha256"]:
            raise RuntimeError("active file changed since patch preparation: "+item["path"])
        if hashlib.sha256((PENDING/item["path"]).read_bytes()).hexdigest()!=item["pending_sha256"]:
            raise RuntimeError("pending file changed without regenerating review patch: "+item["path"])

def linker_contract(work):
    source=work/"values.c"
    source.write_text('#include "memory_layout.h"\nconst uint64_t contract[] __attribute__((used,section(".alix_contract")))={'+
                      ",".join(FIELDS.values())+'};\n')
    obj=work/"values.o"
    run(["x86_64-elf-gcc","-std=c11","-ffreestanding","-I"+str(PENDING/"include"),"-I"+str(ROOT/"include"),
         "-c",source,"-o",obj])
    values=work/"values.bin"
    run(["x86_64-elf-objcopy","--dump-section",".alix_contract="+str(values),obj])
    expected=dict(zip(FIELDS,struct.unpack("<"+"Q"*len(FIELDS),values.read_bytes())))
    for script,entry in (("user/lib/link.ld","_start"),("src/arch/x86/uefi.ld","kernel_entry")):
        assembly=work/(entry+".S")
        assembly.write_text(f'.text\n.globl {entry}\n{entry}: nop\n.data\n.quad 1\n.bss\n.skip 16\n')
        small=work/(entry+".o");binary=work/(entry+".elf")
        run(["x86_64-elf-gcc","-c",assembly,"-o",small])
        run(["x86_64-elf-ld","-nostdlib","-T",PENDING/script,small,"-o",binary])
        symbols={}
        output=subprocess.check_output(["x86_64-elf-nm","--defined-only",str(binary)],text=True)
        for line in output.splitlines():
            value,kind,name=line.split()
            if name.startswith("__alix_user_") and name.removeprefix("__alix_user_") in expected:
                assert kind=="A",(name,kind)
                symbols[name.removeprefix("__alix_user_")]=int(value,16)
        assert symbols==expected,(script,symbols,expected)
        oversize=work/(entry+"-oversize.S")
        size=(expected["image_end"]-expected["pointer_base"]+4096) if entry=="_start" else (expected["pointer_base"]-0x10000000+4096)
        oversize.write_text(f'.text\n.globl {entry}\n{entry}: nop\n.bss\n.skip {size}\n')
        badobj=work/(entry+"-oversize.o")
        run(["x86_64-elf-gcc","-c",oversize,"-o",badobj])
        result=subprocess.run(["x86_64-elf-ld","-nostdlib","-T",str(PENDING/script),str(badobj),"-o",str(work/(entry+"-bad.elf"))],capture_output=True,text=True)
        assert result.returncode and "overlaps" in result.stderr,result.stderr
    assert expected["pointer_limit"]+1==64<<40
    assert expected["heap_size"]//(2<<20)*8==65536
    assert expected["stack_size"]//4096*8==16384
    print("C, user linker and kernel linker absolute contracts/overlap ASSERTs: PASS")
    return expected

class OverlayRoot:
    def __truediv__(self,name):
        path=PENDING/name
        return path if path.exists() else ROOT/name

def host_contracts(work):
    sys.path.insert(0,str(ROOT/"tests"))
    import audio_stream_contract_test as helper
    helper.ROOT=OverlayRoot()
    original=os.environ.get("HOST_CC")
    os.environ["HOST_CC"]=(original or "cc")+" -fsanitize=address,undefined"
    try:
        for name in ("native_vm_contract_test.py","auxiliary_pool_test.py","vm_reclamation_test.py"):
            runpy.run_path(str(PENDING/"tests"/name),run_name="__main__")
    finally:
        if original is None:os.environ.pop("HOST_CC",None)
        else:os.environ["HOST_CC"]=original
    compiler=shlex.split(original or "cc")
    binary=work/"elf-validation"
    run(compiler+["-std=c17","-Wall","-Wextra","-Werror","-fsanitize=address,undefined","-DTTF_HOST_BUILD",
                  "-iquote",str(PENDING/"include"),"-iquote",str(ROOT/"include"),
                  str(PENDING/"tests/elf_validation_host_test.c"),str(PENDING/"src/kernel/elf.c"),"-o",str(binary)])
    run([binary])

def main():
    check_baseline()
    with tempfile.TemporaryDirectory(prefix="alix-layout-review-") as temporary:
        work=Path(temporary)
        linker_contract(work)
        host_contracts(work)
    print("Pending memory layout contracts passed; no active files changed and no guest run")

if __name__=="__main__":main()
