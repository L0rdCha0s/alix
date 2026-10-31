#!/usr/bin/env python3
"""Build the real large-image/high-VA fixture against the pending linker contract."""
from pathlib import Path
import argparse
import json
import subprocess

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
CACHE=ROOT/"ports/zen/upstream/layout-validation"

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--active",action="store_true",help="use the reviewed/applied active header and linker script")
    args=parser.parse_args()
    tree=ROOT if args.active else HERE/"pending"
    CACHE.mkdir(parents=True,exist_ok=True)
    payload=CACHE/"payload.bin"
    with payload.open("wb") as stream:
        for page in range(8192):stream.write(bytes([((page*73)^0xA5)&255])*4096)
    path=str(payload).replace("\\","\\\\").replace('"','\\"')
    assembly=CACHE/"payload.S"
    assembly.write_text('.section .rodata\n.balign 4096\n.globl alix_layout_payload\n.type alix_layout_payload,@object\n'
                        'alix_layout_payload:\n.incbin "'+path+'"\n.size alix_layout_payload, .-alix_layout_payload\n'
                        '.section .note.GNU-stack,"",@progbits\n')
    flags=["-std=c11","-O2","-g","-ffreestanding","-fno-builtin","-fno-stack-protector","-fno-pic","-m64",
           "-mno-red-zone","-mcmodel=large","-ftls-model=local-exec","-fshort-wchar","-Wall","-Wextra","-Werror",
           "-I"+str(tree/"include"),"-I"+str(ROOT/"include"),"-I"+str(ROOT/"user/lib")]
    objects=[]
    for source,name in ((HERE/"user_layout_test.c","test.o"),(assembly,"payload.o")):
        output=CACHE/name
        subprocess.run(["x86_64-elf-gcc"]+flags+["-c",str(source),"-o",str(output)],check=True)
        objects.append(str(output))
    runtime=json.loads((ROOT/"ports/zen/upstream/alix-toolchain/runtime-objects.json").read_text())
    binary=CACHE/"user_layout_test.elf"
    subprocess.run(["x86_64-elf-ld","-nostdlib","-T",str(tree/"user/lib/link.ld"),"-o",str(binary)]+runtime+objects,check=True)
    undefined=subprocess.check_output(["x86_64-elf-nm","--undefined-only",str(binary)],text=True)
    if undefined.strip():raise RuntimeError(undefined)
    data=binary.read_bytes()
    assert data[:6]==b"\x7fELF\x02\x01" and int.from_bytes(data[18:20],"little")==62 and len(data)>32<<20
    print("Native large-image fixture linked against "+("ACTIVE" if args.active else "PENDING")+" layout: "+str(binary))
    if not args.active:print("Not executable on the active old-layout kernel; review/apply/build/guest proof remains required")

if __name__=="__main__":main()
