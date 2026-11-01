#!/usr/bin/env python3
"""Strip debug-only payload while proving upstream executable image identity."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess

ROOT=Path(__file__).resolve().parents[2]


def digest(path,offset=0,length=None):
    result=hashlib.sha256()
    with path.open("rb") as stream:
        stream.seek(offset)
        remaining=length
        while remaining is None or remaining:
            data=stream.read(1024*1024 if remaining is None else min(1024*1024,remaining))
            if not data:break
            result.update(data)
            if remaining is not None:remaining-=len(data)
    if remaining:raise RuntimeError("truncated executable image")
    return result.hexdigest()


def image(path):
    with path.open("rb") as stream:
        header=stream.read(64)
        if header[:7]!=b"\x7fELF\x02\x01\x01":raise RuntimeError("not little-endian ELF64")
        elf=struct.unpack("<16sHHIQQQIHHHHHH",header)
        if elf[1]!=2 or elf[2]!=62 or elf[9]!=56:raise RuntimeError("not native static x86-64 ET_EXEC")
        segments=[]
        for index in range(elf[10]):
            stream.seek(elf[5]+index*56)
            kind,flags,offset,address,physical,filesz,memsz,alignment=struct.unpack("<IIQQQQQQ",stream.read(56))
            if kind in (2,3):raise RuntimeError("dynamic program/interpreter in native image")
            if kind in (1,7):
                segments.append([kind,flags,address,filesz,memsz,alignment,digest(path,offset,filesz)])
        return {"entry":elf[4],"segments":segments}


def main():
    source=ROOT/"ports/zen/upstream/obj-js-alix/dist/bin/js"
    target=ROOT/"build/user/spidermonkey_native.elf"
    target.parent.mkdir(parents=True,exist_ok=True)
    temporary=target.with_suffix(".tmp")
    subprocess.run(["x86_64-elf-strip","--strip-debug","-o",str(temporary),str(source)],check=True)
    original=image(source)
    if image(temporary)!=original:raise RuntimeError("debug stripping changed the upstream runtime image")
    undefined=subprocess.check_output(["x86_64-elf-nm","--undefined-only",str(temporary)],text=True)
    if undefined.strip():raise RuntimeError("unresolved symbols in native SpiderMonkey")
    temporary.replace(target)
    receipt={"source":str(source.relative_to(ROOT)),"source_sha256":digest(source),"target":str(target.relative_to(ROOT)),
             "target_sha256":digest(target),"source_bytes":source.stat().st_size,"target_bytes":target.stat().st_size,"image":original}
    output=ROOT/"build/ports/zen/spidermonkey-native-image.json"
    output.write_text(json.dumps(receipt,indent=2)+"\n")
    print(f"Prepared real SpiderMonkey native ELF: {target.stat().st_size} bytes; load/TLS images match upstream exactly")
    return 0

if __name__=="__main__":raise SystemExit(main())
