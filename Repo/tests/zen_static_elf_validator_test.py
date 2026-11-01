#!/usr/bin/env python3
"""Exercise the active upstream native-ELF validator against real/corrupt ELF."""
import ast
import os
from pathlib import Path
import struct
import tempfile

ROOT=Path(__file__).resolve().parents[1]


def main():
    source=(ROOT/"ports/zen/upstream/firefox-159.0/python/mozbuild/mozbuild/action/check_binary.py").read_text()
    tree=ast.parse(source)
    node=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=="check_alix_static_elf")
    namespace={"os":os,"struct":struct}
    exec(compile(ast.Module(body=[node],type_ignores=[]),"<active-native-ELF-validator>","exec"),namespace)
    validate=namespace["check_alix_static_elf"]
    binary=ROOT/"build/user/posix_spawn_test.elf"
    validate(binary)
    original=binary.read_bytes()
    header=struct.unpack_from("<16sHHIQQQIHHHHHH",original)
    phoff,shoff=header[5:7]
    cases=[]
    def field(name,offset,format,value):
        data=bytearray(original);struct.pack_into(format,data,offset,value);cases.append((name,data))
    field("dynamic ELF",16,"<H",3)
    field("wrong CPU",18,"<H",183)
    field("wrong endianness",5,"B",2)
    field("truncated program table",32,"<Q",len(original)-8)
    field("interpreter",phoff,"<I",3)
    field("dynamic loader",phoff,"<I",2)
    field("RWX text",phoff+4,"<I",7)
    field("oversized file backing",phoff+32,"<Q",len(original)+1)
    field("non-executable entry",24,"<Q",0)
    field("invalid alignment",phoff+48,"<Q",3)
    field("dynamic section",shoff+64+4,"<I",6)
    data=bytearray(original);struct.pack_into("<I",data,shoff+64+4,4);struct.pack_into("<Q",data,shoff+64+8,2)
    cases.append(("allocated relocations",data))
    cases.append(("short ELF",original[:32]))
    with tempfile.TemporaryDirectory(prefix="alix-static-elf-") as directory:
        candidate=Path(directory)/"candidate"
        for name,data in cases:
            candidate.write_bytes(data)
            try:validate(candidate)
            except RuntimeError:pass
            else:raise RuntimeError("accepted "+name)
        # Nonallocated debug relocation records are not runtime relocations.
        data=bytearray(original);struct.pack_into("<I",data,shoff+64+4,4);struct.pack_into("<Q",data,shoff+64+8,0)
        candidate.write_bytes(data);validate(candidate)
    print(f"Native ELF validator PASS: real static ELF, {len(cases)} rejected corrupt/dynamic forms, debug metadata")
    return 0

if __name__=="__main__":raise SystemExit(main())
