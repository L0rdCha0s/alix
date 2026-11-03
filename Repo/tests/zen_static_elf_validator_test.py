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
    binary=ROOT/"build/user/atk_demo.elf"
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
    exported=ROOT/"build/user/dynamic_loader_test.elf"
    shared=sorted((ROOT/"build/ports/zen/dynamic-loader").glob("*.so"))
    if exported.is_file():
        validate(exported)
        for path in shared:validate(path)
        data=exported.read_bytes();h=struct.unpack_from("<16sHHIQQQIHHHHHH",data)
        sections=[struct.unpack_from("<IIQQQQIIQQ",data,h[6]+i*64)for i in range(h[12])]
        relocation=next(s for s in sections if s[1]==4 and s[2]&2 and s[5])
        bad=[]
        for label,position,fmt,value in (
            ("startup code relocation",relocation[4]+8,"<I",1),
            ("startup write to code",relocation[4],"<Q",h[4]),
            ("startup symbol overflow",relocation[4]+12,"<I",0xffffffff),
            ("startup TLS addend overflow",relocation[4]+16,"<q",-(1<<63))):
            mutation=bytearray(data);struct.pack_into(fmt,mutation,position,value);bad.append((label,mutation))
        with tempfile.TemporaryDirectory(prefix="alix-exported-elf-") as directory:
            candidate=Path(directory)/"candidate"
            for label,mutation in bad:
                candidate.write_bytes(mutation)
                try:validate(candidate)
                except RuntimeError:pass
                else:raise RuntimeError("accepted "+label)
        print(f"Native ELF validator PASS: exported ET_EXEC, {len(shared)} real DSOs and {len(bad)} rejected TLS/startup corruptions")
    print(f"Native ELF validator PASS: real static ELF, {len(cases)} rejected corrupt/dynamic forms, debug metadata")
    glyphs = ROOT / "build/user/rust_glyph_rasterizer_test.elf"
    if glyphs.is_file():
        validate(glyphs)
        data = glyphs.read_bytes()
        h = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
        sections = [struct.unpack_from("<IIQQQQIIQQ", data, h[6] + i * 64) for i in range(h[12])]
        table = next(s for s in sections if s[1] == 4 and s[2] & 2 and s[5])
        symbols = sections[table[6]]
        position = next(position for position in range(table[4], table[4] + table[5], 24)
                        if struct.unpack_from("<Q", data, position + 8)[0] & 0xffffffff == 6)
        index = struct.unpack_from("<Q", data, position + 8)[0] >> 32
        symbol = symbols[4] + index * 24
        corruptions = (
            ("GOT nonzero addend", position + 16, "<q", 1),
            ("GOT indirect function", symbol + 4, "B", 0x1a),
            ("GOT undefined strong symbol", symbol + 6, "<H", 0),
            ("GOT symbol outside image", symbol + 8, "<Q", (1 << 64) - 1),
        )
        with tempfile.TemporaryDirectory(prefix="alix-main-got-") as directory:
            candidate = Path(directory) / "candidate"
            for label, position, fmt, value in corruptions:
                mutation = bytearray(data)
                struct.pack_into(fmt, mutation, position, value)
                candidate.write_bytes(mutation)
                try:
                    validate(candidate)
                except RuntimeError:
                    pass
                else:
                    raise RuntimeError("accepted " + label)
        print(f"Native ELF validator PASS: real FreeType executable GOT, {len(corruptions)} rejected corruptions")
    return 0

if __name__=="__main__":raise SystemExit(main())
