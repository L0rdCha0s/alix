#!/usr/bin/env python3
"""Cross-link the integrity-pinned timezone staging utility using Alix libc."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt",type=Path)
    parser.add_argument("--runtime-manifest",type=Path,
                        default=ROOT/"ports/zen/upstream/alix-toolchain/runtime-objects.json")
    args=parser.parse_args()
    receipt=json.loads(args.receipt.read_text())
    output=args.receipt.resolve().parent/(receipt["id"]+"-installer")
    output.mkdir(exist_ok=True)
    config=Path(receipt["installer_config"])
    objects=shlex.split(os.environ.get("ALIX_RUNTIME_OBJECTS",""))
    if not objects:
        objects=json.loads(args.runtime_manifest.read_text())
    objects=[str((ROOT/path).resolve()) for path in objects]
    for obj in objects:
        data=Path(obj).read_bytes()
        if data[:6]!=b"\x7fELF\x02\x01" or int.from_bytes(data[18:20],"little")!=62:
            raise RuntimeError("non-native runtime object: "+obj)
    flags=["-std=c11","-O2","-g","-ffreestanding","-fno-builtin","-fno-stack-protector","-fno-pic",
           "-m64","-mno-red-zone","-mcmodel=large","-ftls-model=local-exec","-Wall","-Wextra","-Werror",
           "-I"+str(ROOT/"include"),"-I"+str(ROOT/"user/lib"),"-I"+str(output)]
    (output/"package_config.h").write_bytes(config.read_bytes())
    package=Path(receipt["package_directory"])
    manifest=json.loads((package/"manifest.json").read_text())
    moments=[datetime(2026,11,1,12,tzinfo=timezone.utc),datetime(2027,7,1,12,tzinfo=timezone.utc),
             datetime(2038,1,19,3,14,8,tzinfo=timezone.utc),datetime(2200,7,1,12,tzinfo=timezone.utc)]
    catalog=["/* Independent Python zoneinfo expectations from the exact packaged TZif files. */",
             "typedef struct { int offset, dst, known; const char *abbreviation; } timezone_reference_t;",
             "typedef struct { const char *name; timezone_reference_t values[4]; } timezone_reference_zone_t;",
             "#define TZ_CATALOG_TIMES 4u",f'#define TZ_CATALOG_COUNT {receipt["zones_and_aliases"]}u',
             f'#define TZ_CATALOG_ALIASES {receipt["aliases"]}u',
             "static const time_t timezone_reference_times[]={"+",".join(str(int(d.timestamp()))+"LL" for d in moments)+"};",
             "static const timezone_reference_zone_t zone_catalog[]={"]
    for entry in manifest["files"]:
        if not entry["path"].startswith("zoneinfo/"): continue
        name=entry["path"].removeprefix("zoneinfo/")
        with (package/entry["path"]).open("rb") as stream: zone=ZoneInfo.from_file(stream,key=name)
        values=[]
        for instant in moments:
            local=instant.astimezone(zone)
            values.append("{"+str(int(local.utcoffset().total_seconds()))+","+str(int(local.dst().total_seconds()!=0))+","+
                          str(int(local.tzname()!="-00"))+","+json.dumps(local.tzname())+"}")
        catalog.append("{"+json.dumps(name)+",{"+",".join(values)+"}},")
    catalog.append("};")
    (output/"zone_catalog.h").write_text("\n".join(catalog)+"\n")
    compiled=[]
    for source,name in ((HERE/"install.c","install.o"),(ROOT/"src/crypto/sha256.c","sha256.o")):
        target=output/name
        subprocess.run(["x86_64-elf-gcc"]+flags+["-c",str(source),"-o",str(target)],check=True)
        compiled.append(str(target))
    binary=output/"tzdata_install.elf"
    subprocess.run(["x86_64-elf-ld","-nostdlib","-T",str(ROOT/"user/lib/link.ld"),"-o",str(binary)]+objects+compiled,check=True)
    undefined=subprocess.check_output(["x86_64-elf-nm","--undefined-only",str(binary)],text=True)
    if undefined.strip(): raise RuntimeError("installer has unresolved symbols: "+undefined)
    subprocess.run(["x86_64-elf-readelf","-h",str(binary)],check=True)
    print("Native timezone staging installer linked: "+str(binary))
    verification=output/"verify.o"
    subprocess.run(["x86_64-elf-gcc"]+flags+["-c",str(HERE/"verify.c"),"-o",str(verification)],check=True)
    verifier=output/"tzdata_verify.elf"
    subprocess.run(["x86_64-elf-ld","-nostdlib","-T",str(ROOT/"user/lib/link.ld"),"-o",str(verifier)]+objects+[str(verification)],check=True)
    undefined=subprocess.check_output(["x86_64-elf-nm","--undefined-only",str(verifier)],text=True)
    if undefined.strip(): raise RuntimeError("verifier has unresolved symbols: "+undefined)
    print("Native all-zone verifier linked: "+str(verifier))
    qa_objects=[]
    for source,name,entry in ((HERE/"install.c","install-qa.o","alix_tzdata_install_main"),
                              (HERE/"verify.c","verify-qa.o","alix_tzdata_verify_main")):
        target=output/name
        subprocess.run(["x86_64-elf-gcc"]+flags+["-Dmain="+entry,"-c",str(source),"-o",str(target)],check=True)
        qa_objects.append(str(target))
    bundle_path=receipt["bundle"].replace("\\","\\\\").replace('"','\\"')
    assembly=output/"bundle.S"
    assembly.write_text('.section .rodata\n.globl alix_timezone_bundle\n.type alix_timezone_bundle,@object\n'
                        'alix_timezone_bundle:\n.incbin "'+bundle_path+'"\n'
                        '.size alix_timezone_bundle, .-alix_timezone_bundle\n.section .note.GNU-stack,"",@progbits\n')
    for source,name in ((assembly,"bundle.o"),(HERE/"package_test.c","package-test.o")):
        target=output/name
        subprocess.run(["x86_64-elf-gcc"]+flags+["-c",str(source),"-o",str(target)],check=True)
        qa_objects.append(str(target))
    acceptance=output/"tzdata_package_test.elf"
    subprocess.run(["x86_64-elf-ld","-nostdlib","-T",str(ROOT/"user/lib/link.ld"),"-o",str(acceptance)]+
                   objects+qa_objects+[str(output/"sha256.o")],check=True)
    undefined=subprocess.check_output(["x86_64-elf-nm","--undefined-only",str(acceptance)],text=True)
    if undefined.strip(): raise RuntimeError("package acceptance ELF has unresolved symbols: "+undefined)
    print("Native full-package acceptance ELF linked: "+str(acceptance))

if __name__=="__main__": main()
