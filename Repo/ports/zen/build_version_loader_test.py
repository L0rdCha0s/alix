#!/usr/bin/env python3
"""Build real default/nondefault symbol versions and a versioned consumer."""
from pathlib import Path
import subprocess,struct,hashlib,json
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'build/ports/zen/version-loader';OUT.mkdir(parents=True,exist_ok=True)
script=OUT/'provider.map';script.write_text('ALIX_1 { global: versioned_value; versioned_data; versioned_tls; local: *; };\nALIX_2 { global: versioned_value; versioned_data; versioned_tls; } ALIX_1;\n')
cc='x86_64-elf-gcc'
flags=['-std=c11','-O2','-g','-fPIC','-fno-stack-protector','-mno-red-zone','-ftls-model=global-dynamic']
provider=OUT/'libversion_provider.so';consumer=OUT/'libversion_consumer.so'
linker='x86_64-elf-ld';links=['-shared','-z','max-page-size=0x1000','-z','relro','-z','now','--hash-style=both']
for name in ('provider','consumer'):
    subprocess.run([cc,*flags,'-c',str(ROOT/f'tests/version_{name}.c'),'-o',str(OUT/(name+'.o'))],check=True)
subprocess.run([linker,*links,'-soname','libversion_provider.so','--version-script='+str(script),str(OUT/'provider.o'),'-o',str(provider)],check=True)
subprocess.run([linker,*links,'-soname','libversion_consumer.so','-rpath','$ORIGIN',str(OUT/'consumer.o'),'-L'+str(OUT),'-lversion_provider','-o',str(consumer)],check=True)
def elf_hash(name):
    value=0
    for byte in name:
        value=((value<<4)+byte)&0xffffffff;high=value&0xf0000000
        if high:value^=high>>24
        value&=~high
    return value
data=bytearray(consumer.read_bytes());header=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
ph=[struct.unpack_from('<IIQQQQQQ',data,header[5]+i*56)for i in range(header[10])]
def offset(address):
    for tag,flags,off,virtual,physical,filesz,memsz,align in ph:
        if tag==1 and virtual<=address<virtual+filesz:return off+address-virtual
    raise RuntimeError('Missing fixture load address')
dynamic=next(p for p in ph if p[0]==2);tags={}
for at in range(dynamic[2],dynamic[2]+dynamic[5],16):
    tag,value=struct.unpack_from('<qQ',data,at)
    if not tag:break
    tags[tag]=value
at=offset(tags[0x6ffffffe]);version,count,file,aux,next=struct.unpack_from('<HHIII',data,at);cursor=at+aux
changed=False
for i in range(count):
    hash,flags,index,name,next=struct.unpack_from('<IHHII',data,cursor);string=offset(tags[5]+name);end=data.index(0,string)
    if data[string:end]==b'ALIX_2':
        data[string:end]=b'ALIX_9';struct.pack_into('<I',data,cursor,elf_hash(b'ALIX_9'));changed=True
    cursor+=next
assert changed
(OUT/'libversion_bad.so').write_bytes(data)
elf=ROOT/'build/user/version_loader_test.elf'
subprocess.run([str(ROOT/'ports/zen/toolchain/alix-clang'),'-std=c11','-O2','-g',str(ROOT/'tests/version_loader_test.c'),'-o',str(elf)],check=True)
(OUT/'native-link.json').write_text(json.dumps({'scope':'Real ELF version definitions, nondefault aliases, requirements and TLS; guest execution separate','files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest()for p in (provider,consumer,OUT/'libversion_bad.so',elf)}},indent=2)+'\n')
print('Versioned ELF acceptance:',elf)
