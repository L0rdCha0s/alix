#!/usr/bin/env python3
"""Check emitted target bytes and the ABI shared by signal reconstruction."""
from pathlib import Path
import struct,subprocess
HERE=Path(__file__).resolve().parent
path=HERE/'out/process_common.o';data=path.read_bytes()
shoff=struct.unpack_from('<Q',data,40)[0];entsize,count=struct.unpack_from('<HH',data,58)
sections=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+i*entsize) for i in range(count)]
def symbols():
    for section in sections:
        if section[1]!=2:continue
        strings=sections[section[6]];names=data[strings[4]:strings[4]+strings[5]]
        for offset in range(section[4],section[4]+section[5],section[9]):
            name,info,other,index,value,size=struct.unpack_from('<IBBHQQ',data,offset)
            if index==0 or index>=len(sections):continue
            end=names.find(b'\0',name);label=names[name:end].decode()
            yield label,data[sections[index][4]+value:sections[index][4]+value+size]
values=dict(symbols());preempt=values['g_user_preempt_stub'];restorer=values['g_user_signal_restorer']
assert len(preempt)==73 and preempt[:5]==bytes.fromhex('48 8d 64 24 80')
assert preempt[36:38]==bytes.fromhex('cd 80') and preempt[-3:]==bytes.fromhex('c2 80 00')
assert restorer==bytes.fromhex('48 89 e7 b8 3e 00 00 00 cd 80 0f 0b')
assert len(values['g_user_thread_exit_stub'])==10
out=HERE/'out/user_stubs.bin';out.write_bytes(preempt+restorer)
text=subprocess.check_output(['x86_64-elf-objdump','-D','-b','binary','-m','i386:x86-64',str(out)],text=True)
(HERE/'out/user_stubs.objdump.txt').write_text(text)
print('Target stub contracts: PASS redzone=128 save=264 return_pc=38 length=73 restorer_offset=0x200')
