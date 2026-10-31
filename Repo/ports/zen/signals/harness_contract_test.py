#!/usr/bin/env python3
"""Reject wrong-process, wrong-status and wrong-instruction guest evidence."""
from pathlib import Path
import ast,importlib.util,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('signal_evidence',HERE/'harness_support.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
binary=HERE/'out/signal_kernel_test.elf';site=module.native_elf_symbol(binary,'signal_badframe_probe')
expected=('SIGNAL_KERNEL_TEST: BADFRAME_ARMED','fault',4,132,6,'signal_badframe_probe')
armed=f'SIGNAL_KERNEL_TEST: BADFRAME_ARMED pid=42 tid=77 signo=4 status=132 vector=6 site=0x{site:016X}\n'
record=f'process: default signal pid=42 tid=77 signo=4 status=132 source=fault vector=6 rip=0x{site:016X}\n'
fault=f'process: user fault in thread /tmp/test.elf reason=invalid_opcode error=0x0 addr=0x0 rip=0x{site:016X} cs=0x2B cpu=7\n'
phase=armed+record+fault
module.verify_signal_termination(phase,binary,expected)
module.verify_expected_user_exception(phase,binary,('invalid_opcode','signal_badframe_probe'))
checks=2

def reject(function,*args):
    global checks
    try:function(*args)
    except RuntimeError:checks+=1;return
    raise AssertionError('accepted invalid guest evidence: '+str(args[0]))

for changed in [record.replace('pid=42','pid=43'),record.replace('tid=77','tid=78'),
                record.replace('signo=4','signo=11'),record.replace('status=132','status=139'),
                record.replace('source=fault','source=raise'),record.replace('vector=6','vector=14'),
                record.replace(f'{site:016X}',f'{site+1:016X}'),'']:
    reject(module.verify_signal_termination,armed+changed+fault,binary,expected)
reject(module.verify_signal_termination,armed+record+record+fault,binary,expected)
reject(module.verify_signal_termination,phase+'process: default signal malformed\n',binary,expected)
for changed in [armed.replace('pid=42','pid=0'),armed.replace('tid=77','tid=0'),
                armed.replace('signo=4','signo=15'),armed.replace('status=132','status=143'),
                armed.replace('vector=6','vector=0'),armed.replace(f'{site:016X}',f'{site+1:016X}'),'']:
    reject(module.verify_signal_termination,changed+record+fault,binary,expected)
for changed in [fault.replace('reason=invalid_opcode','reason=page_fault'),fault.replace('error=0x0','error=0x1'),
                fault.replace('addr=0x0','addr=0x1'),fault.replace('cs=0x2B','cs=0x8'),
                fault.replace(f'{site:016X}',f'{site+1:016X}'),'']:
    reject(module.verify_expected_user_exception,armed+record+changed,binary,('invalid_opcode','signal_badframe_probe'))
reject(module.verify_expected_user_exception,phase+fault,binary,('invalid_opcode','signal_badframe_probe'))

# A correct symbol/log at a modified non-UD2 instruction must also be rejected.
data=bytearray(binary.read_bytes());phoff=int.from_bytes(data[32:40],'little')
size=int.from_bytes(data[54:56],'little');count=int.from_bytes(data[56:58],'little')
for index in range(count):
    h=data[phoff+index*size:phoff+(index+1)*size]
    if int.from_bytes(h[:4],'little')!=1:continue
    offset=int.from_bytes(h[8:16],'little');virtual=int.from_bytes(h[16:24],'little');length=int.from_bytes(h[32:40],'little')
    if virtual<=site and site+2<=virtual+length:
        data[offset+site-virtual:offset+site-virtual+2]=b'\x90\x90';break
else:raise AssertionError('missing fixture load segment')
modified=HERE/'out/negative-opcode-fixture.elf';modified.write_bytes(data)
reject(module.verify_signal_termination,phase,modified,expected)

expected_default=('SIGNAL_KERNEL_TEST: DEFAULT_ARMED','raise',15,143,0,None)
default=('SIGNAL_KERNEL_TEST: DEFAULT_ARMED pid=42 tid=77 signo=15 status=143 vector=0 site=0x0\n'
         'process: default signal pid=42 tid=77 signo=15 status=143 source=raise vector=0 rip=0x0\n')
module.verify_signal_termination(default,binary,expected_default);checks+=1
reject(module.verify_signal_termination,default.replace('status=143 source','status=0 source'),binary,expected_default)
reject(module.verify_signal_termination,default.replace('source=raise','source=fault'),binary,expected_default)

staged=(HERE/'pending/tests/cpp_runtime_qemu_test.py').read_text();active=(ROOT/'tests/cpp_runtime_qemu_test.py').read_text()
ast.parse(staged)
# Ensure the rebase preserved the complete current boot failure/marker logic.
start=active.index('            def boot_failed(')
end=active.index('            offset = len(harness.read_log())',start)
assert active[start:end] in staged
assert 'boot_markers=()' in staged and 'expected_signal_termination=None' in staged
checks+=2
print(f'Signal guest evidence contracts: PASS checks={checks} PID/TID/status/vector/source/ELF-UD2 and current boot diagnostics')
