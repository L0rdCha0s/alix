set pagination off
hbreak *process_exit_signal if (int)$rdi == 4 || (int)$rdi == 6 || (int)$rdi == 7 || (int)$rdi == 8 || (int)$rdi == 11
python
import gdb, json, re
from pathlib import Path
Path(fault_output_dir, 'fault-watch.ready').write_text('hardware breakpoint armed\n')
end
continue
python
fatal_thread = None
frame = gdb.newest_frame()
if int(frame.pc()) == int(gdb.parse_and_eval('(void *)process_exit_signal')):
    match = re.search(r'CPU#(\d+)', gdb.selected_thread().name or '')
    fatal_cpu = int(match.group(1)) if match else gdb.selected_thread().num - 1
    fatal_thread = gdb.parse_and_eval('g_current_threads')[fatal_cpu]
    fatal_signal = int(frame.read_register('rdi')) & 0xffffffff
end
source STALL_SCRIPT_PATH
python
if fatal_thread is not None:
    t = fatal_thread
    process = t['process']; cr3 = int(process['cr3'])
    result = {'pid': int(t['owner_pid']), 'tid': int(t['tid']), 'name': text(t['name'], 64),
              'signal': fatal_signal, 'signal_depth': int(t['signal_depth']), 'signal_frames': []}
    try:
        modules = process_modules(process)
        result['modules'] = modules
        def location(pc):
            for module in modules:
                if any(low <= pc < high for low, high in module['executable_ranges']):
                    return {'module': module['path'], 'offset': hex(pc - int(module['bias'], 16)),
                            'build_id': module.get('build_id')}
            return None
        def probe(pc):
            return {'pc': hex(pc), 'location': location(pc), 'code_hex': virtual(cr3, pc, 32).hex()}
        reason_slot = int(gdb.parse_and_eval('(void *)&gMozCrashReason'))
        reason = int.from_bytes(virtual(cr3, reason_slot, 8), 'little')
        result['moz_crash_reason_address'] = hex(reason)
        if reason:
            result['moz_crash_reason'] = virtual(cr3, reason, min(512, 4096 - (reason & 4095))).split(b'\0', 1)[0].decode('utf-8', 'replace')
        def member(typename, name):
            return next(f for f in gdb.lookup_type(typename).strip_typedefs().fields() if f.name == name)
        context_offset = member('alix_signal_frame_t', 'context').bitpos // 8
        machine_offset = context_offset + member('alix_ucontext_t', 'uc_mcontext').bitpos // 8
        info_offset = member('alix_signal_frame_t', 'info').bitpos // 8
        record = t['signal_frames']
        for _ in range(4):
            if not int(record): break
            saved_record = record.cast(gdb.lookup_type('process_signal_frame_t').pointer()).dereference()
            frame_address = int(saved_record['address'])
            data = virtual(cr3, frame_address, int(gdb.lookup_type('alix_signal_frame_t').sizeof))
            if int.from_bytes(data[:8], 'little') != 0x414c495853494746:
                raise ValueError('invalid userspace signal-frame magic')
            def reg(name):
                f = member('alix_mcontext_t', name); offset = machine_offset + f.bitpos // 8
                return int.from_bytes(data[offset:offset+f.type.sizeof], 'little')
            sf = member('alix_siginfo_t', 'si_signo'); offset = info_offset + sf.bitpos // 8
            item = {'context_source': 'userspace_signal_frame', 'frame_address': hex(frame_address),
                    'signal': int.from_bytes(data[offset:offset+sf.type.sizeof], 'little'), 'trap': reg('trapno'),
                    'cr2': hex(reg('cr2')), 'rsp': hex(reg('rsp')),
                    'registers': {name: hex(reg(name)) for name in
                        ('rax','rbx','rcx','rdx','rsi','rdi','rbp','r8','r9','r10','r11','r12','r13','r14','r15')}}
            item.update(probe(reg('rip')))
            result['signal_frames'].append(item)
            record = record['previous']
        address = int(t['kernel_stack_top']) - int(gdb.lookup_type('syscall_frame_t').sizeof)
        saved = gdb.Value(address).cast(gdb.lookup_type('syscall_frame_t').pointer()).dereference()
        result['last_syscall'] = {'rip': hex(int(saved['rip'])), 'rsp': hex(int(saved['rsp']))}
    except (gdb.error, RuntimeError, ValueError) as error:
        result['capture_error'] = str(error)
    Path(fault_output_dir, 'fault-snapshot.json').write_text(json.dumps(result, indent=2) + '\n')
    print('ZEN_FATAL_SNAPSHOT ' + json.dumps(result))
end
delete breakpoints
detach
