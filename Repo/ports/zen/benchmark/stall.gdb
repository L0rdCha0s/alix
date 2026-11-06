set pagination off
python
import gdb, json, math, re, struct

inferior = gdb.selected_inferior()
snapshot = {'ticks': int(gdb.parse_and_eval('g_ticks')), 'cpus': [], 'modules': {}, 'threads': [], 'render_contexts': []}
def text(value, limit=256):
    try: return value.string(encoding='utf-8', errors='replace', length=limit).split('\0', 1)[0]
    except gdb.error: return '<unreadable>'
def notes(address, size, reader=None):
    data = reader(address, size) if reader else bytes(inferior.read_memory(address, size))
    position = 0
    while position + 12 <= len(data):
        names, desc, kind = struct.unpack_from('<III', data, position)
        position += 12
        if names > len(data) - position: break
        owner = data[position:position+names].rstrip(b'\0')
        position += (names + 3) & ~3
        if desc > len(data) - position: break
        value = data[position:position+desc]
        position += (desc + 3) & ~3
        if owner == b'GNU' and kind == 3: return value.hex()
    return None
# Read another process without changing CR3 or calling target code. The high
# physmap is common to every address space (include/physmem.h). Page tables
# are stable while all CPUs are stopped; absent/swapped pages remain absent.
pte_cache = {}
def physical(address, size):
    return bytes(inferior.read_memory(0xffff800000000000 + address, size))
def virtual(cr3, address, size):
    result = bytearray()
    while size:
        table = cr3 & 0x000ffffffffff000
        for shift in (39, 30, 21, 12):
            location = table + ((address >> shift) & 511) * 8
            if location not in pte_cache:
                pte_cache[location] = struct.unpack('<Q', physical(location, 8))[0]
            entry = pte_cache[location]
            if not entry & 1: raise gdb.MemoryError('user page not resident: ' + hex(address))
            if shift in (30, 21) and entry & 128:
                mapped = (entry & 0x000ffffffffff000 & ~((1 << shift) - 1)) + (address & ((1 << shift) - 1))
                break
            table = entry & 0x000ffffffffff000
            if shift == 12: mapped = table + (address & 4095)
        count = min(size, 4096 - (address & 4095))
        result.extend(physical(mapped, count)); address += count; size -= count
    return bytes(result)
fields = {field.name: field for field in gdb.lookup_type('dl_module').strip_typedefs().fields() if field.name}
def field(cr3, address, name):
    member = fields[name]
    return int.from_bytes(virtual(cr3, address + member.bitpos // 8, member.type.sizeof), 'little')
def process_modules(process):
    cr3 = int(process['cr3'])
    address = int.from_bytes(virtual(cr3, int(gdb.parse_and_eval('&dl_modules')), 8), 'little')
    modules, seen = [], set()
    for _ in range(128):
        if not address or address in seen: break
        seen.add(address)
        path = virtual(cr3, field(cr3, address, 'path'), 256).split(b'\0', 1)[0].decode('utf-8', 'replace')
        if not path.startswith('/'): raise ValueError('invalid module path; check executable symbols')
        bias = field(cr3, address, 'bias')
        entry = {'path': path, 'bias': hex(bias), 'executable_ranges': []}
        headers = field(cr3, address, 'program_headers')
        for index in range(min(field(cr3, address, 'program_header_count'), 128)):
            kind, flags, _, vaddr, _, size, memsz, _ = struct.unpack('<IIQQQQQQ', virtual(cr3, headers + index * 56, 56))
            if kind == 1 and flags & 1: entry['executable_ranges'].append([bias + vaddr, bias + vaddr + memsz])
            if kind == 4 and 0 < size <= 65536:
                try:
                    build_id = notes(bias + vaddr, size, lambda a, n: virtual(cr3, a, n))
                    if build_id: entry['build_id'] = build_id
                except gdb.error: pass
        modules.append(entry); address = field(cr3, address, 'next')
    return modules

def swgl_state(cr3, modules, pc):
    info = globals().get('swgl_profile_info')
    module = next((m for m in modules if m['path'].endswith('/libxul.so')), None)
    if not module:
        return {'status': 'module_unavailable'}
    if module.get('build_id') != info['build_id']:
        return {'status': 'module_build_id_mismatch', 'build_id': module.get('build_id')}
    bias = int(module['bias'], 16)
    def read_fields(address, group):
        result = {}
        for name, field in info[group].items():
            offset, size, kind = field['offset'], field['size'], field['kind']
            if not 0 <= offset < 4096 or not 0 < size <= 128:
                raise ValueError('SWGL field exceeds bounded capture layout')
            data = virtual(cr3, address + offset, size)
            if kind == 'ptr':
                if size != 8: raise ValueError('SWGL pointer is not 64-bit')
                value = hex(int.from_bytes(data, 'little'))
            elif kind in ('int', 'uint'):
                value = int.from_bytes(data, 'little', signed=kind == 'int')
            elif kind in ('floats', 'ints'):
                if size % 4: raise ValueError('invalid SWGL vector width')
                value = list(struct.unpack('<' + ('f' if kind == 'floats' else 'i') * (size // 4), data))
                value = [v if not isinstance(v, float) or math.isfinite(v) else str(v) for v in value]
            else:
                raise ValueError('unknown SWGL field kind')
            result[name] = value
        return result
    address = int.from_bytes(virtual(cr3, bias + info['fragment_shader_offset'], 8), 'little')
    if not address: return {'status': 'no_current_shader'}
    result = {'status': 'OK', 'shader_address': hex(address), 'build_id': info['build_id'],
              'fragment': read_fields(address, 'fragment')}
    run = int(result['fragment']['run_func'], 16)
    result['blur_run_selected'] = any(run == bias + low for low, high in info['blur_run_ranges'])
    result['pc_inside_blur_run'] = any(bias + low <= pc < bias + high for low, high in info['blur_run_ranges'])
    if result['blur_run_selected']:
        result['blur'] = read_fields(address, 'blur')
        sampler = int(result['blur']['sColor0'], 16)
        if sampler:
            result['sampler'] = read_fields(sampler, 'sampler')
            result['sampler']['format_name'] = info['texture_formats'].get(str(result['sampler']['format']), 'unknown')
    return result

for cpu_thread in inferior.threads():
    cpu_thread.switch()
    match = re.search(r'CPU#(\d+)', cpu_thread.name or '')
    cpu = int(match.group(1)) if match else cpu_thread.num - 1
    row = {'cpu': cpu}
    try:
        frame = gdb.newest_frame()
        row.update(rip=hex(int(frame.read_register('rip'))), cs=int(frame.read_register('cs')),
                   rsp=hex(int(frame.read_register('rsp'))), cr3=hex(int(frame.read_register('cr3'))))
        thread = gdb.parse_and_eval('g_current_threads')[cpu]
        if not int(thread):
            snapshot['cpus'].append(row); continue
        row.update(tid=int(thread['tid']), pid=int(thread['owner_pid']), name=text(thread['name'], 64),
                   runtime_ticks=int(thread['runtime_ticks']), preempt_depth=int(thread['preempt_disable_depth']))
        process = thread['process']
        cr3 = int(process['cr3']) if int(process) else int(row['cr3'], 16)
        row['executable'] = text(process['executable_path']) if int(process) else ''
        user_pc = int(row['rip'], 16) if row['cs'] & 3 == 3 else None
        user_sp = int(row['rsp'], 16) if user_pc else None
        if not user_pc and bool(thread['is_user']):
            address = int(thread['kernel_stack_top']) - int(gdb.lookup_type('syscall_frame_t').sizeof)
            saved = gdb.Value(address).cast(gdb.lookup_type('syscall_frame_t').pointer()).dereference()
            if int(saved['cs']) == 0x2b and int(saved['rip']) >= 0x100000000:
                user_pc, user_sp = int(saved['rip']), int(saved['rsp'])
                row['user_context_source'] = 'last_syscall_frame'
        elif user_pc:
            row['user_context_source'] = 'live_registers'
            row['user_registers'] = {name: hex(int(frame.read_register(name))) for name in
                ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15')}
        if user_pc:
            row.update(user_pc=hex(user_pc), user_sp=hex(user_sp))
            try:
                row['user_code_probe'] = {'address': hex(user_pc),
                    'code_hex': virtual(cr3, user_pc, 32).hex()}
            except gdb.error as error:
                row['user_code_probe_error'] = str(error)
        pid = str(row['pid'])
        if '/usr/lib/zen/' in row['executable'] and pid not in snapshot['modules']:
            try:
                address = int(gdb.parse_and_eval('(void *)pthread_self'))
                row['pthread_self_probe'] = {'address': hex(address),
                    'code_hex': virtual(cr3, address, 32).hex()}
            except gdb.error: pass
            try:
                snapshot['modules'][pid] = process_modules(process)
            except (gdb.error, ValueError) as error:
                row['module_error'] = str(error)
        modules = snapshot['modules'].get(pid, [])
        def identify(address):
            for module in modules:
                if any(low <= address < high for low, high in module['executable_ranges']):
                    return {'address': hex(address), 'module': module['path'],
                            'offset': hex(address - int(module['bias'], 16)), 'build_id': module.get('build_id')}
            return None
        if user_pc:
            row['user_location'] = identify(user_pc)
        if globals().get('swgl_profile_info') and row.get('user_context_source') == 'live_registers' and (
                row['name'] == 'Renderer' or row['name'].startswith('WRWorker')):
            try:
                row['swgl_shader_state'] = swgl_state(cr3, modules, user_pc)
            except (gdb.error, ValueError) as error:
                row['swgl_shader_state'] = {'status': 'unavailable', 'error': str(error)}
        # These are candidates, not an unwound call stack: Gecko omits frame
        # pointers. Only values inside an executable module range are retained.
        if user_sp and modules:
            base, length = int(thread['user_stack_base']), int(thread['user_stack_size'])
            if not length and int(process):
                length = int(process['user_stack_size'])
                base = int(process['user_stack_top']) - length
            if base <= user_sp < base + length:
                try:
                    data = virtual(cr3, user_sp, min(2048, base + length - user_sp))
                    candidates = []
                    for offset in range(0, len(data) - 7, 8):
                        address = struct.unpack_from('<Q', data, offset)[0]
                        location = identify(address)
                        if location and len(candidates) < 32:
                            location.update(stack_address=hex(user_sp + offset), stack_offset=offset)
                            candidates.append(location)
                    row['stack_code_candidates'] = candidates
                except gdb.error: pass
    except (gdb.error, RuntimeError, ValueError) as error:
        row['error'] = str(error)
    snapshot['cpus'].append(row)
thread = gdb.parse_and_eval('g_thread_registry_head')
registered = []
for _ in range(2048):
    if not int(thread): break
    registered.append(thread)
    snapshot['threads'].append({'tid': int(thread['tid']), 'pid': int(thread['owner_pid']),
        'name': text(thread['name'], 64), 'state': str(thread['state']),
        'runtime_ticks': int(thread['runtime_ticks']), 'cpu': int(thread['running_cpu']),
        'queued': bool(thread['in_run_queue']), 'queue_cpu': int(thread['run_queue_cpu']),
        'priority': str(thread['priority']), 'preempt_depth': int(thread['preempt_disable_depth'])})
    thread = thread['registry_next']
snapshot['threads_truncated'] = bool(int(thread))

render_pids = {int(t['owner_pid']) for t in registered if text(t['name'], 64) in ('Renderer', 'Compositor')}
for t in registered:
    name, pid = text(t['name'], 64), int(t['owner_pid'])
    role = any(word in name for word in
        ('Renderer', 'Compositor', 'RenderBackend', 'SceneBuilder', 'MainThread', 'WRWorker'))
    runnable = str(t['state']) in ('THREAD_STATE_READY', 'THREAD_STATE_RUNNING')
    if pid not in render_pids or not bool(t['is_user']) or not (role or runnable):
        continue
    if len(snapshot['render_contexts']) >= 96: break
    row = {'tid': int(t['tid']), 'pid': pid, 'name': name, 'state': str(t['state']),
           'runtime_ticks': int(t['runtime_ticks']), 'vm_syscall_active': bool(t['vm_syscall_active']),
           'context_source': 'last_syscall_frame', 'stack_code_candidates': []}
    try:
        process = t['process']; cr3 = int(process['cr3'])
        modules = snapshot['modules'].get(str(pid))
        if not modules:
            modules = process_modules(process); snapshot['modules'][str(pid)] = modules
        def locate(address):
            for module in modules:
                if any(low <= address < high for low, high in module['executable_ranges']):
                    return {'address': hex(address), 'module': module['path'],
                            'offset': hex(address - int(module['bias'], 16)), 'build_id': module.get('build_id')}
        # A preempted user's resume address may live in the saved kernel
        # call chain rather than the last user syscall frame. These are code
        # candidates only, not an unwind or proof of mutex ownership.
        context, bottom, top = int(t['context']), int(t['stack_base']), int(t['kernel_stack_top'])
        if int(t['running_cpu']) == 0xffffffff and bottom <= context < top:
            data = bytes(inferior.read_memory(context, min(4096, top - context)))
            candidates = []
            for offset in range(0, len(data) - 7, 8):
                location = locate(struct.unpack_from('<Q', data, offset)[0])
                if location and len(candidates) < 24:
                    location.update(stack_address=hex(context + offset), stack_offset=offset)
                    candidates.append(location)
            row['kernel_stack_user_code_candidates'] = candidates
        frame_address = int(t['kernel_stack_top']) - int(gdb.lookup_type('syscall_frame_t').sizeof)
        saved = gdb.Value(frame_address).cast(gdb.lookup_type('syscall_frame_t').pointer()).dereference()
        if int(saved['cs']) != 0x2b: raise ValueError('no saved user syscall frame')
        pc, sp = int(saved['rip']), int(saved['rsp'])
        row.update(user_pc=hex(pc), user_sp=hex(sp), user_location=locate(pc))
        try:
            row['user_code_probe'] = {'address': hex(pc),
                'code_hex': virtual(cr3, pc, 32).hex()}
        except gdb.error as error:
            row['user_code_probe_error'] = str(error)
        if row['vm_syscall_active']:
            row['syscall_number'] = int(saved['rax'])
            if int(saved['rax']) == 43:
                address = int(saved['rdi'])
                row['futex'] = {'address': hex(address), 'expected': int(saved['rsi']) & 0xffffffff,
                                'value': int.from_bytes(virtual(cr3, address, 4), 'little')}
        base, size = int(t['user_stack_base']), int(t['user_stack_size'])
        if not size:
            size = int(process['user_stack_size']); base = int(process['user_stack_top']) - size
        if base <= sp < base + size:
            data = virtual(cr3, sp, min(2048, base + size - sp))
            for offset in range(0, len(data) - 7, 8):
                location = locate(struct.unpack_from('<Q', data, offset)[0])
                if location and len(row['stack_code_candidates']) < 32:
                    location.update(stack_address=hex(sp + offset), stack_offset=offset)
                    row['stack_code_candidates'].append(location)
    except (gdb.error, RuntimeError, ValueError) as error:
        row['error'] = str(error)
    snapshot['render_contexts'].append(row)
snapshot['process_address_spaces'] = {}
snapshot['user_heap_summaries'] = {}
try:
    kernel_bins = gdb.parse_and_eval('g_free_bins')
    kernel_array = kernel_bins.type.strip_typedefs()
    kernel_low, kernel_high = kernel_array.range()
    kernel_block = kernel_array.target().target().strip_typedefs()
    kernel_fields = {field.name: field.bitpos // 8 for field in kernel_block.fields()}
    if kernel_low != 0 or kernel_high != 31 or kernel_block.sizeof != 48:
        raise ValueError('unsupported kernel heap symbol layout')
    kernel_bottom = int(gdb.parse_and_eval('g_heap_start'))
    kernel_top = int(gdb.parse_and_eval('g_heap_end'))
    kernel_heads = struct.unpack('<32Q', bytes(inferior.read_memory(kernel_bins.address, 256)))
    kernel_summary = {'lock_owner_cpu': int(gdb.parse_and_eval('g_heap_lock_owner')),
                      'lock_depth': int(gdb.parse_and_eval('g_heap_lock_depth')),
                      'bins': []}
    snapshot['kernel_heap_free_lists'] = kernel_summary
    # Diagnostic walk counts only. A stopped allocator may be between its
    # ordinary metadata writes; a held-lock snapshot is not an integrity check.
    for index, requests in ((0,(16,32)), (1,(48,64)), (2,(96,112,128)),
                            (3,(240,256)), (4,(496,512)), (5,(1008,1024)),
                            (7,(4096,))):
        address, visited, histogram = kernel_heads[index], set(), {}
        row = {'index': index, 'first_fit': {str(n): None for n in requests}}
        kernel_summary['bins'].append(row)
        while address and len(visited) < 256:
            if address in visited or not kernel_bottom <= address <= kernel_top - kernel_block.sizeof:
                row['invalid_or_cyclic_pointer'] = hex(address); break
            visited.add(address)
            data = bytes(inferior.read_memory(address, kernel_block.sizeof))
            offset = kernel_fields['size']
            size = int.from_bytes(data[offset:offset+8], 'little')
            if address + kernel_block.sizeof + size > kernel_top:
                row['invalid_size'] = size; break
            histogram[str(size)] = histogram.get(str(size), 0) + 1
            for requested in requests:
                if size >= requested and row['first_fit'][str(requested)] is None:
                    row['first_fit'][str(requested)] = len(visited)
            offset = kernel_fields['free_next']
            address = int.from_bytes(data[offset:offset+8], 'little')
        row.update(nodes=len(visited), truncated=bool(address), size_histogram=histogram)
except (gdb.error, ValueError) as error:
    snapshot['kernel_heap_free_list_error'] = str(error)
try:
    bins_value = gdb.parse_and_eval('g_heap_free_bins')
    bins_address = int(bins_value.address)
    array_type = bins_value.type.strip_typedefs()
    low, high = array_type.range()
    block_type = array_type.target().target().strip_typedefs()
    offsets = {field.name: field.bitpos // 8 for field in block_type.fields()}
    user_base = int(gdb.parse_and_eval('g_mem_layout.user_pointer_base'))
    locks = [int(symbol.value().address) for symbol in gdb.lookup_static_symbols('g_heap_lock')
             if int(symbol.value().address) >= user_base]
    if low != 0 or high not in (63,127) or block_type.sizeof != 48 or len(locks) != 1:
        raise ValueError('unsupported user heap symbol layout')
    processes = {int(t['owner_pid']): t['process'] for t in registered
                 if text(t['name'], 64) in ('Renderer', 'cubeb-alix') and int(t['process'])}
    for pid, proc in processes.items():
        summary = {'status': 'OK', 'bins': []}
        snapshot['user_heap_summaries'][str(pid)] = summary
        try:
            cr3 = int(proc['cr3'])
            bottom, top = int(proc['user_heap_base']), int(proc['user_heap_brk'])
            summary.update(heap_base=hex(bottom), heap_break=hex(top),
                           lock_state=int.from_bytes(virtual(cr3, locks[0], 4), 'little'),
                           bin_count=high + 1)
            heads = struct.unpack('<' + str(high + 1) + 'Q', virtual(cr3, bins_address, (high + 1) * 8))
            groups = ((6,(96,112)), (7,(128,160,192,208,224,240)),
                      (8,(256,384,496)), (9,(512,768,1008))) if high == 63 else (
                      (5,(96,)), (6,(112,)), (14,(240,)), (30,(496,)), (62,(1008,)))
            for index, requests in groups:
                address, visited, histogram = heads[index], set(), {}
                row = {'index': index, 'first_fit': {str(n): None for n in requests}}
                summary['bins'].append(row)
                limit = 512 if index == 7 else 128
                while address and len(visited) < limit:
                    if address in visited or not bottom <= address <= top - block_type.sizeof:
                        row['invalid_or_cyclic_pointer'] = hex(address); break
                    visited.add(address)
                    data = virtual(cr3, address, block_type.sizeof)
                    size = int.from_bytes(data[offsets['size']:offsets['size']+8], 'little')
                    if address + block_type.sizeof + size > top:
                        row['invalid_size'] = size; break
                    histogram[str(size)] = histogram.get(str(size), 0) + 1
                    for requested in requests:
                        if size >= requested and row['first_fit'][str(requested)] is None:
                            row['first_fit'][str(requested)] = len(visited)
                    address = int.from_bytes(data[offsets['free_next']:offsets['free_next']+8], 'little')
                row.update(nodes=len(visited), truncated=bool(address), size_histogram=histogram)
        except (gdb.error, ValueError) as error:
            summary.update(status='unavailable', error=str(error))
except (gdb.error, ValueError) as error:
    snapshot['user_heap_summary_error'] = str(error)
process = gdb.parse_and_eval('g_process_list')
for _ in range(4000):
    if not int(process): break
    snapshot['process_address_spaces'][str(int(process['pid']))] = hex(int(process['cr3']))
    process = process['next']
print('ZEN_STALL_SNAPSHOT_JSON ' + json.dumps(snapshot, sort_keys=True))
end
thread apply all bt 8
