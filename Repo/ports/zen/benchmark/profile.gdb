set pagination off
p g_ticks
p g_time_slice_ticks
p g_sched_steal_enable
p g_ui_cpu_index
python
import json
def allocation_location(address):
    result = {'symbol': gdb.execute('info symbol ' + hex(address), to_string=True).strip()}
    line = gdb.find_pc_line(address)
    if line.symtab:
        result.update(file=line.symtab.filename, line=line.line)
    return result
counters = {}
try:
    fields = gdb.lookup_type('process_t').strip_typedefs().fields()
    array = next(field.type for field in fields if field.name == 'futex_buckets')
    low, high = array.range()
    counters['futex_bucket_count'] = high - low + 1
except (gdb.error, StopIteration):
    pass
try:
    audio = gdb.parse_and_eval('g_hda')
    output = {name: int(audio[name]) for name in ('used_bytes', 'pcm_lead_bytes', 'empty_events',
        'reprime_events', 'stream_errors', 'rejected_writers', 'writer_pid', 'hw_pos_prev', 'last_hw_update_ms')}
    output['running'] = bool(audio['running'])
    if int(audio['active_pcm']):
        stream = audio['active_pcm'].dereference()
        output['stream'] = {name: int(stream[name]) for name in
            ('submitted_frames', 'played_frames', 'dropped_frames', 'owner_pid')}
    print('AUDIO_OUTPUT ' + json.dumps(output))
except gdb.error as error:
    print('AUDIO_OUTPUT_ERROR ' + str(error))
for name in ('g_sbrk_zero_bytes_avoided', 'g_vm_fresh_maps', 'g_vm_tlb_transactions',
             'g_vm_tlb_wait_sleeps', 'g_futex_wait_registrations', 'g_futex_wake_calls',
             'g_vm_no_present_changes', 'g_vm_tlb_waits', 'g_vm_serial_waits',
             'g_vm_tlb_completion_wakes', 'g_vm_tlb_pending_transactions',
             'g_vm_serial_wakes', 'g_vm_empty_wakes_avoided',
             'g_futex_memory_busy_retries', 'g_ahci_early_completion_hints',
             'g_futex_wake_candidates', 'g_futex_woken', 'g_futex_empty_wake_fast_enabled',
             'g_futex_empty_wakes_avoided', 'g_user_file_inline_socket',
             'g_user_file_inline_poll', 'g_user_file_inline_audio',
             'g_sched_idle_placement_enable', 'g_sched_idle_placement_redirects',
             'g_video_opaque_copy_enabled', 'g_video_opaque_copy_bytes', 'g_user_message_prepare_saved_bytes',
             'g_timer_delivered_irqs', 'g_timer_caught_up_ticks', 'g_timer_max_catchup_ticks',
             'g_timer_clock_reads',
             'g_user_message_empty_control_skips', 'g_io_event_notifications',
             'g_io_event_waits', 'g_io_event_wakes', 'g_io_event_timeouts',
             'g_io_admission_restarts', 'g_io_completion_requests',
             'g_io_event_empty_takes_avoided', 'g_tcp_pending_send_accepts',
             'g_tcp_pending_send_bytes',
             'g_tcp_rx_capacity_bytes', 'g_tcp_rx_peak_capacity_bytes',
             'g_tcp_rx_growths', 'g_tcp_rx_growth_failures',
             'g_sched_terminal_current_rejections', 'g_sched_terminal_switches',
             'g_vfs_lazy_loads', 'g_vfs_lazy_load_bytes', 'g_vfs_lazy_load_failures',
             'g_alixfs_deferred_files', 'g_alixfs_deferred_bytes',
             'g_vfs_service->queue->admission_count',
             'g_user_tcp_service->queue->admission_count',
             'g_thread_self_profile_enabled', 'g_thread_self_profile_calls'):
    try:
        counters[name] = int(gdb.parse_and_eval(name))
    except gdb.error:
        pass
for name in ('g_alixfs_snapshot_alloc_failures', 'g_alixfs_snapshot_failed_bytes',
             'g_alixfs_chunk_alloc_failures', 'g_alixfs_node_write_failures',
             'g_alixfs_streamed_nodes', 'g_alixfs_streamed_bytes', 'g_alixfs_stream_retries',
             'g_alixfs_free_rebuilds'):
    try: counters[name] = int(gdb.parse_and_eval(name))
    except gdb.error: pass
try:
    heap = {name: int(gdb.parse_and_eval(name)) for name in
            ('kernel_heap_size', 'g_heap_trace_bytes_in_use', 'g_heap_trace_peak_bytes')}
    heap['trace_enabled'] = bool(gdb.parse_and_eval('g_heap_trace_enabled'))
    try:
        failures = int(gdb.parse_and_eval('g_heap_allocation_failures'))
        records = gdb.parse_and_eval('g_heap_failure_records')
        heap['allocation_failures'] = failures
        if failures:
            first = gdb.parse_and_eval('g_heap_first_failure')
            heap['first_failure'] = {'bytes': int(first['bytes']), 'caller': hex(int(first['caller']))}
        heap['recent_failures'] = [{'sequence': sequence + 1,
            'bytes': int(records[sequence % 16]['bytes']),
            'caller': hex(int(records[sequence % 16]['caller']))}
            for sequence in range(max(0, failures - 16), failures)]
        for record in heap['recent_failures'] + ([heap['first_failure']] if failures else []):
            record['location'] = allocation_location(int(record['caller'], 16))
        try:
            heap['realloc_failures'] = int(gdb.parse_and_eval('g_heap_realloc_failures'))
            if heap['realloc_failures']:
                for name in ('first', 'last'):
                    record = gdb.parse_and_eval('g_heap_' + name + '_realloc_failure')
                    heap[name + '_realloc_failure'] = {'bytes': int(record['bytes']),
                        'previous_bytes': int(record['previous_bytes']), 'caller': hex(int(record['caller'])),
                        'location': allocation_location(int(record['caller']))}
        except gdb.error:
            pass
    except gdb.error:
        pass
    if int(gdb.parse_and_eval('g_heap_lock_owner')) == 0xffffffff:
        kind = gdb.lookup_type('struct heap_block')
        members = {field.name: field for field in kind.fields() if field.name}
        address = int(gdb.parse_and_eval('g_heap_head'))
        low, high = (int(gdb.parse_and_eval(name)) for name in ('g_heap_start', 'g_heap_end'))
        count, allocated, available, largest = 0, 0, 0, 0
        previous = 0
        while address and count < 65536:
            if not low <= address <= high - kind.sizeof:
                heap['walk_error'] = 'heap walk escaped region'; break
            raw = bytes(gdb.selected_inferior().read_memory(address, kind.sizeof))
            block = {name: int.from_bytes(raw[field.bitpos // 8:field.bitpos // 8 + field.type.sizeof], 'little')
                     for name, field in members.items() if name in ('size', 'next', 'prev', 'free')}
            if block['prev'] != previous or block['size'] > high - address - kind.sizeof:
                heap['walk_error'] = 'heap walk found inconsistent links/size'; break
            if block['free']:
                available += block['size']; largest = max(largest, block['size'])
            else: allocated += block['size']
            previous, address = address, block['next']; count += 1
        heap.update(walk_blocks=count, walk_truncated=bool(address), allocated_payload_bytes=allocated,
                    free_payload_bytes=available, largest_free_block_bytes=largest)
        if not address:
            heap['trace_matches_walk'] = allocated == heap['g_heap_trace_bytes_in_use']
            heap['walk_covers_region'] = allocated + available + count * kind.sizeof == high - low
    else:
        heap['walk_skipped'] = 'allocator lock owned at capture'
    print('KERNEL_HEAP ' + json.dumps(heap, sort_keys=True))
    mount = gdb.parse_and_eval('mounts')
    records = []
    for _ in range(16):
        if not int(mount): break
        backend = mount['backend']
        if int(backend):
            header = backend['header']
            records.append({name: int(header[name]) for name in
                ('node_count', 'node_capacity', 'data_region_offset', 'data_region_size', 'free_chunk_count')})
            records[-1].update(dirty_bytes=int(mount['dirty_bytes']),
                device_bytes=int(backend['device']['sector_count']) * int(backend['sector_size']))
        mount = mount['next']
    print('ALIXFS_MOUNTS ' + json.dumps(records, sort_keys=True))
    fields = {field.name: field for field in gdb.lookup_type('struct vfs_node').fields() if field.name}
    inferior = gdb.selected_inferior()
    pending = [int(gdb.parse_and_eval("'vfs.c'::root"))]
    nodes, buffers = {}, []
    while pending and len(nodes) < 20000:
        address = pending.pop()
        if not address or address in nodes: continue
        raw = bytes(inferior.read_memory(address, gdb.lookup_type('struct vfs_node').sizeof))
        node = {name: int.from_bytes(raw[field.bitpos // 8:field.bitpos // 8 + field.type.sizeof], 'little')
                for name, field in fields.items() if name in
                ('name', 'parent', 'first_child', 'next_sibling', 'data', 'capacity', 'size', 'type', 'data_unloaded')}
        nodes[address] = node
        pending.extend((node['first_child'], node['next_sibling']))
        if node['data'] and node['capacity']: buffers.append((address, node))
    def path_for(address):
        parts, visited = [], set()
        while address in nodes and address not in visited and len(visited) < 128:
            visited.add(address); node = nodes[address]
            if node['name']:
                name = bytes(inferior.read_memory(node['name'], 256)).split(b'\0', 1)[0].decode('utf-8', 'replace')
                if name.strip('/'): parts.append(name.strip('/'))
            address = node['parent']
        return '/' + '/'.join(reversed(parts))
    top = sorted(buffers, key=lambda item: item[1]['capacity'], reverse=True)[:24]
    unloaded = [(address, node) for address, node in nodes.items() if node.get('data_unloaded')]
    print('VFS_CACHE ' + json.dumps({'nodes': len(nodes), 'truncated': bool(pending),
        'buffer_capacity_bytes': sum(node['capacity'] for _, node in buffers),
        'file_size_bytes': sum(node['size'] for _, node in buffers),
        'unloaded_files': len(unloaded), 'unloaded_bytes': sum(node['size'] for _, node in unloaded),
        'largest_unloaded': [{'path': path_for(address), 'size': node['size']}
            for address, node in sorted(unloaded, key=lambda item: item[1]['size'], reverse=True)[:16]],
        'largest': [{'path': path_for(address), 'capacity': node['capacity'], 'size': node['size'], 'type': node['type']}
                    for address, node in top]}, sort_keys=True))
except gdb.error as error:
    print('STORAGE_PROFILE_ERROR ' + str(error))
try:
    operations = gdb.parse_and_eval('g_user_storage_operations')
    for i in range(64):
        counters['storage_operation_' + str(i)] = int(operations[i])
except gdb.error:
    pass
try:
    operations = gdb.parse_and_eval('g_user_file_inline_storage')
    for i in range(64):
        counters['inline_storage_' + str(i)] = int(operations[i])
except gdb.error:
    pass
for name in ('g_futex_resume_count', 'g_futex_resume_ticks'):
    try:
        values = gdb.parse_and_eval(name)
        low, high = values.type.range()
        counters[name + '_total'] = sum(int(values[i]) for i in range(low, high + 1))
    except gdb.error:
        pass
print('PERFORMANCE_COUNTERS ' + json.dumps(counters, sort_keys=True))
try:
    print('SCHED_SETTINGS hz/ticks/steal/ui',
        gdb.parse_and_eval('g_frequency_hz'), gdb.parse_and_eval('g_time_slice_ticks'),
        gdb.parse_and_eval('g_sched_steal_enable'), gdb.parse_and_eval('g_ui_cpu_index'))
except gdb.error:
    pass
end
p g_cpu_usage
p g_cpu_switch_counts
p g_heap_trace_bytes_in_use
p g_free_bytes
p *g_vfs_service->queue
p *g_user_tcp_service->queue
python
try:
    print('IO_ADMISSION_RESTARTS', gdb.parse_and_eval('g_io_admission_restarts'))
except gdb.error:
    pass
try:
    print('IO_COMPLETIONS requests/matched/broadcasts',
        gdb.parse_and_eval('g_io_completion_requests'),
        gdb.parse_and_eval('g_io_completion_matched'),
        gdb.parse_and_eval('g_io_completion_broadcasts'))
except gdb.error:
    pass
end
python
try:
    value = gdb.parse_and_eval('g_file_io_errors')
    raw = bytes(gdb.selected_inferior().read_memory(int(value.address), 128 * 128 * 8))
    errors = [(i // 128, i % 128, int.from_bytes(raw[i*8:i*8+8], 'little')) for i in range(128*128)]
    print('FILE_ERRORS (operation, errno, count)', [x for x in errors if x[2]])
except gdb.error:
    pass
t = gdb.parse_and_eval('g_thread_registry_head')
renderer_priorities = []
compositor_priorities = []
audio_priorities = []
vsync_priorities = []
timer_priorities = []
try:
    scheduler_cost_enabled = bool(gdb.parse_and_eval('g_sched_cost_control.enabled'))
    scheduler_cost_type = gdb.lookup_type('scheduler_cost_stats_t')
    scheduler_cost_fields = {field.name: (field.bitpos // 8, field.type.sizeof)
                             for field in scheduler_cost_type.fields() if field.name}
except gdb.error:
    scheduler_cost_enabled = False
scheduler_cost_rows = []
for i in range(4000):
    if int(t) == 0:
        break
    name = t['name'].string()
    if scheduler_cost_enabled:
        raw = bytes(gdb.selected_inferior().read_memory(int(t['scheduler_cost'].address), scheduler_cost_type.sizeof))
        cost = {name: int.from_bytes(raw[offset:offset+size], 'little')
                for name, (offset, size) in scheduler_cost_fields.items()}
        if any(cost.values()):
            scheduler_cost_rows.append({'tid': int(t['tid']), 'pid': int(t['owner_pid']),
                                        'name': name, 'runtime_ticks': int(t['runtime_ticks']), 'counters': cost})
    roles = {'Renderer': renderer_priorities, 'Compositor': compositor_priorities, 'cubeb-alix': audio_priorities}
    if name in ('Softwar~cThread', 'SoftwareVsyncThread'):
        roles[name] = vsync_priorities
    if name == 'Timer':
        roles[name] = timer_priorities
    if name in roles:
        roles[name].append({'tid': int(t['tid']), 'pid': int(t['owner_pid']),
            'base': str(t['base_priority']), 'effective': str(t['priority']),
            'override_active': bool(t['priority_override_active']), 'state': str(t['state']),
            'affinity_enabled': bool(t['affinity_enabled']), 'affinity_cpu': int(t['affinity_cpu']),
            'last_cpu': int(t['last_cpu_index']), 'queue_cpu': int(t['run_queue_cpu'])})
    print('THREAD', int(t['tid']), int(t['owner_pid']), name,
          str(t['state']), 'priority', str(t['priority']), 'ticks', int(t['runtime_ticks']),
          'cpu', int(t['running_cpu']), 'queue', int(t['run_queue_cpu']),
          'queued', bool(t['in_run_queue']), 'transition', bool(t['in_transition']),
          'wake_pending', bool(t['wake_pending']), 'exited', bool(t['exited']),
          'pending_destroy', bool(t['pending_destroy']), 'lifetime', str(t['lifetime_state']),
          'process_state', str(t['process']['state']) if int(t['process']) else None,
          'process_lifetime', str(t['process']['lifetime_state']) if int(t['process']) else None)
    t = t['registry_next']
print('NATIVE_RENDERER_PRIORITIES ' + json.dumps(renderer_priorities))
print('NATIVE_COMPOSITOR_PRIORITIES ' + json.dumps(compositor_priorities))
print('NATIVE_AUDIO_PRIORITIES ' + json.dumps(audio_priorities))
print('NATIVE_VSYNC_PRIORITIES ' + json.dumps(vsync_priorities))
print('NATIVE_TIMER_PRIORITIES ' + json.dumps(timer_priorities))
print('SCHEDULER_COST ' + json.dumps({'enabled': scheduler_cost_enabled, 'units': 'raw_tsc',
                                   'ticks': int(gdb.parse_and_eval('g_ticks')),
                                   'scope': 'registered threads; counters since arming; nested stages overlap',
                                   'threads': scheduler_cost_rows}))
for cpu in range(int(gdb.parse_and_eval("'smp.c'::g_cpu_count"))):
    current = gdb.parse_and_eval('g_current_threads')[cpu]
    outgoing = gdb.parse_and_eval('g_switch_out_threads')[cpu]
    print('SCHED_HANDOFF', cpu, 'current_tid', int(current['tid']) if int(current) else None,
          'outgoing_tid', int(outgoing['tid']) if int(outgoing) else None,
          'restore_flags', hex(int(gdb.parse_and_eval('g_switch_restore_rflags')[cpu])))
end
thread apply all bt 8
python
try:
    gdb.execute('set var g_thread_self_profile_enabled = 0')
except gdb.error:
    pass
try:
    gdb.execute('set var g_sched_cost_control.enabled = 0')
except gdb.error:
    pass
end
