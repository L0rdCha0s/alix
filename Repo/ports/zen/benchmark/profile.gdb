set pagination off
p g_ticks
p g_time_slice_ticks
p g_sched_steal_enable
p g_ui_cpu_index
python
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
for i in range(4000):
    if int(t) == 0:
        break
    print('THREAD', int(t['tid']), int(t['owner_pid']), t['name'].string(),
          str(t['state']), 'ticks', int(t['runtime_ticks']),
          'cpu', int(t['running_cpu']), 'queue', int(t['run_queue_cpu']),
          'queued', bool(t['in_run_queue']), 'transition', bool(t['in_transition']),
          'wake_pending', bool(t['wake_pending']))
    t = t['registry_next']
end
thread apply all bt 8
