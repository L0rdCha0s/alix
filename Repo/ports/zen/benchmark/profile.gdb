set pagination off
p g_ticks
p g_time_slice_ticks
p g_sched_steal_enable
p g_ui_cpu_index
python
import json
counters = {}
for name in ('g_sbrk_zero_bytes_avoided', 'g_vm_fresh_maps', 'g_vm_tlb_transactions',
             'g_vm_tlb_wait_sleeps', 'g_futex_wait_registrations', 'g_futex_wake_calls',
             'g_vm_no_present_changes', 'g_vm_tlb_waits', 'g_vm_serial_waits',
             'g_vm_tlb_completion_wakes', 'g_vm_tlb_pending_transactions',
             'g_vm_serial_wakes', 'g_vm_empty_wakes_avoided',
             'g_futex_memory_busy_retries', 'g_ahci_early_completion_hints',
             'g_futex_wake_candidates', 'g_futex_woken', 'g_user_file_inline_socket',
             'g_user_file_inline_poll', 'g_user_message_prepare_saved_bytes',
             'g_user_message_empty_control_skips', 'g_io_event_notifications',
             'g_io_event_waits', 'g_io_event_wakes', 'g_io_event_timeouts',
             'g_io_admission_restarts', 'g_io_completion_requests',
             'g_io_event_empty_takes_avoided', 'g_tcp_pending_send_accepts',
             'g_tcp_pending_send_bytes',
             'g_vfs_service->queue->admission_count',
             'g_user_tcp_service->queue->admission_count'):
    try:
        counters[name] = int(gdb.parse_and_eval(name))
    except gdb.error:
        pass
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
for i in range(4000):
    if int(t) == 0:
        break
    print('THREAD', int(t['tid']), int(t['owner_pid']), t['name'].string(),
          str(t['state']), 'priority', str(t['priority']), 'ticks', int(t['runtime_ticks']),
          'cpu', int(t['running_cpu']), 'queue', int(t['run_queue_cpu']),
          'queued', bool(t['in_run_queue']), 'transition', bool(t['in_transition']),
          'wake_pending', bool(t['wake_pending']))
    t = t['registry_next']
end
thread apply all bt 8
