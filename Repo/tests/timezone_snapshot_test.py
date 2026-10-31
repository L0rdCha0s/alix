#!/usr/bin/env python3
"""Race native timezone publication/readback and validate the syscall wire."""
from pathlib import Path
import argparse
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from audio_stream_contract_test import function_definition

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--sanitizer", choices=("address,undefined", "thread"), default="address,undefined")
args = parser.parse_args()
clock = (ROOT / "src/kernel/timekeeping.c").read_text()
api = (ROOT / "src/kernel/syscall.c").read_text()
header = (ROOT / "include/timekeeping.h").read_text()
wire = (ROOT / "include/syscall_defs.h").read_text()


def section(text, start, end):
    begin = text.index(start)
    return text[begin:text.index(end, begin) + len(end)]


code = r'''
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#define TIMEKEEPING_TZ_NAME_MAX 32
typedef pthread_mutex_t spinlock_t;
typedef struct { const char *name; } tzdb_zone_t;
static void spinlock_lock(spinlock_t *lock) { assert(!pthread_mutex_lock(lock)); }
static void spinlock_unlock(spinlock_t *lock) { assert(!pthread_mutex_unlock(lock)); }
'''
code += section(header, "typedef struct\n{\n    uint8_t month;", "} timekeeping_timezone_spec_t;")
code += section(clock, "typedef struct\n{\n    char name[TIMEKEEPING_TZ_NAME_MAX];", "} timekeeping_timezone_state_t;")
code += "\n" + wire[wire.index("#define SYSCALL_TIMEZONE_VERSION"):wire.index("#define SYSCALL_VM_PROT_NONE")]
code += "\nstatic timekeeping_timezone_state_t g_timezone;\nstatic uint64_t g_timezone_generation = 1;\nstatic spinlock_t g_timezone_lock = PTHREAD_MUTEX_INITIALIZER;\n"
for name in ("static void timekeeping_copy_string(", "static void timekeeping_set_timezone_internal(",
             "bool timekeeping_timezone_snapshot("):
    code += function_definition(clock, name) + "\n"
code += r'''
static unsigned guard_depth, allocations;
static bool deny_alloc, deny_copy;
static void spinlock_preempt_disable(void) { assert(!guard_depth++); }
static void spinlock_preempt_enable(void) { assert(guard_depth-- == 1); }
static bool user_ptr_range_valid(const void *ptr, size_t size) { return ptr && size == 328; }
static bool user_copy_to_user(void *to, const void *from, size_t size) {
    assert(guard_depth == 1);
    if (deny_copy) return false;
    memcpy(to, from, size); return true;
}
static void *checked_calloc(size_t n, size_t size) {
    assert(guard_depth == 1);
    if (deny_alloc) return NULL;
    void *value = calloc(n, size); if (value) ++allocations; return value;
}
static void checked_free(void *value) { assert(guard_depth == 1 && allocations); --allocations; free(value); }
'''
code += function_definition(api, "static void syscall_copy_string(")
code += "\n#define calloc checked_calloc\n#define free checked_free\n"
code += function_definition(api, "static int64_t syscall_do_timezone_info(")
code += "\n#undef calloc\n#undef free\n"
code += r'''
static const timekeeping_dst_rule_t rule_a = {3, 2, 0, 120};
static const timekeeping_dst_rule_t rule_b = {11, 1, 0, 180};
static void publish(unsigned parity) {
    timekeeping_set_timezone_internal(parity ? "B" : "A", parity ? -300 : 600, true,
        parity ? -240 : 660, parity ? &rule_b : &rule_a, parity ? &rule_a : &rule_b,
        NULL, NULL);
}
static void *writer(void *unused) {
    (void)unused;
    for (unsigned i=0; i<30000; ++i) publish(i & 1);
    return NULL;
}
static void *reader(void *unused) {
    (void)unused; uint64_t previous = 0;
    for (unsigned i=0; i<30000; ++i) {
        timekeeping_timezone_spec_t snapshot;
        uint64_t generation;
        assert(timekeeping_timezone_snapshot(&snapshot, &generation));
        assert(generation >= previous); previous = generation;
        bool b = !strcmp(snapshot.name, "B");
        assert(b || !strcmp(snapshot.name, "A"));
        assert(snapshot.standard_offset_minutes == (b ? -300 : 600));
        assert(snapshot.dst_offset_minutes == (b ? -240 : 660));
        assert(snapshot.dst_enabled && !snapshot.use_zone && !snapshot.zone_name[0]);
        assert(!memcmp(&snapshot.dst_start, b ? &rule_b : &rule_a, sizeof(rule_a)));
        assert(!memcmp(&snapshot.dst_end, b ? &rule_a : &rule_b, sizeof(rule_a)));
    }
    return NULL;
}
int main(void) {
    publish(0);
    pthread_t threads[5];
    assert(!pthread_create(&threads[0], NULL, writer, NULL));
    for (unsigned i=1; i<5; ++i) assert(!pthread_create(&threads[i], NULL, reader, NULL));
    for (unsigned i=0; i<5; ++i) assert(!pthread_join(threads[i], NULL));
    syscall_timezone_info_t output;
    memset(&output, 0xa5, sizeof(output));
    publish(0);
    assert(syscall_do_timezone_info(&output, sizeof(output)) == 0);
    assert(output.version == 1 && output.size == 328 && output.flags == 0);
    assert(output.kind == SYSCALL_TIMEZONE_RULE && output.standard_offset_seconds == 36000);
    assert(output.dst_offset_seconds == 39600 && output.start.time_seconds == 7200);
    assert(output.start.clock_basis == SYSCALL_TIMEZONE_CLOCK_WALL);
    assert(output.end.month == 11 && !strcmp(output.display_name, "A"));
    for (unsigned i=2; i<sizeof(output.display_name); ++i) assert(!output.display_name[i]);
    timekeeping_set_timezone_internal("UTC", 0, false, 0, NULL, NULL, NULL, NULL);
    assert(syscall_do_timezone_info(&output, sizeof(output)+64) == 0);
    assert(output.kind == SYSCALL_TIMEZONE_FIXED && !output.standard_offset_seconds);
    tzdb_zone_t zone = {"Australia/Sydney"};
    timekeeping_set_timezone_internal("Sydney", 600, true, 660, &rule_a, &rule_b, zone.name, &zone);
    assert(syscall_do_timezone_info(&output, sizeof(output)) == 0);
    assert(output.kind == SYSCALL_TIMEZONE_IANA && !strcmp(output.zone_id, zone.name));
    assert(syscall_do_timezone_info(&output, 327) == -22);
    assert(syscall_do_timezone_info(NULL, 328) == -14);
    deny_alloc = true; assert(syscall_do_timezone_info(&output, 328) == -12); deny_alloc = false;
    deny_copy = true; assert(syscall_do_timezone_info(&output, 328) == -14); deny_copy = false;
    assert(!allocations && !guard_depth);
    puts("Timezone publication 120000 concurrent snapshots and native syscall ABI: PASS");
}
'''
with tempfile.TemporaryDirectory(prefix="alix-timezone-snapshot-") as directory:
    path = Path(directory) / "test.c"
    binary = Path(directory) / "test"
    path.write_text(code)
    subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread",
                    "-fsanitize=" + args.sanitizer, str(path), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
