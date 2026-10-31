#!/usr/bin/env python3
"""Inject migration between CPU identification and current-context slot access."""
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import compile_and_run, function_definition

ROOT = Path(__file__).resolve().parents[1]
source = (ROOT / "include/process_internal.h").read_text()
code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#define SMP_MAX_CPUS 2
typedef struct { int identity; } thread_t;
typedef struct { int identity; } process_t;
static thread_t own_thread, other_thread, incoming_thread;
static process_t own_process, other_process, incoming_process;
static thread_t *g_current_threads[2];
static process_t *g_current_processes[2];
static uint32_t cpu;
static uint64_t flags;
static bool inject, migrate_on_restore;
static unsigned migrations;
static uint64_t cpu_save_flags(void) { return flags; }
static void cpu_cli(void) { flags &= ~512ULL; }
static void migrate(void) {
    cpu = 1; g_current_threads[0] = &other_thread; g_current_processes[0] = &other_process;
    g_current_threads[1] = &own_thread; g_current_processes[1] = &own_process; ++migrations;
}
static void cpu_restore_flags(uint64_t value) {
    flags = value;
    if ((flags & 512) && migrate_on_restore) { migrate_on_restore = false; migrate(); }
}
static uint32_t smp_current_cpu_index(void) {
    uint32_t original = cpu;
    if ((flags & 512) && inject) { inject = false; migrate(); }
    return original;
}
'''
for name in ("static inline thread_t *current_thread_local(", "static inline process_t *current_process_local(",
             "static inline void set_current_thread_local(", "static inline void set_current_process_local("):
    code += function_definition(source, name) + "\n"
code += r'''
static void reset(unsigned enabled) {
    cpu = migrations = 0; flags = 2 | (enabled ? 512 : 0);
    inject = true; migrate_on_restore = false;
    g_current_threads[0] = &own_thread; g_current_threads[1] = &other_thread;
    g_current_processes[0] = &own_process; g_current_processes[1] = &other_process;
}
int main(void) {
    reset(1); uint32_t old_index = smp_current_cpu_index();
    assert(migrations == 1 && g_current_threads[old_index] != &own_thread);
    for (unsigned enabled = 0; enabled < 2; ++enabled) {
        reset(enabled); uint64_t saved = flags;
        assert(current_thread_local() == &own_thread && current_process_local() == &own_process);
        assert(!migrations && flags == saved);
        set_current_thread_local(&incoming_thread); set_current_process_local(&incoming_process);
        assert(g_current_threads[0] == &incoming_thread && g_current_processes[0] == &incoming_process);
        assert(g_current_threads[1] == &other_thread && g_current_processes[1] == &other_process);
        assert(!migrations && flags == saved);
        cpu = 3; inject = false;
        assert(!current_thread_local() && !current_process_local());
        set_current_thread_local(NULL); set_current_process_local(NULL);
        assert(flags == saved && g_current_threads[0] == &incoming_thread);
        reset(enabled); migrate_on_restore = true;
        assert(current_thread_local() == &own_thread && flags == saved);
        assert(migrations == enabled);
    }
    puts("Current-context snapshot: old migration race reproduced; getter/setter IRQ boundaries PASS");
}
'''
compile_and_run("current-context", code)
