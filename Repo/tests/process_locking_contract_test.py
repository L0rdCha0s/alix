#!/usr/bin/env python3
"""Structural regressions for kernel spinlock/interrupt ordering."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]


def source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def function_body(text: str, signature: str) -> str:
    start = text.find(signature)
    if start < 0:
        raise AssertionError(f"missing function: {signature}")
    opening = text.find("{", start + len(signature))
    if opening < 0:
        raise AssertionError(f"missing body: {signature}")
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[opening + 1:index]
    raise AssertionError(f"unterminated body: {signature}")


def before(body: str, first: str, second: str) -> None:
    first_at = body.find(first)
    second_at = body.find(second)
    if first_at < 0 or second_at < 0 or first_at >= second_at:
        raise AssertionError(f"expected {first!r} before {second!r}")


def main() -> int:
    process_api = source("src/kernel/process/process_api.c")
    timer = source("src/drivers/timer.c")
    spinlock = source("include/spinlock.h")
    process_internal = source("include/process_internal.h")
    process_init = source("src/kernel/process/process_init.c")
    process_scheduler = source("src/kernel/process/process_scheduler.c")
    lapic = source("src/arch/x86/lapic.c")
    igb = source("src/drivers/igb.c")

    tick = function_body(process_api, "void process_on_timer_tick(interrupt_frame_t *frame)")
    for lock_taking_work in (
        "scheduler_log_process_age_snapshot(now_ticks)",
        "sleep_queue_wake_due(now_ticks)",
        "stack_watch_check_timeouts()",
    ):
        before(tick, "spinlock_preempt_disabled()", lock_taking_work)
    before(tick, "smp_current_cpu_index() == 0", "sleep_queue_wake_due(now_ticks)")

    timer_tick = function_body(timer, "void timer_on_tick(void)")
    before(timer_tick, "g_ticks++", "spinlock_preempt_disabled()")
    before(timer_tick, "spinlock_preempt_disabled()", "task->callback(task->context)")

    generic_lock = function_body(spinlock, "static inline void spinlock_lock(spinlock_t *lock)")
    before(generic_lock, "spinlock_preempt_disable()", "spinlock_lock_raw(lock)")
    generic_unlock = function_body(spinlock, "static inline void spinlock_unlock(spinlock_t *lock)")
    before(generic_unlock, "spinlock_unlock_raw(lock)", "spinlock_preempt_enable()")

    irq_lock = function_body(spinlock, "static inline uint64_t spinlock_lock_irqsave(spinlock_t *lock)")
    before(irq_lock, '"cli"', "spinlock_lock(lock)")
    irq_unlock = function_body(spinlock, "static inline void spinlock_unlock_irqrestore(spinlock_t *lock, uint64_t flags)")
    before(irq_unlock, "spinlock_unlock_raw(lock)", '"push %0; popfq"')
    before(irq_unlock, '"push %0; popfq"', "spinlock_preempt_enable()")

    scheduler_lock = function_body(process_internal, "static inline uint64_t scheduler_lock_acquire(const char *where)")
    if "spinlock_lock_raw(&g_scheduler_lock)" not in scheduler_lock:
        raise AssertionError("cross-stack scheduler lock must use the raw primitive")

    if "#define LAPIC_DEST_ALL_EXCLUDING_SELF  (3u << 18)" not in lapic:
        raise AssertionError("APIC all-excluding-self shorthand must be binary 11")
    broadcast = function_body(lapic, "void lapic_broadcast_ipi(uint8_t vector, bool include_self)")
    if "LAPIC_DEST_ALL_EXCLUDING_SELF" not in broadcast:
        raise AssertionError("APIC broadcast excluding self does not target the APs")

    scheduler_main = function_body(process_init, "static void scheduler_main_loop(void)")
    before(scheduler_main, "cpu_cli()", "scheduler_schedule(false)")
    before(scheduler_main, "scheduler_schedule(false)", '"sti; hlt"')
    idle_entry = function_body(process_scheduler, "void idle_thread_entry(void *arg)")
    before(idle_entry, "cpu_cli()", "scheduler_schedule(false)")
    before(idle_entry, "scheduler_schedule(false)", '"sti; hlt"')

    igb_irq = function_body(igb, "void igb_on_irq(void)")
    before(igb_irq, "spinlock_preempt_disabled()", "igb_handle_receive()")

    irq_shared_sources = {
        "src/drivers/keyboard.c": ("g_kbd_buffer_lock",),
        "src/drivers/serial.c": ("g_serial_queue_lock", "g_serial_hw_lock"),
        "src/drivers/igb.c": ("g_rx_lock", "g_tx_lock"),
        "src/drivers/rtl8139.c": ("g_rx_lock",),
    }
    for path, names in irq_shared_sources.items():
        text = source(path)
        for name in names:
            if f"spinlock_lock(&{name})" in text:
                raise AssertionError(f"{path}: {name} bypasses irqsave")

    print("process locking contract test passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AssertionError as error:
        print(f"process locking contract test failed: {error}", file=sys.stderr)
        raise SystemExit(1)
