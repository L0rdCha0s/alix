#include "serial.h"
#include "io.h"
#include "libc.h"
#include "serial_format.h"
#include "spinlock.h"
#include "process.h"
#include "smp.h"
#include "arch/x86/cpu.h"
#include "timer.h"
#include "timekeeping.h"
#include <stdint.h>

#define COM1 0x3F8

static const uint64_t CANONICAL_MASK = 0xFFFF800000000000ULL;

#define SERIAL_QUEUE_SIZE 8192
#ifndef SERIAL_LOG_PREFIX_ENABLE
#define SERIAL_LOG_PREFIX_ENABLE 1
#endif

static char g_serial_queue[SERIAL_QUEUE_SIZE];
static size_t g_serial_queue_head = 0;
static size_t g_serial_queue_tail = 0;
static spinlock_t g_serial_queue_lock;
static spinlock_t g_serial_hw_lock;
static spinlock_t g_serial_output_lock;
static uint32_t g_serial_output_owner = UINT32_MAX;
static uint32_t g_serial_output_depth = 0;
static uint64_t g_serial_output_saved_flags[SMP_MAX_CPUS];
static bool g_serial_async_enabled = false;
static bool g_serial_worker_started = false;

static void serial_hw_write_char(char c);
static void serial_worker_entry(void *arg);
static void serial_log_lock(void);
static void serial_log_unlock(void);

static inline uint64_t serial_cpu_save_flags(void)
{
    uint64_t flags;
    __asm__ volatile ("pushfq; pop %0" : "=r"(flags));
    return flags;
}

static inline void serial_cpu_restore_flags(uint64_t flags)
{
    __asm__ volatile ("push %0; popfq" :: "r"(flags) : "cc");
}

static inline void serial_cpu_cli(void)
{
    __asm__ volatile ("cli" ::: "memory");
}

static int serial_transmit_ready(void)
{
    return (inb(COM1 + 5) & 0x20) != 0;
}

static int serial_receive_ready(void)
{
    return (inb(COM1 + 5) & 0x01) != 0;
}

void serial_init(void)
{
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1 + 0, 0x01);
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x0B);
    spinlock_init(&g_serial_queue_lock);
    spinlock_init(&g_serial_hw_lock);
    spinlock_init(&g_serial_output_lock);
    g_serial_output_owner = UINT32_MAX;
    g_serial_output_depth = 0;
}

static void serial_hw_write_char(char c)
{
    spinlock_lock(&g_serial_hw_lock);
    while (!serial_transmit_ready())
    {
    }
    outb(COM1, (uint8_t)c);
    spinlock_unlock(&g_serial_hw_lock);
}

static void serial_queue_push(char c)
{
    while (1)
    {
        spinlock_lock(&g_serial_queue_lock);
        size_t next_tail = (g_serial_queue_tail + 1) % SERIAL_QUEUE_SIZE;
        if (next_tail != g_serial_queue_head)
        {
            g_serial_queue[g_serial_queue_tail] = c;
            g_serial_queue_tail = next_tail;
            spinlock_unlock(&g_serial_queue_lock);
            return;
        }
        char flushed = g_serial_queue[g_serial_queue_head];
        g_serial_queue_head = (g_serial_queue_head + 1) % SERIAL_QUEUE_SIZE;
        spinlock_unlock(&g_serial_queue_lock);
        serial_hw_write_char(flushed);
    }
}

static bool serial_queue_pop(char *out)
{
    bool result = false;
    spinlock_lock(&g_serial_queue_lock);
    if (g_serial_queue_head != g_serial_queue_tail)
    {
        *out = g_serial_queue[g_serial_queue_head];
        g_serial_queue_head = (g_serial_queue_head + 1) % SERIAL_QUEUE_SIZE;
        result = true;
    }
    spinlock_unlock(&g_serial_queue_lock);
    return result;
}

static void serial_output_char(char c)
{
    if (!g_serial_async_enabled)
    {
        serial_hw_write_char(c);
        return;
    }
    serial_queue_push(c);
}

static void serial_output_decimal(uint64_t value)
{
    char buf[32];
    size_t pos = 0;
    do
    {
        buf[pos++] = (char)('0' + (value % 10ULL));
        value /= 10ULL;
    } while (value > 0 && pos < sizeof(buf));

    while (pos > 0)
    {
        serial_output_char(buf[--pos]);
    }
}

static uint64_t serial_now_millis(void)
{
    uint64_t ms = timekeeping_now_millis();
    if (ms != 0)
    {
        return ms;
    }
    uint32_t freq = timer_frequency();
    if (freq == 0)
    {
        return 0;
    }
    uint64_t ticks = timer_ticks();
    return (ticks * 1000ULL) / (uint64_t)freq;
}

static uint64_t serial_uptime_millis(void)
{
    uint32_t freq = timer_frequency();
    if (freq == 0)
    {
        return 0;
    }
    uint64_t ticks = timer_ticks();
    return (ticks * 1000ULL) / (uint64_t)freq;
}

static void serial_log_prefix(void)
{
#if !SERIAL_LOG_PREFIX_ENABLE
    return;
#endif
    uint64_t wall_ms = serial_now_millis();
    uint64_t wall_seconds = wall_ms / 1000ULL;
    uint64_t millis_part = wall_ms % 1000ULL;
    uint64_t up_ms = serial_uptime_millis();
    uint64_t up_seconds = up_ms / 1000ULL;
    uint32_t cpu = smp_current_cpu_index();

    serial_output_char('[');
    serial_output_decimal(wall_seconds);
    serial_output_char('.');
    serial_output_char((char)('0' + (millis_part / 100ULL) % 10ULL));
    serial_output_char((char)('0' + (millis_part / 10ULL) % 10ULL));
    serial_output_char((char)('0' + (millis_part % 10ULL)));
    serial_output_char(']');
    serial_output_char('[');
    serial_output_char('u');
    serial_output_char('p');
    serial_output_char('=');
    serial_output_decimal(up_seconds);
    serial_output_char('s');
    serial_output_char(']');
    serial_output_char('[');
    serial_output_char('c');
    serial_output_char('p');
    serial_output_char('u');
    serial_output_decimal(cpu);
    serial_output_char(']');
    serial_output_char(' ');
}

static void serial_output_hex64(uint64_t value)
{
    static const char hex[] = "0123456789ABCDEF";
    for (int shift = 60; shift >= 0; shift -= 4)
    {
        serial_output_char(hex[(value >> shift) & 0xF]);
    }
}

static bool is_canonical(uint64_t addr)
{
    uint64_t mask = addr & CANONICAL_MASK;
    return mask == 0 || mask == CANONICAL_MASK;
}

typedef struct serial_output_context
{
    uint64_t caller;
} serial_output_context_t;

static void serial_report_invalid_pointer(uint64_t address, uint64_t caller)
{
    serial_output_char('!');
    serial_output_hex64(address);
    serial_output_char('@');
    serial_output_hex64(caller);
    serial_output_char('\n');
    for (;;)
    {
        __asm__ volatile ("hlt");
    }
}

static bool serial_validate_pointer_with_caller(const void *ptr, uint64_t caller)
{
    if (!ptr)
    {
        return true;
    }
    uint64_t addr = (uint64_t)(uintptr_t)ptr;
    if (!is_canonical(addr))
    {
        serial_report_invalid_pointer(addr, caller);
        return false;
    }
    return true;
}

static bool serial_validate_string_pointer(void *ctx, const void *ptr)
{
    if (!ptr)
    {
        return true;
    }
    const serial_output_context_t *info = (const serial_output_context_t *)ctx;
    uint64_t caller = info ? info->caller : 0;
    return serial_validate_pointer_with_caller(ptr, caller);
}

static void serial_putc_adapter(void *ctx, char c)
{
    (void)ctx;
    if (c == '\n')
    {
        serial_output_char('\r');
    }
    serial_output_char(c);
}

static void serial_vprintf_locked(const char *format, va_list args, uint64_t caller)
{
    if (!serial_validate_pointer_with_caller(format, caller))
    {
        return;
    }
    serial_output_context_t ctx_data = {
        .caller = caller
    };
    serial_format_ctx_t ctx = {
        .putc = serial_putc_adapter,
        .validate = serial_validate_string_pointer,
        .ctx = &ctx_data,
        .count = 0,
        .error = false
    };
    serial_format_vprintf(&ctx, format, args);
}

void serial_printf(const char *format, ...)
{
    if (!format)
    {
        return;
    }
    serial_log_lock();
    serial_log_prefix();
    va_list args;
    va_start(args, format);
    uint64_t caller = (uint64_t)__builtin_return_address(0);
    serial_vprintf_locked(format, args, caller);
    va_end(args);
    size_t fmt_len = strlen(format);
    bool has_trailing_nl = (fmt_len > 0 && format[fmt_len - 1] == '\n');
    if (!has_trailing_nl)
    {
        serial_output_char('\r');
        serial_output_char('\n');
    }
    serial_log_unlock();
}

void serial_output_bytes(const char *data, size_t length)
{
    if (!data || length == 0)
    {
        return;
    }
    serial_log_lock();
    for (size_t i = 0; i < length; ++i)
    {
        serial_output_char(data[i]);
    }
    serial_log_unlock();
}

char serial_read_char(void)
{
    while (!serial_receive_ready())
    {
    }
    return (char)inb(COM1);
}

bool serial_has_char(void)
{
    return serial_receive_ready() != 0;
}

bool serial_is_ready(void)
{
    return serial_transmit_ready() != 0;
}

static void serial_early_hw_write_char(char c)
{
    /* Bypass locks/queue: poll the UART directly. */
    while (!serial_transmit_ready())
    {
    }
    outb(COM1, (uint8_t)c);
}

void serial_early_write_string(const char *s)
{
    if (!s)
    {
        return;
    }
    for (const char *p = s; *p; ++p)
    {
        if (*p == '\n')
        {
            serial_early_hw_write_char('\r');
        }
        serial_early_hw_write_char(*p);
    }
}

static void serial_worker_entry(void *arg)
{
    (void)arg;
    while (1)
    {
        char ch;
        if (!serial_queue_pop(&ch))
        {
            process_sleep_ms(1);
            continue;
        }
        serial_hw_write_char(ch);
    }
}

void serial_start_async_worker(void)
{
    if (g_serial_worker_started)
    {
        return;
    }
    process_t *proc = process_create_kernel("seriald",
                                            serial_worker_entry,
                                            NULL,
                                            PROCESS_DEFAULT_STACK_SIZE,
                                            -1);
    if (proc)
    {
        g_serial_worker_started = true;
        g_serial_async_enabled = true;
    }
}

static void serial_log_lock(void)
{
    uint32_t cpu = smp_current_cpu_index();
    if (g_serial_output_owner == cpu)
    {
        g_serial_output_depth++;
        return;
    }
    uint64_t flags = serial_cpu_save_flags();
    serial_cpu_cli();
    spinlock_lock(&g_serial_output_lock);
    g_serial_output_owner = cpu;
    g_serial_output_depth = 1;
    if (cpu < SMP_MAX_CPUS)
    {
        g_serial_output_saved_flags[cpu] = flags;
    }
}

static void serial_log_unlock(void)
{
    uint32_t cpu = smp_current_cpu_index();
    if (g_serial_output_owner != cpu || g_serial_output_depth == 0)
    {
        spinlock_unlock(&g_serial_output_lock);
        return;
    }
    g_serial_output_depth--;
    if (g_serial_output_depth == 0)
    {
        g_serial_output_owner = UINT32_MAX;
        uint64_t flags = 0;
        if (cpu < SMP_MAX_CPUS)
        {
            flags = g_serial_output_saved_flags[cpu];
        }
        spinlock_unlock(&g_serial_output_lock);
        serial_cpu_restore_flags(flags);
    }
}
