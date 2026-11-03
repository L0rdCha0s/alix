#include "syslog.h"
#include "alix_mutex.h"
#include "errno.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "time.h"
#include "unistd.h"
#include "usyscall.h"

#define LOG_IDENT_CAPACITY 256u
static alix_mutex_t log_settings_lock;
static char log_ident[LOG_IDENT_CAPACITY];
static int log_options, log_facility = LOG_USER;
static unsigned log_mask = 0xff;
typedef struct
{
    char ident[LOG_IDENT_CAPACITY], pid[32];
    char format[SYSCALL_LOG_MAX_BYTES], message[SYSCALL_LOG_MAX_BYTES], record[SYSCALL_LOG_MAX_BYTES];
    int options, facility;
} syslog_work_t;

void openlog(const char *ident, int options, int facility)
{
    int saved = errno;
    alix_mutex_lock(&log_settings_lock);
    size_t length = ident ? strnlen(ident, sizeof(log_ident) - 1) : 0;
    for (size_t index = 0; index < length; ++index)
        log_ident[index] = ident[index] == '\n' || ident[index] == '\r' ? '_' : ident[index];
    log_ident[length] = 0;
    log_options = options;
    if (!(facility & ~LOG_FACMASK) && LOG_FAC(facility) < LOG_NFACILITIES) log_facility = facility;
    alix_mutex_unlock(&log_settings_lock);
    errno = saved;
}

void closelog(void)
{
    int saved = errno;
    alix_mutex_lock(&log_settings_lock);
    log_ident[0] = 0; log_options = 0; log_facility = LOG_USER;
    alix_mutex_unlock(&log_settings_lock);
    errno = saved;
}

int setlogmask(int mask)
{
    return (int)(mask ? __atomic_exchange_n(&log_mask, (unsigned)mask & 0xffu, __ATOMIC_ACQ_REL) :
                       __atomic_load_n(&log_mask, __ATOMIC_ACQUIRE));
}

static bool expand_log_errno(char *output, const char *format, const char *error)
{
    size_t used = 0;
    while (*format)
    {
        if (format[0] == '%' && format[1] == '%')
        {
            if (used + 2 >= SYSCALL_LOG_MAX_BYTES) return false;
            output[used++] = *format++; output[used++] = *format++;
        }
        else if (format[0] == '%' && format[1] == 'm')
        {
            format += 2;
            for (const char *p = error; *p; ++p)
            {
                size_t count = *p == '%' ? 2 : 1;
                if (used + count >= SYSCALL_LOG_MAX_BYTES) return false;
                if (*p == '%') output[used++] = '%';
                output[used++] = *p;
            }
        }
        else
        {
            if (used + 1 >= SYSCALL_LOG_MAX_BYTES) return false;
            output[used++] = *format++;
        }
    }
    output[used] = 0;
    return true;
}

void vsyslog(int priority, const char *format, va_list arguments)
{
    int saved = errno;
    if (!format || (priority & ~(LOG_PRIMASK | LOG_FACMASK)) || LOG_FAC(priority) >= LOG_NFACILITIES ||
        !(__atomic_load_n(&log_mask, __ATOMIC_ACQUIRE) & LOG_MASK(LOG_PRI(priority)))) return;
    syslog_work_t *work = calloc(1, sizeof(*work));
    if (!work) { errno = saved; return; }
    alix_mutex_lock(&log_settings_lock);
    memcpy(work->ident, log_ident, sizeof(work->ident));
    work->options = log_options; work->facility = log_facility;
    alix_mutex_unlock(&log_settings_lock);
    if (!(priority & LOG_FACMASK)) priority |= work->facility;
    int length;
    if (!expand_log_errno(work->format, format, strerror(saved)))
    {
        strcpy(work->message, "[syslog format exceeds limit]");
        length = (int)strlen(work->message);
    }
    else
    {
        va_list copy; va_copy(copy, arguments);
        length = vsnprintf(work->message, sizeof(work->message), work->format, copy);
        va_end(copy);
    }
    if (length < 0) { free(work); errno = saved; return; }
    if ((size_t)length >= sizeof(work->message)) length = sizeof(work->message) - 1;
    if (work->options & LOG_PID) snprintf(work->pid, sizeof(work->pid), "%d", getpid());
    int prefix = snprintf(work->record, sizeof(work->record), "<%d>%lld%s%s%s%s%s: ", priority,
        (long long)time(NULL), work->ident[0] || work->pid[0] ? " " : "", work->ident,
        work->pid[0] ? "[" : "", work->pid, work->pid[0] ? "]" : "");
    if (prefix < 0 || (size_t)prefix >= sizeof(work->record) - 1) { free(work); errno = saved; return; }
    size_t used = (size_t)prefix;
    for (int index = 0; index < length && used < sizeof(work->record) - 1; ++index)
    {
        char value = work->message[index];
        work->record[used++] = !value || value == '\n' || value == '\r' ? ' ' : value;
    }
    work->record[used++] = '\n';
    int64_t result = sys_file_io(SYSCALL_FILE_LOG, (uintptr_t)work->record, used, 0, 0);
    if (result != (int64_t)used && (work->options & LOG_CONS)) (void)sys_serial_write(work->record, used);
    if (work->options & LOG_PERROR) (void)write(STDERR_FILENO, work->record, used);
    free(work);
    errno = saved;
}

void syslog(int priority, const char *format, ...)
{
    va_list arguments; va_start(arguments, format);
    vsyslog(priority, format, arguments);
    va_end(arguments);
}
