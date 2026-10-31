#include "userlib.h"
#include "time.h"
#include "sys/time.h"
#include "locale.h"
#include "errno.h"
#include "serial.h"

#define WORKERS 8u
#define CHECK(condition, label) do { if (!(condition)) { \
    serial_printf("CALENDAR_LOCALE_TEST: FAIL %s\n", label); return 1; } } while (0)

typedef struct
{
    alix_thread_t thread;
    unsigned index, failed, cpu_mask;
    uintptr_t calendar_address, text_address;
    syscall_timezone_info_t timezone;
} calendar_worker_t;
static unsigned ready, release_workers;

static void calendar_worker(void *argument)
{
    calendar_worker_t *state = argument;
    time_t input = (time_t)state->index * 86400;
    struct tm *calendar = gmtime(&input);
    state->calendar_address = (uintptr_t)calendar;
    char *text = calendar ? asctime(calendar) : NULL;
    state->text_address = (uintptr_t)text;
    if (!calendar || !text) state->failed = 1;
    errno = (int)(100 + state->index);
    __atomic_add_fetch(&ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&release_workers, __ATOMIC_ACQUIRE)) sys_yield();
    for (unsigned cpu = 0; cpu < WORKERS; ++cpu)
    {
        if (sys_thread_set_affinity(cpu) || sys_thread_cpu() != cpu ||
            !calendar || calendar->tm_mday != (int)(state->index + 1) ||
            calendar->tm_year != 70 || calendar->tm_mon != 0 ||
            !text || text[9] != (char)('1' + state->index) ||
            errno != (int)(100 + state->index)) state->failed = 1;
        if (sys_timezone_info(&state->timezone, sizeof(state->timezone)) != 0 ||
            state->timezone.version != SYSCALL_TIMEZONE_VERSION ||
            state->timezone.size != 328 || state->timezone.kind != SYSCALL_TIMEZONE_FIXED ||
            state->timezone.standard_offset_seconds != 0 || state->timezone.dst_offset_seconds != 0 ||
            state->timezone.flags != 0 || state->timezone.generation == 0 ||
            strcmp(state->timezone.display_name, "UTC") || state->timezone.zone_id[0]) state->failed = 1;
        state->cpu_mask |= 1u << cpu;
    }
}

int main(void)
{
    struct timeval *wall = calloc(1, sizeof(*wall));
    syscall_timezone_info_t *zone = calloc(1, sizeof(*zone));
    CHECK(wall && zone, "time query allocations");
    uint64_t before = sys_time_millis();
    CHECK(gettimeofday(wall, NULL) == 0, "gettimeofday");
    uint64_t after = sys_time_millis();
    uint64_t measured = (uint64_t)wall->tv_sec * 1000 + (uint64_t)wall->tv_usec / 1000;
    CHECK(wall->tv_sec >= 0 && wall->tv_usec >= 0 && wall->tv_usec < 1000000 &&
          wall->tv_usec % 1000 == 0 && measured >= before && measured <= after,
          "wall-clock syscall bracket and millisecond resolution");
    CHECK(sizeof(*zone) == 328 && sys_timezone_info(zone, sizeof(*zone)) == 0 &&
          zone->version == 1 && zone->size == 328 && zone->kind <= SYSCALL_TIMEZONE_IANA &&
          zone->generation != 0 && zone->flags == 0 &&
          memchr(zone->zone_id, 0, sizeof(zone->zone_id)) &&
          memchr(zone->display_name, 0, sizeof(zone->display_name)) &&
          zone->standard_offset_seconds >= -86400 && zone->standard_offset_seconds <= 86400 &&
          zone->dst_offset_seconds >= -86400 && zone->dst_offset_seconds <= 86400,
          "timezone snapshot wire");
    CHECK(sys_timezone_info(zone, sizeof(*zone) - 1) == -EINVAL &&
          sys_timezone_info(NULL, sizeof(*zone)) == -EFAULT, "timezone invalid outputs");
    free(zone); free(wall);
    time_t epoch = -1;
    struct tm calendar;
    CHECK(gmtime_r(&epoch, &calendar) == &calendar && calendar.tm_year == 69 &&
          calendar.tm_mon == 11 && calendar.tm_mday == 31 && calendar.tm_sec == 59 &&
          calendar.tm_wday == 3 && calendar.tm_yday == 364 && calendar.tm_gmtoff == 0 &&
          calendar.tm_zone && !strcmp(calendar.tm_zone, "UTC"), "negative epoch");
    errno = EDOM;
    CHECK(timegm(&calendar) == -1 && errno == EDOM, "valid minus-one epoch");
    calendar = (struct tm){.tm_year=100, .tm_mon=1, .tm_mday=29};
    CHECK(timegm(&calendar) == 951782400 && calendar.tm_yday == 59, "Gregorian leap year");
    calendar = (struct tm){.tm_year=200, .tm_mon=1, .tm_mday=29};
    CHECK(timegm(&calendar) == 4107542400LL && calendar.tm_mon == 2 &&
          calendar.tm_mday == 1, "non-leap century normalization");
    epoch = 0x7fffffffffffffffLL;
    CHECK(!gmtime_r(&epoch, &calendar) && errno == EOVERFLOW, "unrepresentable tm_year");
    calendar = (struct tm){.tm_year=-1900, .tm_mon=0, .tm_mday=1, .tm_wday=6};
    char text[26];
    CHECK(asctime_r(&calendar, text) && !strcmp(text, "Sat Jan  1 00:00:00    0\n"), "asctime year padding");

    CHECK(setlocale(LC_ALL, "C") && !setlocale(LC_TIME, "en_AU.UTF-8") &&
          !strcmp(setlocale(LC_TIME, NULL), "C"), "unsupported locale preserves state");
    CHECK(setenv("LANG", "unsupported", 1) == 0 && !setlocale(LC_ALL, ""), "LANG resolution");
    CHECK(setenv("LC_ALL", "POSIX", 1) == 0 && setlocale(LC_ALL, ""), "LC_ALL precedence");
    struct lconv *convention = localeconv();
    CHECK(convention && !strcmp(convention->decimal_point, ".") &&
          !*convention->thousands_sep && !*convention->grouping &&
          convention->frac_digits == 127 && convention->int_n_sign_posn == 127,
          "C numeric and monetary conventions");

    calendar_worker_t *workers = calloc(WORKERS, sizeof(*workers));
    CHECK(workers, "worker allocation");
    for (unsigned i = 0; i < WORKERS; ++i)
    {
        workers[i].index = i;
        CHECK(alix_thread_create(&workers[i].thread, "calendar", calendar_worker, &workers[i]) == 0,
              "thread creation");
    }
    while (__atomic_load_n(&ready, __ATOMIC_ACQUIRE) != WORKERS) sys_yield();
    __atomic_store_n(&release_workers, 1, __ATOMIC_RELEASE);
    for (unsigned i = 0; i < WORKERS; ++i)
    {
        CHECK(alix_thread_join(workers[i].thread, NULL) == 0, "join");
        CHECK(!workers[i].failed && workers[i].cpu_mask == 0xFF, "private time storage across CPUs");
        for (unsigned j = 0; j < i; ++j)
            CHECK(workers[i].calendar_address != workers[j].calendar_address &&
                  workers[i].text_address != workers[j].text_address, "distinct thread buffers");
    }
    free(workers);
    serial_printf("CALENDAR_LOCALE_TEST: PASS workers=8 cpu_mask=0xFF utc=1 locale=1 wall=1 snapshot=1\n");
    return 0;
}
