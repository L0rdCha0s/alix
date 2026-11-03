#ifndef ALIX_TIME_H
#define ALIX_TIME_H

#ifdef TTF_HOST_BUILD
#include_next <time.h>
#else
#include "types.h"

typedef int64_t time_t;
typedef int64_t clock_t;
typedef int clockid_t;
struct timespec { time_t tv_sec; long tv_nsec; };
struct tm
{
    int tm_sec, tm_min, tm_hour, tm_mday, tm_mon, tm_year;
    int tm_wday, tm_yday, tm_isdst;
    long tm_gmtoff;
    const char *tm_zone;
};
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID 3
#define TIME_UTC 1
#define CLOCKS_PER_SEC 1000

#ifdef __cplusplus
extern "C" {
#endif
int clock_gettime(clockid_t clock, struct timespec *value);
int clock_getres(clockid_t clock, struct timespec *value);
clock_t clock(void);
int timespec_get(struct timespec *value, int base);
int nanosleep(const struct timespec *duration, struct timespec *remaining);
time_t time(time_t *result);
double difftime(time_t end, time_t beginning);
struct tm *gmtime_r(const time_t *value, struct tm *result);
struct tm *gmtime(const time_t *value);
time_t timegm(struct tm *value);
char *asctime_r(const struct tm *value, char *output);
char *asctime(const struct tm *value);
struct tm *localtime_r(const time_t *value, struct tm *result);
struct tm *localtime(const time_t *value);
time_t mktime(struct tm *value);
char *ctime_r(const time_t *value, char *output);
char *ctime(const time_t *value);
size_t strftime(char *output, size_t size, const char *format, const struct tm *value);
char *strptime(const char *input, const char *format, struct tm *value);
void tzset(void);
extern long timezone;
extern int daylight;
extern char *tzname[2];
#ifdef __cplusplus
}
#endif
#endif
#endif
