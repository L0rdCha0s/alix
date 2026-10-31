#!/usr/bin/env python3
"""Run the production UTC calendar and C locale modules against host references."""
from pathlib import Path
import os
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CC = shlex.split(os.environ.get("HOST_CC", "cc"))
CALENDAR_SYMBOLS = ("gmtime_r", "gmtime", "timegm", "asctime_r", "asctime")

HARNESS = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <locale.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct tm *alix_gmtime_r(const time_t *, struct tm *);
struct tm *alix_gmtime(const time_t *);
time_t alix_timegm(struct tm *);
char *alix_asctime_r(const struct tm *, char *);
char *alix_asctime(const struct tm *);
char *alix_setlocale(int, const char *);
struct lconv *alix_localeconv(void);

static void equal_tm(const struct tm *a, const struct tm *b)
{
    assert(a->tm_year == b->tm_year && a->tm_mon == b->tm_mon && a->tm_mday == b->tm_mday);
    assert(a->tm_hour == b->tm_hour && a->tm_min == b->tm_min && a->tm_sec == b->tm_sec);
    assert(a->tm_wday == b->tm_wday && a->tm_yday == b->tm_yday && a->tm_isdst == b->tm_isdst);
}

static void check_timestamp(time_t value)
{
    struct tm ours, expected;
    assert(gmtime_r(&value, &expected));
    errno = EDOM;
    assert(alix_gmtime_r(&value, &ours) == &ours && errno == EDOM);
    equal_tm(&ours, &expected);
    assert(alix_timegm(&ours) == value && errno == EDOM);
    equal_tm(&ours, &expected);
    if (ours.tm_year >= -900 && ours.tm_year <= 8099) {
        char actual[26], reference[40];
        assert(alix_asctime_r(&ours, actual) == actual);
        assert(asctime_r(&expected, reference));
        assert(strcmp(actual, reference) == 0 && strlen(actual) == 25);
    }
}

static uint64_t random_state = 0x36fadb17c45a91e3ULL;
static uint64_t next_random(void)
{
    random_state ^= random_state << 13;
    random_state ^= random_state >> 7;
    random_state ^= random_state << 17;
    return random_state;
}

static void test_calendar(void)
{
    const time_t samples[] = {
        -62167219200LL, -62135596800LL, -30610224000LL, -2208988801LL,
        -2208988800LL, -1, 0, 1, 86399, 86400, 951782399, 951782400,
        2147483647, 2147483648LL, 4107542400LL, 13574563200LL, 253402300799LL
    };
    for (unsigned i = 0; i < sizeof(samples) / sizeof(samples[0]); ++i) check_timestamp(samples[i]);
    for (unsigned i = 0; i < 50000; ++i) {
        time_t t = (time_t)(next_random() % 60000000000000ULL) - 30000000000000LL;
        check_timestamp(t);
        /* Darwin timegm rejects pre-1900 input even though its gmtime accepts
         * it. Negative-era coverage above uses gmtime plus inverse checks;
         * compare normalization only where both host implementations work. */
        struct tm input = {.tm_year=(int)(next_random() % 20000) + 100,
                           .tm_mon=(int)(next_random() % 240) - 120,
                           .tm_mday=(int)(next_random() % 1600) - 800,
                           .tm_hour=(int)(next_random() % 400) - 200,
                           .tm_min=(int)(next_random() % 600) - 300,
                           .tm_sec=(int)(next_random() % 1000) - 500,
                           .tm_isdst=1};
        struct tm original = input, reference = input;
        time_t actual = alix_timegm(&input), expected = timegm(&reference);
        if (actual != expected) {
            fprintf(stderr, "timegm mismatch input y=%d m=%d d=%d h=%d min=%d s=%d dst=%d actual=%lld expected=%lld\n",
                    original.tm_year, original.tm_mon, original.tm_mday, original.tm_hour,
                    original.tm_min, original.tm_sec, original.tm_isdst,
                    (long long)actual, (long long)expected);
        }
        assert(actual == expected);
        equal_tm(&input, &reference);
    }
    struct tm output, untouched;
    memset(&untouched, 0xa5, sizeof(untouched));
    for (unsigned i = 0; i < 2; ++i) {
        time_t limit = i ? INT64_MAX : INT64_MIN;
        output = untouched; errno = 0;
        assert(!alix_gmtime_r(&limit, &output) && errno == EOVERFLOW);
        assert(!memcmp(&output, &untouched, sizeof(output)));
    }
    struct tm extreme = {.tm_year=INT_MIN, .tm_mon=0, .tm_mday=1};
    time_t first = alix_timegm(&extreme);
    assert(first != -1 && extreme.tm_year == INT_MIN);
    assert(alix_gmtime_r(&first, &output) && output.tm_year == INT_MIN);
    --first;
    assert(!alix_gmtime_r(&first, &output) && errno == EOVERFLOW);
    extreme = (struct tm){.tm_year=INT_MAX, .tm_mon=11, .tm_mday=31,
                         .tm_hour=23, .tm_min=59, .tm_sec=59};
    time_t last = alix_timegm(&extreme);
    assert(last != -1 && extreme.tm_year == INT_MAX);
    ++last;
    assert(!alix_gmtime_r(&last, &output) && errno == EOVERFLOW);
    extreme = (struct tm){.tm_year=INT_MAX, .tm_mon=12, .tm_mday=1};
    untouched = extreme;
    assert(alix_timegm(&extreme) == -1 && errno == EOVERFLOW);
    assert(!memcmp(&extreme, &untouched, sizeof(extreme)));
    time_t negative_one = -1;
    assert(alix_gmtime_r(&negative_one, &output));
    errno = EDOM;
    assert(alix_timegm(&output) == -1 && errno == EDOM);
    assert(!alix_gmtime_r(NULL, &output) && errno == EINVAL);
    assert(!alix_gmtime_r(&negative_one, NULL) && errno == EINVAL);
    assert(alix_timegm(NULL) == -1 && errno == EINVAL);

    output = (struct tm){.tm_year=-1900, .tm_mon=0, .tm_mday=1, .tm_wday=6};
    char text[27]; memset(text, '#', sizeof(text));
    assert(alix_asctime_r(&output, text) == text);
    assert(!strcmp(text, "Sat Jan  1 00:00:00    0\n") && text[26] == '#');
    output.tm_year = -901;
    assert(alix_asctime_r(&output, text) && !strcmp(text + 20, " 999\n"));
    output.tm_year = 8099;
    assert(alix_asctime_r(&output, text) && !strcmp(text + 20, "9999\n"));
    output.tm_year = 8100;
    memset(text, '#', sizeof(text));
    assert(!alix_asctime_r(&output, text) && errno == EOVERFLOW && text[0] == '#');
    output.tm_year = 70; output.tm_wday = 7;
    assert(!alix_asctime_r(&output, text) && errno == EINVAL && text[0] == '#');
}

static struct worker { time_t value; struct tm *calendar; char *text; } workers[8];
static unsigned ready, release_workers;
static void *worker(void *argument)
{
    struct worker *state = argument;
    state->calendar = alix_gmtime(&state->value);
    assert(state->calendar);
    state->text = alix_asctime(state->calendar);
    assert(state->text);
    __atomic_add_fetch(&ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&release_workers, __ATOMIC_ACQUIRE)) sched_yield();
    struct tm expected;
    assert(gmtime_r(&state->value, &expected));
    equal_tm(state->calendar, &expected);
    char reference[26]; assert(asctime_r(&expected, reference));
    assert(!strcmp(state->text, reference));
    return NULL;
}

static void test_thread_storage(void)
{
    pthread_t threads[8];
    for (unsigned i = 0; i < 8; ++i) {
        workers[i].value = 1000000000 + i * 86400;
        assert(!pthread_create(&threads[i], NULL, worker, &workers[i]));
    }
    while (__atomic_load_n(&ready, __ATOMIC_ACQUIRE) != 8) sched_yield();
    time_t zero = 0;
    struct tm *main_tm = alix_gmtime(&zero);
    char *main_text = alix_asctime(main_tm);
    for (unsigned i = 0; i < 8; ++i) {
        assert(workers[i].calendar != main_tm && workers[i].text != main_text);
        for (unsigned j = 0; j < i; ++j)
            assert(workers[i].calendar != workers[j].calendar && workers[i].text != workers[j].text);
    }
    __atomic_store_n(&release_workers, 1, __ATOMIC_RELEASE);
    for (unsigned i = 0; i < 8; ++i) assert(!pthread_join(threads[i], NULL));
}

static void test_locale(void)
{
    const int categories[] = {LC_ALL, LC_COLLATE, LC_CTYPE, LC_MONETARY, LC_NUMERIC, LC_TIME, LC_MESSAGES};
    const char *variables[] = {"LC_ALL", "LC_COLLATE", "LC_CTYPE", "LC_MONETARY", "LC_NUMERIC", "LC_TIME", "LC_MESSAGES", "LANG"};
    for (unsigned i = 0; i < sizeof(variables) / sizeof(variables[0]); ++i) assert(!unsetenv(variables[i]));
    for (unsigned i = 0; i < sizeof(categories) / sizeof(categories[0]); ++i) {
        assert(!strcmp(alix_setlocale(categories[i], NULL), "C"));
        assert(!strcmp(alix_setlocale(categories[i], "C"), "C"));
        assert(!strcmp(alix_setlocale(categories[i], "POSIX"), "C"));
        assert(!strcmp(alix_setlocale(categories[i], ""), "C"));
        assert(!alix_setlocale(categories[i], "en_US.UTF-8"));
        assert(!alix_setlocale(categories[i], "C.UTF-8"));
    }
    assert(!alix_setlocale(-1, NULL) && !alix_setlocale(INT_MAX, "C"));
    assert(!setenv("LANG", "unsupported", 1));
    assert(!alix_setlocale(LC_ALL, "") && !alix_setlocale(LC_TIME, ""));
    assert(!strcmp(alix_setlocale(LC_ALL, NULL), "C"));
    assert(!setenv("LC_TIME", "C", 1));
    assert(alix_setlocale(LC_TIME, "") && !alix_setlocale(LC_ALL, ""));
    assert(!setenv("LC_ALL", "POSIX", 1));
    assert(alix_setlocale(LC_ALL, ""));
    assert(!setenv("LC_ALL", "", 1));
    assert(!alix_setlocale(LC_ALL, ""));
    assert(!setenv("LANG", "C", 1) && !setenv("LC_MESSAGES", "missing", 1));
    assert(!alix_setlocale(LC_ALL, "") && alix_setlocale(LC_TIME, ""));
    assert(!setenv("LC_MESSAGES", "", 1));
    assert(alix_setlocale(LC_ALL, ""));
    assert(setlocale(LC_ALL, "C"));
    struct lconv *a = alix_localeconv(), *b = localeconv();
#define MATCH_STRING(field) assert(!strcmp(a->field, b->field))
    MATCH_STRING(decimal_point); MATCH_STRING(thousands_sep); MATCH_STRING(grouping);
    MATCH_STRING(int_curr_symbol); MATCH_STRING(currency_symbol); MATCH_STRING(mon_decimal_point);
    MATCH_STRING(mon_thousands_sep); MATCH_STRING(mon_grouping); MATCH_STRING(positive_sign); MATCH_STRING(negative_sign);
#define MATCH_CHAR(field) assert(a->field == b->field && a->field == CHAR_MAX)
    MATCH_CHAR(int_frac_digits); MATCH_CHAR(frac_digits); MATCH_CHAR(p_cs_precedes); MATCH_CHAR(p_sep_by_space);
    MATCH_CHAR(n_cs_precedes); MATCH_CHAR(n_sep_by_space); MATCH_CHAR(p_sign_posn); MATCH_CHAR(n_sign_posn);
    MATCH_CHAR(int_p_cs_precedes); MATCH_CHAR(int_p_sep_by_space); MATCH_CHAR(int_n_cs_precedes);
    MATCH_CHAR(int_n_sep_by_space); MATCH_CHAR(int_p_sign_posn); MATCH_CHAR(int_n_sign_posn);
}

int main(void)
{
    test_calendar();
    test_thread_storage();
    test_locale();
    puts("Calendar/locale production contracts: PASS references=100000 threads=8");
}
'''

with tempfile.TemporaryDirectory(prefix="alix-calendar-locale-") as directory:
    folder = Path(directory)
    harness = folder / "test.c"
    harness.write_text(HARNESS)
    flags = ["-std=c11", "-D_DARWIN_C_SOURCE", "-D_DEFAULT_SOURCE", "-D_GNU_SOURCE",
             "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-g", "-pthread"]
    for module, symbols in (("calendar", CALENDAR_SYMBOLS), ("locale", ("setlocale", "localeconv"))):
        # Host ABI headers provide the host's struct tm and TLS errno. Alix's
        # native errno numbers/storage differ; those are checked by native make.
        subprocess.run(CC + flags +
                       [f"-D{name}=alix_{name}" for name in symbols] +
                       ["-c", str(ROOT / "user/lib" / (module + ".c")),
                        "-o", str(folder / (module + ".o"))], check=True)
    binary = folder / "test"
    subprocess.run(CC + flags + [str(harness), str(folder / "calendar.o"),
                                str(folder / "locale.o"), "-o", str(binary)], check=True)
    subprocess.run([str(binary)], check=True)
