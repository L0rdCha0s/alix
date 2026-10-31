#!/usr/bin/env python3
"""Exercise native timezone/formatting code using host clocks/files as references."""
from pathlib import Path
import os
import shlex
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
CC = shlex.split(os.environ.get("HOST_CC", "cc"))
WIRE = (ROOT / "include/syscall_defs.h").read_text()
WIRE = WIRE[WIRE.index("#define SYSCALL_TIMEZONE_VERSION"):WIRE.index("#define SYSCALL_VM_PROT_NONE")]
PLATFORM = r'''
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
''' + WIRE + r'''
#define SYSCALL_OPEN_READ 1u
typedef struct { unsigned value; } alix_mutex_t;
void alix_mutex_lock(alix_mutex_t *);
void alix_mutex_unlock(alix_mutex_t *);
int sys_timezone_info(syscall_timezone_info_t *, size_t);
int sys_open(const char *, uint64_t);
ssize_t sys_read(int, void *, size_t);
int sys_close(int);
'''

HARNESS = r'''
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "platform.h"
#include "timezone_fixtures.h"
struct tm *alix_localtime_r(const time_t *, struct tm *);
time_t alix_mktime(struct tm *);
void alix_tzset(void);
size_t alix_strftime(char *, size_t, const char *, const struct tm *);
extern long alix_timezone;
extern int alix_daylight;
extern char *alix_tzname[2];
void alix_test_reference_limit(void);
static pthread_mutex_t snapshot_lock = PTHREAD_MUTEX_INITIALIZER;
static syscall_timezone_info_t snapshot = {.version=1,.size=328,.generation=1,.kind=0,.display_name="UTC"};
static int fail_open, fail_read, interrupt_read;
static unsigned open_count, close_count, query_count;
typedef union { max_align_t alignment; size_t size; } allocation_header_t;
static long allocation_failure = -1;
static unsigned long live_allocations;
void *alix_malloc(size_t size)
{
    long remaining=__atomic_load_n(&allocation_failure,__ATOMIC_RELAXED);
    if (remaining >= 0 && __atomic_fetch_sub(&allocation_failure,1,__ATOMIC_RELAXED)==0) return NULL;
    if (size > SIZE_MAX-sizeof(allocation_header_t)) return NULL;
    allocation_header_t *block=malloc(sizeof(*block)+size); if (!block) return NULL;
    block->size=size; __atomic_add_fetch(&live_allocations,1,__ATOMIC_RELAXED); return block+1;
}
void *alix_calloc(size_t count,size_t size)
{
    if (count && size>SIZE_MAX/count) return NULL;
    void *result=alix_malloc(count*size); if(result) memset(result,0,count*size); return result;
}
void alix_free(void *pointer)
{
    if(pointer) { __atomic_sub_fetch(&live_allocations,1,__ATOMIC_RELAXED); free((allocation_header_t *)pointer-1); }
}
void alix_mutex_lock(alix_mutex_t *lock) { while (__atomic_exchange_n(&lock->value, 1, __ATOMIC_ACQUIRE)) sched_yield(); }
void alix_mutex_unlock(alix_mutex_t *lock) { __atomic_store_n(&lock->value, 0, __ATOMIC_RELEASE); }
int sys_timezone_info(syscall_timezone_info_t *out, size_t size)
{
    assert(size == 328); __atomic_add_fetch(&query_count, 1, __ATOMIC_RELAXED);
    pthread_mutex_lock(&snapshot_lock); *out = snapshot; pthread_mutex_unlock(&snapshot_lock); return 0;
}
int sys_open(const char *path, uint64_t flags)
{
    assert(flags == 1); if (fail_open) return -EIO;
    int fd = open(path, O_RDONLY); if (fd < 0) return -errno;
    ++open_count; return fd;
}
ssize_t sys_read(int fd, void *out, size_t size)
{
    if (fail_read) return -EIO;
    if (interrupt_read) { --interrupt_read; return -EINTR; }
    if (size > 137) size = 137;
    ssize_t result = read(fd, out, size); return result < 0 ? -errno : result;
}
int sys_close(int fd) { ++close_count; return close(fd); }

static void equal_tm(const struct tm *a, const struct tm *b)
{
    if (a->tm_year != b->tm_year || a->tm_mon != b->tm_mon || a->tm_mday != b->tm_mday ||
        a->tm_hour != b->tm_hour || a->tm_min != b->tm_min || a->tm_sec != b->tm_sec ||
        a->tm_isdst != b->tm_isdst || a->tm_gmtoff != b->tm_gmtoff)
        fprintf(stderr, "date mismatch TZ=%s actual=%d-%d-%d %d:%d:%d dst%d off%ld expected=%d-%d-%d %d:%d:%d dst%d off%ld\n",
                getenv("TZ"), a->tm_year,a->tm_mon,a->tm_mday,a->tm_hour,a->tm_min,a->tm_sec,a->tm_isdst,a->tm_gmtoff,
                b->tm_year,b->tm_mon,b->tm_mday,b->tm_hour,b->tm_min,b->tm_sec,b->tm_isdst,b->tm_gmtoff);
    assert(a->tm_year == b->tm_year && a->tm_mon == b->tm_mon && a->tm_mday == b->tm_mday);
    assert(a->tm_hour == b->tm_hour && a->tm_min == b->tm_min && a->tm_sec == b->tm_sec);
    assert(a->tm_wday == b->tm_wday && a->tm_yday == b->tm_yday && a->tm_isdst == b->tm_isdst);
    assert(a->tm_gmtoff == b->tm_gmtoff && !strcmp(a->tm_zone, b->tm_zone));
}

static void compare(time_t value)
{
    struct tm actual, expected;
    assert(localtime_r(&value, &expected));
    errno = EDOM;
    assert(alix_localtime_r(&value, &actual) && errno == EDOM);
    equal_tm(&actual, &expected);
    const char *format = "%a %A %b %B %C %d %e %F %g %G %h %H %I %j %m %M %n %p %r %R %S %t %T %u %U %V %w %W %x %X %y %Y %%";
    char ours[512], host[512];
    assert(strftime(host, sizeof(host), format, &expected));
    assert(alix_strftime(ours, sizeof(ours), format, &actual));
    if (strcmp(ours, host)) fprintf(stderr, "format mismatch:\n%s\n%s\n", ours, host);
    assert(!strcmp(ours, host));
    /* Darwin strftime %z reuses the current standard offset for some historical
     * dates. The timestamp's independently verified tm_gmtoff is authoritative. */
    long magnitude = expected.tm_gmtoff < 0 ? -expected.tm_gmtoff : expected.tm_gmtoff;
    snprintf(host,sizeof(host),"%c%02ld%02ld %s",expected.tm_gmtoff < 0 ? '-' : '+',
             magnitude/3600,magnitude/60%60,expected.tm_zone);
    assert(alix_strftime(ours,sizeof(ours),"%z %Z",&actual) && !strcmp(ours,host));
    struct tm inverse = actual;
    errno = EDOM;
    time_t back = alix_mktime(&inverse);
    assert(back == value && errno == EDOM);
    equal_tm(&inverse, &actual);
}

static void test_zones(void)
{
    const char *zones[] = {"UTC0", "EST5EDT,M3.2.0/2,M11.1.0/2", "AEST-10AEDT-11,M10.1.0/2,M4.1.0/3",
                          "LHST-10:30LHDT-11,M10.1.0/2,M4.1.0/2", "ABC-5:45", "ABC3:12:34",
                          "America/New_York", "Australia/Sydney", "Australia/Lord_Howe", "Asia/Kathmandu", "Europe/Dublin"};
    for (unsigned zone = 0; zone < sizeof(zones) / sizeof(zones[0]); ++zone)
    {
        assert(!setenv("TZ", zones[zone], 1)); tzset(); alix_tzset();
        /* Darwin's explicit POSIX-TZ rules are not applied before 1970;
         * historical reference coverage uses named TZif zones instead. */
        time_t beginning = zone < 6 ? 31536000 : -2208988800LL;
        for (unsigned i = 0; i < 800; ++i) compare(beginning + (time_t)i * 9367921);
        const time_t transitions[] = {1173596399,1173596400,1194155999,1194156000,
                                     1696089599,1696089600,1712415599,1712415600,
                                     2147483647,2147483648LL,4107542400LL,7258118400LL};
        for (unsigned i = 0; i < sizeof(transitions) / sizeof(transitions[0]); ++i) compare(transitions[i]);
    }
    assert(!setenv("TZ", "EST5EDT,M3.2.0/2,M11.1.0/2", 1)); alix_tzset();
    assert(alix_timezone == 18000 && alix_daylight == 1 && !strcmp(alix_tzname[0], "EST") && !strcmp(alix_tzname[1], "EDT"));
    struct tm gap = {.tm_year=124,.tm_mon=2,.tm_mday=10,.tm_hour=2,.tm_min=30,.tm_isdst=-1};
    assert(alix_mktime(&gap) == 1710055800 && gap.tm_hour == 3 && gap.tm_min == 30 && gap.tm_isdst == 1);
    for (int dst = 0; dst <= 1; ++dst)
    {
        struct tm fold = {.tm_year=124,.tm_mon=10,.tm_mday=3,.tm_hour=1,.tm_min=30,.tm_isdst=dst};
        assert(alix_mktime(&fold) == (dst ? 1730611800 : 1730615400) && fold.tm_isdst == dst);
    }
    assert(!setenv("TZ", "America/New_York", 1)); alix_tzset();
    gap = (struct tm){.tm_year=124,.tm_mon=2,.tm_mday=10,.tm_hour=2,.tm_min=30,.tm_isdst=-1};
    assert(alix_mktime(&gap) == 1710055800 && gap.tm_hour == 3 && gap.tm_min == 30);
    for(int dst=0;dst<=1;++dst)
    {
        struct tm actual={.tm_year=124,.tm_mon=dst ? 0 : 6,.tm_mday=1,.tm_hour=12,.tm_isdst=dst};
        struct tm expected=actual; tzset();
        assert(alix_mktime(&actual)==mktime(&expected)); equal_tm(&actual,&expected);
    }
}

static void test_native(void)
{
    assert(!unsetenv("TZ"));
    pthread_mutex_lock(&snapshot_lock);
    snapshot.kind=1; snapshot.standard_offset_seconds=36000; snapshot.dst_offset_seconds=39600; ++snapshot.generation;
    snapshot.start=(syscall_timezone_rule_t){10,1,0,7200,0}; snapshot.end=(syscall_timezone_rule_t){4,1,0,10800,0};
    pthread_mutex_unlock(&snapshot_lock);
    time_t summer=1704067200, winter=1719792000;
    struct tm date;
    assert(alix_localtime_r(&summer,&date) && date.tm_gmtoff==39600 && date.tm_isdst==1 && date.tm_hour==11);
    assert(alix_localtime_r(&winter,&date) && date.tm_gmtoff==36000 && date.tm_isdst==0 && date.tm_hour==10);
    const char *saved_name = date.tm_zone;
    pthread_mutex_lock(&snapshot_lock); snapshot.kind=0; snapshot.standard_offset_seconds=20700; ++snapshot.generation; pthread_mutex_unlock(&snapshot_lock);
    assert(alix_localtime_r(&summer,&date) && date.tm_hour==5 && date.tm_min==45 && date.tm_gmtoff==20700);
    assert(!strcmp(saved_name,"UTC+10:00:00"));
}

static time_t utc(int year,int month,int day,int hour)
{
    struct tm value={.tm_year=year-1900,.tm_mon=month-1,.tm_mday=day,.tm_hour=hour};
    return timegm(&value);
}

static void test_rule_edges(void)
{
    struct tm date;
    time_t leap_day=utc(2024,2,29,12),march=utc(2024,3,1,12);
    assert(!setenv("TZ","AAA0BBB,J60/0,J300/0",1));
    assert(alix_localtime_r(&leap_day,&date) && date.tm_isdst==0);
    assert(alix_localtime_r(&march,&date) && date.tm_isdst==1);
    assert(!setenv("TZ","AAA0BBB,59/0,300/0",1));
    assert(alix_localtime_r(&leap_day,&date) && date.tm_isdst==1);
    assert(!setenv("TZ","ABC5DEF4,M3.1.0/2u,M11.1.0/2u",1));
    time_t before=utc(2024,3,3,2)-1,after=before+1;
    assert(alix_localtime_r(&before,&date) && date.tm_isdst==0);
    assert(alix_localtime_r(&after,&date) && date.tm_isdst==1);
    assert(!setenv("TZ","EST5EDT",1));
    after=utc(2024,7,1,0);
    assert(alix_localtime_r(&after,&date) && date.tm_isdst==1 && date.tm_gmtoff==-14400);
    assert(!setenv("TZ","AEST-10AEDT,M10.1.0/2,M4.1.0/3",1));
    after=utc(1900,1,1,0);
    assert(alix_localtime_r(&after,&date) && date.tm_isdst==1 && date.tm_hour==11);
}

static unsigned concurrent_ready, concurrent_start;
static void *concurrent_reader(void *unused)
{
    (void)unused; __atomic_add_fetch(&concurrent_ready,1,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&concurrent_start,__ATOMIC_ACQUIRE)) sched_yield();
    time_t epoch=1704067200;
    for(unsigned i=0;i<2000;++i)
    {
        struct tm date; assert(alix_localtime_r(&epoch,&date));
        assert(date.tm_gmtoff==3600 || date.tm_gmtoff==-18000 || date.tm_gmtoff==20700);
        assert(date.tm_isdst==0);
        char output[80]; assert(alix_strftime(output,sizeof(output),"%F %T %z %Z",&date));
        assert(date.tm_zone && !strncmp(date.tm_zone,"UTC",3));
    }
    return NULL;
}

static void test_concurrency(void)
{
    assert(!unsetenv("TZ"));
    pthread_mutex_lock(&snapshot_lock); snapshot.kind=0; snapshot.standard_offset_seconds=3600; ++snapshot.generation; pthread_mutex_unlock(&snapshot_lock);
    pthread_t threads[8];
    for(unsigned i=0;i<8;++i) assert(!pthread_create(&threads[i],NULL,concurrent_reader,NULL));
    while(__atomic_load_n(&concurrent_ready,__ATOMIC_ACQUIRE)!=8) sched_yield();
    __atomic_store_n(&concurrent_start,1,__ATOMIC_RELEASE);
    const int offsets[]={3600,-18000,20700};
    for(unsigned i=0;i<6000;++i)
    {
        pthread_mutex_lock(&snapshot_lock); snapshot.standard_offset_seconds=offsets[i%3]; ++snapshot.generation; pthread_mutex_unlock(&snapshot_lock);
        if(i%8==0) sched_yield();
    }
    for(unsigned i=0;i<8;++i) assert(!pthread_join(threads[i],NULL));
}

static void test_failures(int argc, char **argv)
{
    time_t value=1704067200;
    unsigned long before_invalid=live_allocations;
    for (int i=1;i<argc-2;++i)
    {
        char *selector=malloc(strlen(argv[i])+2); assert(selector); selector[0]=':'; strcpy(selector+1,argv[i]);
        assert(!setenv("TZ",selector,1)); free(selector);
        struct tm date, original; memset(&original,0xa5,sizeof(original)); date=original;
        errno=0; assert(!alix_localtime_r(&value,&date) && errno && !memcmp(&date,&original,sizeof(date)));
        assert(open_count==close_count);
        /* The final file is structurally valid but its post-table dates are
         * unspecified. Caching that valid state is different from a parse leak. */
        if(i!=argc-3) assert(live_allocations==before_invalid);
    }
    before_invalid=live_allocations;
    for(unsigned i=0;i<256;++i)
    {
        char selector[40]; snprintf(selector,sizeof(selector),"Bad%c%c999999",'A'+i/26,'A'+i%26);
        assert(!setenv("TZ",selector,1));
        struct tm date; assert(!alix_localtime_r(&value,&date));
        assert(live_allocations==before_invalid);
    }
    assert(!setenv("TZ","America/New_York",1)); interrupt_read=3; alix_tzset();
    fail_read=1; errno=0; alix_tzset(); assert(errno==EIO);
    struct tm date; assert(!alix_localtime_r(&value,&date) && errno==EIO);
    fail_read=0; assert(alix_localtime_r(&value,&date));
    fail_open=1; alix_tzset(); assert(errno==EIO); fail_open=0;
    assert(open_count==close_count);
    alix_tzset();
    unsigned long baseline=live_allocations;
    for(long failure=0;failure<20;++failure)
    {
        allocation_failure=failure; alix_tzset(); allocation_failure=-1;
        assert(live_allocations<=baseline && open_count==close_count);
        alix_tzset(); assert(live_allocations==baseline);
    }
    for(unsigned i=0;i<128;++i) { alix_tzset(); assert(live_allocations==baseline); }
    assert(!alix_localtime_r(NULL,&date) && errno==EINVAL);
    char output[5]="####";
    assert(!alix_strftime(output,4,"1234",&date) && output[0]==0 && output[4]==0);
    assert(!alix_strftime(NULL,0,"%Y",&date));
}

static void test_fixed_tzif(const char *path)
{
    char *selector=malloc(strlen(path)+2); assert(selector); selector[0]=':'; strcpy(selector+1,path);
    assert(!setenv("TZ",selector,1)); free(selector);
    const time_t values[]={-2208988800LL,0,2147483648LL,7258118400LL};
    for(unsigned i=0;i<sizeof(values)/sizeof(values[0]);++i)
    {
        struct tm date;
        assert(alix_localtime_r(&values[i],&date) && date.tm_gmtoff==741 && !strcmp(date.tm_zone,"TEST"));
    }
}

static void test_native_vectors(const char *binary_path)
{
    const struct { const unsigned char *data; size_t size; const timezone_sample_t *samples; size_t count; } fixtures[]={
        {timezone_new_york_bytes,sizeof(timezone_new_york_bytes),timezone_new_york_samples,sizeof(timezone_new_york_samples)/sizeof(timezone_new_york_samples[0])},
        {timezone_sydney_bytes,sizeof(timezone_sydney_bytes),timezone_sydney_samples,sizeof(timezone_sydney_samples)/sizeof(timezone_sydney_samples[0])},
        {timezone_lord_howe_bytes,sizeof(timezone_lord_howe_bytes),timezone_lord_howe_samples,sizeof(timezone_lord_howe_samples)/sizeof(timezone_lord_howe_samples[0])}
    };
    for(unsigned f=0;f<3;++f)
    {
        char path[1024]; snprintf(path,sizeof(path),"%s-zone%u",binary_path,f);
        FILE *file=fopen(path,"wb"); assert(file);
        assert(fwrite(fixtures[f].data,1,fixtures[f].size,file)==fixtures[f].size && !fclose(file));
        assert(!setenv("TZ",path,1));
        for(unsigned i=0;i<fixtures[f].count;++i)
        {
            const timezone_sample_t *sample=&fixtures[f].samples[i];
            time_t epoch=sample->epoch; struct tm date;
            assert(alix_localtime_r(&epoch,&date));
            assert(date.tm_year==sample->year-1900 && date.tm_mon==sample->month-1 && date.tm_mday==sample->day);
            assert(date.tm_hour==sample->hour && date.tm_min==sample->minute && date.tm_sec==sample->second);
            assert(date.tm_gmtoff==sample->offset && date.tm_isdst==sample->dst && !strcmp(date.tm_zone,sample->name));
            char text[128]; assert(alix_strftime(text,sizeof(text),"%Y-%m-%d %H:%M:%S %G-W%V-%u %z %Z",&date));
            assert(!strcmp(text,sample->formatted) && alix_mktime(&date)==epoch);
        }
    }
}

int main(int argc,char **argv)
{
    test_zones(); test_native(); test_rule_edges(); test_concurrency(); test_failures(argc,argv);
    test_fixed_tzif(argv[argc-2]); test_fixed_tzif(argv[argc-1]); alix_test_reference_limit();
    test_native_vectors(argv[0]);
    puts("Native timezone/TZif/strftime production contracts: PASS");
}
'''

def tzif(*, offset=0, dst=0, index=0, names=b"UTC\0", transitions=(), footer=b"UTC0", leap=0):
    def block(width):
        header = b"TZif2" + bytes(15) + struct.pack(">6I", 0, 0, leap, len(transitions), 1, len(names))
        times = b"".join(struct.pack(">q" if width == 8 else ">i", x) for x in transitions)
        return header + times + bytes(len(transitions)) + struct.pack(">iBB", offset, dst, index) + names + bytes(leap * (width + 4))
    return block(4) + block(8) + b"\n" + footer + b"\n"

with tempfile.TemporaryDirectory(prefix="alix-timezone-") as directory:
    folder=Path(directory)
    (folder/"platform.h").write_text(PLATFORM)
    (folder/"timezone_fixtures.h").write_bytes((ROOT/"tests/timezone_fixtures.h").read_bytes())
    (folder/"test.c").write_text(HARNESS)
    symbols=("gmtime", "gmtime_r", "timegm", "asctime", "asctime_r", "localtime", "localtime_r",
             "mktime", "ctime", "ctime_r", "strftime", "tzset", "timezone", "daylight", "tzname")
    flags=["-std=c11", "-D_DARWIN_C_SOURCE", "-D_GNU_SOURCE", "-D_DEFAULT_SOURCE", "-Wall", "-Wextra", "-Werror",
           "-g", "-pthread", "-fsanitize=address,undefined"]
    objects=[]
    for module in ("calendar", "timezone", "calendar_format"):
        text=(ROOT/"user/lib"/(module+".c")).read_text().replace('#include "timezone_platform.h"','#include "platform.h"')
        if module == "timezone":
            text += r'''
#include <assert.h>
void alix_test_reference_limit(void)
{
    alix_mutex_lock(&zone_lock);
    assert(zone_current);
    unsigned saved=zone_current->references;
    __atomic_store_n(&zone_current->references,UINT_MAX,__ATOMIC_RELAXED);
    alix_mutex_unlock(&zone_lock);
    errno=0;
    assert(!zone_acquire(0) && errno==EOVERFLOW);
    alix_mutex_lock(&zone_lock);
    __atomic_store_n(&zone_current->references,saved,__ATOMIC_RELAXED);
    alix_mutex_unlock(&zone_lock);
}
'''
        source=folder/(module+".c"); source.write_text(text)
        output=folder/(module+".o"); objects.append(str(output))
        subprocess.run(CC+flags+[f"-D{x}=alix_{x}" for x in symbols+("malloc","calloc","free")]+["-c",str(source),"-o",str(output)],check=True)
    binary=folder/"test"
    subprocess.run(CC+flags+[str(folder/"test.c")]+objects+["-o",str(binary)],check=True)
    malformed=[b"",b"not timezone",tzif()[:43],tzif()[:-1],tzif(dst=2),tzif(index=10),tzif(names=b"UTC"),
               tzif(offset=-(1<<31)),tzif(transitions=(10,9)),tzif(footer=b"EST5EDT,M13.1.0,M11.1.0"),
               tzif(footer=b"UTC0\nJUNK"),tzif(leap=1),tzif(transitions=(1,2),footer=b"")]
    paths=[]
    for i,data in enumerate(malformed):
        path=folder/f"bad{i}";path.write_bytes(data);paths.append(str(path))
    fixed=tzif(offset=741,names=b"TEST\0",footer=b"")
    for name,data in (("fixed-v2",fixed),("fixed-v1",fixed[:4]+b"\0"+fixed[5:55])):
        path=folder/name;path.write_bytes(data);paths.append(str(path))
    subprocess.run([str(binary)]+paths,check=True)
