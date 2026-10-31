#include "userlib.h"
#include "time.h"
#include "stdio.h"
#include "stdlib.h"
#include "errno.h"
#include "serial.h"
#include "timezone_fixtures.h"

#define CHECK(condition,label) do { if (!(condition)) { \
    serial_printf("TIMEZONE_TEST: FAIL %s\n",label); return 1; } } while(0)
#define WORKERS 8u

static int check_sample(const timezone_sample_t *sample, struct tm *date, char *text)
{
    time_t epoch = sample->epoch;
    errno = EDOM;
    if (!localtime_r(&epoch,date) || errno != EDOM || date->tm_year != sample->year-1900 ||
        date->tm_mon != sample->month-1 || date->tm_mday != sample->day || date->tm_hour != sample->hour ||
        date->tm_min != sample->minute || date->tm_sec != sample->second || date->tm_wday != sample->weekday ||
        date->tm_yday != sample->yearday || date->tm_isdst != sample->dst || date->tm_gmtoff != sample->offset ||
        !date->tm_zone || strcmp(date->tm_zone,sample->name)) return 0;
    if (!strftime(text,128,"%Y-%m-%d %H:%M:%S %G-W%V-%u %z %Z",date) || strcmp(text,sample->formatted)) return 0;
    if (mktime(date) != epoch || errno != EDOM) return 0;
    return 1;
}

static int write_fixture(const char *path,const unsigned char *data,size_t size)
{
    FILE *file = fopen(path,"wb");
    if (!file) return 0;
    int okay = fwrite(data,1,size,file) == size;
    if (fclose(file)) okay = 0;
    return okay;
}

typedef struct
{
    alix_thread_t thread;
    unsigned failed, cpu_mask;
    struct tm date;
    char text[128];
} timezone_worker_t;

static void timezone_worker(void *argument)
{
    timezone_worker_t *state=argument;
    for(unsigned cpu=0;cpu<WORKERS;++cpu)
    {
        if(sys_thread_set_affinity(cpu) || sys_thread_cpu()!=cpu) state->failed=1;
        for(unsigned i=0;i<sizeof(timezone_new_york_samples)/sizeof(timezone_new_york_samples[0]);++i)
            if(!check_sample(&timezone_new_york_samples[i],&state->date,state->text)) state->failed=1;
        state->cpu_mask |= 1u<<cpu;
    }
}

int main(void)
{
    struct tm *date=calloc(1,sizeof(*date));
    char *text=malloc(128);
    CHECK(date && text,"private query buffers");
    CHECK(unsetenv("TZ")==0,"system timezone selection");
    time_t epoch=0;
    CHECK(localtime_r(&epoch,date) && date->tm_year==70 && date->tm_hour==0 &&
          date->tm_gmtoff==0 && date->tm_isdst==0 && !strcmp(date->tm_zone,"UTC"),"system UTC snapshot");
    CHECK(setenv("TZ","AEST-10AEDT-11,M10.1.0/2,M4.1.0/3",1)==0,"POSIX selector");
    epoch=1704067200;
    CHECK(localtime_r(&epoch,date) && date->tm_hour==11 && date->tm_gmtoff==39600 &&
          date->tm_isdst==1 && !strcmp(date->tm_zone,"AEDT"),"southern POSIX DST");
    CHECK(setenv("TZ","EST5EDT,M3.2.0/2,M11.1.0/2",1)==0,"fold selector");
    *date=(struct tm){.tm_year=124,.tm_mon=2,.tm_mday=10,.tm_hour=2,.tm_min=30,.tm_isdst=-1};
    CHECK(mktime(date)==1710055800 && date->tm_hour==3 && date->tm_isdst==1,"spring gap normalization");
    for(int dst=0;dst<=1;++dst)
    {
        *date=(struct tm){.tm_year=124,.tm_mon=10,.tm_mday=3,.tm_hour=1,.tm_min=30,.tm_isdst=dst};
        CHECK(mktime(date)==(dst ? 1730611800 : 1730615400) && date->tm_isdst==dst,"autumn fold selection");
    }
    const struct fixture
    {
        const char *path,*selector;
        const unsigned char *bytes;
        size_t length;
        const timezone_sample_t *samples;
        size_t count;
    } fixtures[] = {
        {"/tmp/zone-new-york.tzif",":/tmp/zone-new-york.tzif",timezone_new_york_bytes,sizeof(timezone_new_york_bytes),
         timezone_new_york_samples,sizeof(timezone_new_york_samples)/sizeof(timezone_new_york_samples[0])},
        {"/tmp/zone-sydney.tzif",":/tmp/zone-sydney.tzif",timezone_sydney_bytes,sizeof(timezone_sydney_bytes),
         timezone_sydney_samples,sizeof(timezone_sydney_samples)/sizeof(timezone_sydney_samples[0])},
        {"/tmp/zone-lord-howe.tzif",":/tmp/zone-lord-howe.tzif",timezone_lord_howe_bytes,sizeof(timezone_lord_howe_bytes),
         timezone_lord_howe_samples,sizeof(timezone_lord_howe_samples)/sizeof(timezone_lord_howe_samples[0])},
    };
    unsigned samples=0;
    for(unsigned fixture=0;fixture<sizeof(fixtures)/sizeof(fixtures[0]);++fixture)
    {
        CHECK(write_fixture(fixtures[fixture].path,fixtures[fixture].bytes,fixtures[fixture].length),"write exact TZif asset");
        CHECK(setenv("TZ",fixtures[fixture].selector,1)==0,"TZif selector");
        for(unsigned i=0;i<fixtures[fixture].count;++i)
        {
            if(!check_sample(&fixtures[fixture].samples[i],date,text))
            {
                serial_printf("TIMEZONE_TEST: FAIL TZif fixture=%u sample=%u errno=%d\n",fixture,i,errno);
                return 1;
            }
            ++samples;
        }
    }
    CHECK(setenv("TZ",":/tmp/zone-new-york.tzif",1)==0,"parallel TZif selector");
    timezone_worker_t *workers=calloc(WORKERS,sizeof(*workers));
    CHECK(workers,"worker records");
    for(unsigned i=0;i<WORKERS;++i)
        CHECK(alix_thread_create(&workers[i].thread,"timezone",timezone_worker,&workers[i])==0,"worker creation");
    for(unsigned i=0;i<WORKERS;++i)
    {
        CHECK(alix_thread_join(workers[i].thread,NULL)==0,"worker join");
        CHECK(!workers[i].failed && workers[i].cpu_mask==0xFF,"parallel timestamp/formatting");
    }
    free(workers); free(date); free(text);
    serial_printf("TIMEZONE_TEST: PASS workers=8 cpu_mask=0xFF tzif_samples=%u posix=1 fold=1 gap=1 format=1\n",samples);
    return 0;
}
