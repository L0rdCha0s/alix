#include "userlib.h"
#include "time.h"
#include "errno.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "serial.h"
#include "package_config.h"
#include "zone_catalog.h"

int main(void)
{
    struct tm *date=calloc(1,sizeof(*date));
    size_t selector_capacity=sizeof(TZ_PACKAGE_ROOT)+sizeof("/zoneinfo/")+256;
    char *selector=malloc(selector_capacity);
    if(!date || !selector) return 1;
    unsigned cases=0,unknown=0;
    for(unsigned zone=0;zone<TZ_CATALOG_COUNT;++zone)
    {
        int length=snprintf(selector,selector_capacity,":%s/zoneinfo/%s",TZ_PACKAGE_ROOT,zone_catalog[zone].name);
        if(length<0 || (size_t)length>=selector_capacity || setenv("TZ",selector,1)) return 1;
        for(unsigned sample=0;sample<TZ_CATALOG_TIMES;++sample)
        {
            const timezone_reference_t *expected=&zone_catalog[zone].values[sample];
            time_t instant=timezone_reference_times[sample];
            errno=0;
            struct tm *result=localtime_r(&instant,date);
            if(!expected->known)
            {
                if(result || errno!=EOVERFLOW)
                {
                    serial_printf("TZDATA_RUNTIME: FAIL unknown-zone zone=%s sample=%u errno=%d\n",zone_catalog[zone].name,sample,errno);
                    return 1;
                }
                ++unknown; ++cases; continue;
            }
            if(!result || date->tm_gmtoff!=expected->offset || date->tm_isdst!=expected->dst ||
               !date->tm_zone || strcmp(date->tm_zone,expected->abbreviation) || mktime(date)!=instant)
            {
                serial_printf("TZDATA_RUNTIME: FAIL zone=%s sample=%u errno=%d expected_offset=%d actual_offset=%ld\n",
                              zone_catalog[zone].name,sample,errno,expected->offset,result ? date->tm_gmtoff : 0L);
                return 1;
            }
            ++cases;
        }
    }
    free(date); free(selector);
    serial_printf("TZDATA_RUNTIME: PASS release=%s zones=%u cases=%u aliases=%u unknown=%u inactive=1\n",
                  TZ_PACKAGE_RELEASE,TZ_CATALOG_COUNT,cases,TZ_CATALOG_ALIASES,unknown);
    return 0;
}
