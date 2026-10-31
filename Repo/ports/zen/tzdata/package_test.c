#include "userlib.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "serial.h"
#include "package_config.h"

extern const unsigned char alix_timezone_bundle[TZ_PACKAGE_SIZE];
int alix_tzdata_install_main(int argc,char **argv);
int alix_tzdata_verify_main(void);

#define CHECK(condition,label) do { if(!(condition)) { \
    serial_printf("TZDATA_PACKAGE_TEST: FAIL %s\n",label);return 1; } } while(0)

static int file_equals(const char *path,const char *text)
{
    FILE *file=fopen(path,"rb");if(!file) return 0;
    size_t size=strlen(text);char *buffer=malloc(size+1);if(!buffer) { fclose(file);return 0; }
    size_t count=fread(buffer,1,size+1,file);
    int okay=!ferror(file) && count==size && !memcmp(buffer,text,size);
    fclose(file);free(buffer);return okay;
}

static int create_sentinel(const char *path,const char *text)
{
    FILE *existing=fopen(path,"rb");
    if(existing) { fclose(existing);return file_equals(path,text); }
    FILE *file=fopen(path,"wb");if(!file) return 0;
    size_t size=strlen(text);int okay=fwrite(text,1,size,file)==size;
    if(fclose(file)) okay=0;
    return okay;
}

int main(void)
{
    syscall_timezone_info_t *before=calloc(1,sizeof(*before)),*after=calloc(1,sizeof(*after));
    CHECK(before && after && sys_timezone_info(before,sizeof(*before))==0,"initial timezone config");
    CHECK(alix_ensure_dir_path("/usr/share/zoneinfo/src"),"source directory");
    CHECK(create_sentinel("/usr/share/zoneinfo/src/.alix-tz-qa-preserve","existing source survives\n"),"source sentinel");
    CHECK(create_sentinel("/usr/share/zoneinfo/.alix-tz-qa-custom","custom zone survives\n"),"custom sentinel");
    FILE *bundle=fopen("/tmp/iana-timezone.bundle","wb");
    CHECK(bundle,"bundle file");
    CHECK(fwrite(alix_timezone_bundle,1,TZ_PACKAGE_SIZE,bundle)==TZ_PACKAGE_SIZE && fclose(bundle)==0,"bundle write");
    static char *check[]={"tzdata-install","check","/tmp/iana-timezone.bundle",NULL};
    static char *stage[]={"tzdata-install","stage","/tmp/iana-timezone.bundle",NULL};
    static char *verify[]={"tzdata-install","verify","/tmp/iana-timezone.bundle",NULL};
    CHECK(alix_tzdata_install_main(3,check)==0,"package preflight");
    CHECK(alix_tzdata_install_main(3,stage)==0,"full package stage");
    CHECK(alix_tzdata_install_main(3,stage)==0,"idempotent package stage");
    CHECK(alix_tzdata_install_main(3,verify)==0,"full package SHA-256 readback");
    CHECK(alix_tzdata_verify_main()==0,"all-zone native calendar checks");
    CHECK(file_equals("/usr/share/zoneinfo/src/.alix-tz-qa-preserve","existing source survives\n") &&
          file_equals("/usr/share/zoneinfo/.alix-tz-qa-custom","custom zone survives\n"),"custom files preserved");
    CHECK(sys_timezone_info(after,sizeof(*after))==0 && !memcmp(before,after,sizeof(*before)),"system selection unchanged");
    free(before);free(after);
    serial_printf("TZDATA_PACKAGE_TEST: PASS release=%s files=%u config_preserved=1 custom_preserved=1 inactive=1\n",
                  TZ_PACKAGE_RELEASE,TZ_PACKAGE_ENTRIES);
    return 0;
}
