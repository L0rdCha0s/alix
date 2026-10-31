#!/usr/bin/env python3
"""Run the native all-zone verifier against production calendar/TZif code on host."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt",type=Path)
    args=parser.parse_args()
    receipt=json.loads(args.receipt.read_text())
    artifacts=args.receipt.resolve().parent/(receipt["id"]+"-installer")
    wire=(ROOT/"include/syscall_defs.h").read_text()
    wire=wire[wire.index("#define SYSCALL_TIMEZONE_VERSION"):wire.index("#define SYSCALL_VM_PROT_NONE")]
    platform='''#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
'''+wire+'''
#define SYSCALL_OPEN_READ 1u
typedef struct { unsigned value; } alix_mutex_t;
void alix_mutex_lock(alix_mutex_t *);
void alix_mutex_unlock(alix_mutex_t *);
int sys_timezone_info(syscall_timezone_info_t *,size_t);
int sys_open(const char *,uint64_t);
ssize_t sys_read(int,void *,size_t);
int sys_close(int);
void serial_printf(const char *,...);
'''
    model=r'''
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "platform.h"
#include "package_config.h"
void alix_mutex_lock(alix_mutex_t *lock) { while(__atomic_exchange_n(&lock->value,1,__ATOMIC_ACQUIRE)) sched_yield(); }
void alix_mutex_unlock(alix_mutex_t *lock) { __atomic_store_n(&lock->value,0,__ATOMIC_RELEASE); }
int sys_timezone_info(syscall_timezone_info_t *out,size_t size)
{
    if(size!=sizeof(*out)) return -EINVAL;
    memset(out,0,sizeof(*out));out->version=1;out->size=sizeof(*out);out->generation=1;strcpy(out->display_name,"UTC");return 0;
}
int sys_open(const char *path,uint64_t flags)
{
    if(flags!=1 || strncmp(path,TZ_PACKAGE_ROOT,strlen(TZ_PACKAGE_ROOT))) return -EINVAL;
    const char *base=getenv("PACKAGE_SOURCE_DIR");
    const char *tail=path+strlen(TZ_PACKAGE_ROOT);
    size_t size=strlen(base)+strlen(tail)+1;char *full=malloc(size);if(!full) return -ENOMEM;
    snprintf(full,size,"%s%s",base,tail);int fd=open(full,O_RDONLY);free(full);return fd<0 ? -errno : fd;
}
ssize_t sys_read(int fd,void *out,size_t size) { ssize_t n=read(fd,out,size);return n<0 ? -errno : n; }
int sys_close(int fd) { return close(fd); }
void serial_printf(const char *format,...) { va_list args;va_start(args,format);vprintf(format,args);va_end(args); }
'''
    symbols=("gmtime","gmtime_r","timegm","asctime","asctime_r","localtime","localtime_r",
             "mktime","ctime","ctime_r","strftime","tzset","timezone","daylight","tzname")
    with tempfile.TemporaryDirectory(prefix="alix-tz-catalog-") as temporary:
        work=Path(temporary)
        (work/"platform.h").write_text(platform)
        (work/"model.c").write_text(model)
        for name in ("package_config.h","zone_catalog.h"):
            (work/name).write_bytes((artifacts/name).read_bytes())
        compiler=shlex.split(os.environ.get("HOST_CC","cc"))
        flags=["-std=c11","-D_DARWIN_C_SOURCE","-D_GNU_SOURCE","-D_DEFAULT_SOURCE","-Wall","-Wextra","-Werror",
               "-g","-fsanitize=address,undefined","-pthread"]
        objects=[]
        for original in (ROOT/"user/lib/calendar.c",ROOT/"user/lib/timezone.c",ROOT/"user/lib/calendar_format.c",HERE/"verify.c"):
            source=work/original.name
            source.write_text(original.read_text().replace('#include "timezone_platform.h"','#include "platform.h"')
                              .replace('#include "userlib.h"','#include "platform.h"').replace('#include "serial.h"',''))
            target=source.with_suffix(".o");objects.append(str(target))
            subprocess.run(compiler+flags+[f"-D{x}=alix_{x}" for x in symbols]+["-c",str(source),"-o",str(target)],check=True)
        binary=work/"verify"
        subprocess.run(compiler+flags+[str(work/"model.c")]+objects+["-o",str(binary)],check=True)
        subprocess.run([str(binary)],env={**os.environ,"PACKAGE_SOURCE_DIR":receipt["package_directory"]},check=True)

if __name__=="__main__":main()
