#!/usr/bin/env python3
"""Run production native installer logic with confined host syscall models."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
PLATFORM=r'''
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#define SYSCALL_OPEN_READ 1u
#define SYSCALL_OPEN_WRITE 2u
#define SYSCALL_OPEN_CREATE 4u
#define SYSCALL_NODE_TYPE_DIR 0u
#define SYSCALL_NODE_TYPE_FILE 1u
#define SYSCALL_NODE_TYPE_BLOCK 2u
#define SYSCALL_NODE_TYPE_SYMLINK 3u
typedef struct { uint32_t type,reserved; uint64_t size_bytes; char name[128]; } syscall_dirent_t;
ssize_t sys_list_dir(const char *,syscall_dirent_t *,size_t);
int sys_mkdir(const char *);
int alix_open(const char *,uint64_t,...);
ssize_t alix_write(int,const void *,size_t);
int alix_close(int);
void serial_printf(const char *,...);
'''
MODEL=r'''
#include <dirent.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "platform.h"
static char *translate(const char *path)
{
    if(strncmp(path,"/root",5)) return strdup(path);
    const char *base=getenv("TEST_ROOT"); if(!base) abort();
    size_t size=strlen(base)+strlen(path)+1;
    char *result=malloc(size); if(result) snprintf(result,size,"%s%s",base,path); return result;
}
FILE *alix_fopen(const char *path,const char *mode)
{
    char *real=translate(path); FILE *result=real ? fopen(real,mode) : NULL; free(real); return result;
}
int alix_open(const char *path,uint64_t flags,...)
{
    char *real=translate(path); if(!real) return -1;
    int result=open(real,(flags&2 ? O_WRONLY : O_RDONLY)|(flags&4 ? O_CREAT : 0),0600); free(real); return result;
}
ssize_t alix_write(int fd,const void *bytes,size_t size)
{
    static unsigned calls;
    const char *limit=getenv("TEST_FAIL_WRITE");
    if(limit && ++calls>=strtoul(limit,NULL,10)) return -1;
    if(size>4093) size=4093;
    return write(fd,bytes,size);
}
int alix_close(int fd) { return close(fd); }
int sys_mkdir(const char *path) { char *real=translate(path); if(!real) return -1; int result=mkdir(real,0700); free(real); return result; }
ssize_t sys_list_dir(const char *path,syscall_dirent_t *entries,size_t capacity)
{
    if(!strcmp(path,"/"))
    {
        if(!capacity) return -1;
        memset(entries,0,sizeof(*entries)); entries->type=SYSCALL_NODE_TYPE_DIR; strcpy(entries->name,"root"); return 1;
    }
    char *real=translate(path); if(!real) return -1;
    DIR *directory=opendir(real); free(real); if(!directory) return -1;
    size_t count=0; struct dirent *entry;
    while((entry=readdir(directory)))
    {
        if(!strcmp(entry->d_name,".") || !strcmp(entry->d_name,"..")) continue;
        if(count==capacity) break;
        struct stat st; if(fstatat(dirfd(directory),entry->d_name,&st,AT_SYMLINK_NOFOLLOW)) { closedir(directory); return -1; }
        memset(&entries[count],0,sizeof(entries[count]));
        entries[count].type=S_ISLNK(st.st_mode) ? 3 : S_ISDIR(st.st_mode) ? 0 : S_ISREG(st.st_mode) ? 1 : 2;
        if(strlen(entry->d_name)>=sizeof(entries[count].name)) { closedir(directory); return -1; }
        strcpy(entries[count].name,entry->d_name); ++count;
    }
    closedir(directory); return (ssize_t)count;
}
void serial_printf(const char *format,...)
{
    va_list args; va_start(args,format); vprintf(format,args); va_end(args);
}
'''

def tree(path):
    return {p.relative_to(path).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
            for p in path.rglob("*") if p.is_file() and not p.is_symlink()}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receipt",type=Path)
    args=parser.parse_args()
    receipt=json.loads(args.receipt.read_text())
    bundle=Path(receipt["bundle"])
    package=Path(receipt["package_directory"])
    with tempfile.TemporaryDirectory(prefix="alix-tz-installer-") as temporary:
        work=Path(temporary)
        (work/"platform.h").write_text(PLATFORM)
        (work/"package_config.h").write_bytes(Path(receipt["installer_config"]).read_bytes())
        (work/"crypto").mkdir()
        (work/"crypto/sha256.h").write_bytes((ROOT/"include/crypto/sha256.h").read_bytes())
        source=(HERE/"install.c").read_text().replace('#include "userlib.h"','#include "platform.h"').replace('#include "serial.h"','')
        source=source.replace('#include "package_config.h"','#include "package_config.h"\nFILE *alix_fopen(const char *,const char *);\n#define fopen alix_fopen')
        (work/"install.c").write_text(source)
        crypto=(ROOT/"src/crypto/sha256.c").read_text().replace('#include "libc.h"','#include <string.h>')
        (work/"sha256.c").write_text(crypto)
        (work/"model.c").write_text(MODEL)
        compiler=shlex.split(os.environ.get("HOST_CC","cc"))
        flags=["-std=c11","-D_DARWIN_C_SOURCE","-D_GNU_SOURCE","-DTTF_HOST_BUILD","-Wall","-Wextra","-Werror",
               "-g","-fsanitize=address,undefined","-I"+str(work)]
        subprocess.run(compiler+flags+["-Dopen=alix_open","-Dwrite=alix_write","-Dclose=alix_close",
                                      "-c",str(work/"install.c"),"-o",str(work/"install.o")],check=True)
        binary=work/"installer"
        subprocess.run(compiler+flags+[str(work/"model.c"),str(work/"sha256.c"),str(work/"install.o"),"-o",str(binary)],check=True)
        destination=work/"disk"; logical=destination/"root/usr/share/zoneinfo"
        logical.mkdir(parents=True)
        (logical/"src").mkdir(); (logical/"src/tzdata.zi").write_text("custom source")
        (logical/"alix.tzd").write_text("existing native database")
        (logical/"Custom").write_text("custom timezone")
        preserved=tree(destination)
        release=logical/".alix-releases"/receipt["id"]
        environment={**os.environ,"TEST_ROOT":str(destination)}
        def run(mode,archive=bundle,success=True,extra=None):
            result=subprocess.run([str(binary),mode,str(archive)],env={**environment,**(extra or {})},capture_output=True,text=True)
            if (result.returncode==0)!=success:
                raise AssertionError(result.stdout+result.stderr)
            return result.stdout
        assert f'missing={receipt["entries"]}' in run("check") and tree(destination)==preserved
        bad=work/"bad.bundle"; data=bytearray(bundle.read_bytes());data[-1]^=1;bad.write_bytes(data)
        run("stage",bad,False); assert tree(destination)==preserved
        conflict=release/"zoneinfo/America/New_York";conflict.parent.mkdir(parents=True);conflict.write_text("keep me")
        before=tree(destination);run("stage",success=False);assert tree(destination)==before
        conflict.unlink();conflict.parent.rmdir()
        outside=work/"outside";outside.mkdir();conflict.parent.symlink_to(outside,target_is_directory=True)
        run("stage",success=False);assert list(outside.iterdir())==[]
        conflict.parent.unlink()
        assert f'created={receipt["entries"]}' in run("stage")
        assert f'identical={receipt["entries"]}' in run("stage")
        assert "TZDATA_VERIFY: PASS" in run("verify")
        for relative,hash_value in preserved.items(): assert tree(destination)[relative]==hash_value
        for path in package.rglob("*"):
            if path.is_file(): assert (release/path.relative_to(package)).read_bytes()==path.read_bytes()
        extra=release/"custom-note";extra.write_text("preserved extra")
        run("stage");assert extra.read_text()=="preserved extra"
        failed_disk=work/"failed-disk";failed_root=failed_disk/"root/usr/share/zoneinfo"
        failed_root.mkdir(parents=True);(failed_root/"custom").write_text("unchanged")
        failed_environment={"TEST_ROOT":str(failed_disk)}
        run("stage",success=False,extra={**failed_environment,"TEST_FAIL_WRITE":"10"})
        before_retry=tree(failed_disk)
        assert before_retry["root/usr/share/zoneinfo/custom"]==hashlib.sha256(b"unchanged").hexdigest()
        run("verify",success=False,extra=failed_environment)
        run("stage",success=False,extra=failed_environment)
        assert tree(failed_disk)==before_retry
        print(f'Pinned timezone installer ASan/UBSan: PASS integrity/conflicts/symlinks/{receipt["entries"]}-file stage/idempotence/custom preservation/partial failure')

if __name__=="__main__":main()
