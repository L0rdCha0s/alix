#!/usr/bin/env python3
"""Production temporary-file creation: collisions, exclusive modes and failures."""
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run


def main():
    code = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"temporary object line %d: %s\n",__LINE__,#c); abort(); } } while (0)
static unsigned entropy_calls, file_calls, directory_calls, collisions;
static int entropy_error, operation_error, last_flags;
static char captured[PATH_MAX];
static int model_entropy(void *out, size_t bytes) {
    CHECK(bytes == sizeof(uint64_t)); ++entropy_calls;
    if (entropy_error) { errno=entropy_error; return -1; }
    uint64_t value=entropy_calls*UINT64_C(0x9e3779b97f4a7c15);memcpy(out,&value,bytes);return 0;
}
static int model_open(const char *path, uint64_t flags, ...) {
    ++file_calls;CHECK(file_calls<10000);
    va_list args;va_start(args,flags);unsigned mode=va_arg(args,unsigned);va_end(args);
    CHECK(mode==0600&&(flags&(O_CREAT|O_EXCL|O_RDWR))==(O_CREAT|O_EXCL|O_RDWR)&&!(flags&O_TRUNC));
    last_flags=(int)flags;strcpy(captured,path);
    if(collisions){--collisions;errno=EEXIST;return -1;}
    if(operation_error){errno=operation_error;return -1;}return 17;
}
static int model_mkdir(const char *path, unsigned mode) {
    ++directory_calls;CHECK(directory_calls<10000&&mode==0700);strcpy(captured,path);
    if(collisions){--collisions;errno=EEXIST;return -1;}
    if(operation_error){errno=operation_error;return -1;}return 0;
}
#define getentropy model_entropy
#define open model_open
#define mkdir model_mkdir
#define mkostemps native_mkostemps
#define mkstemps native_mkstemps
#define mkostemp native_mkostemp
#define mkstemp native_mkstemp
#define mkdtemp native_mkdtemp
'''
    source = (ROOT / "user/lib/tempfile.c").read_text()
    code += "\n".join(line for line in source.splitlines() if not line.startswith("#include"))
    code += r'''
static void reset(void){entropy_calls=file_calls=directory_calls=collisions=0;entropy_error=operation_error=0;captured[0]=0;}
int main(void){
    char *path=calloc(PATH_MAX+8,1);CHECK(path);
    reset();strcpy(path,"/tmp/prefix-XXXXXX");collisions=3;errno=EDOM;
    CHECK(native_mkstemp(path)==17&&errno==EDOM&&file_calls==4&&!directory_calls&&!strcmp(path,captured));
    CHECK(!strncmp(path,"/tmp/prefix-",12)&&strlen(path)==18);
    reset();strcpy(path,"/tmp/file-XXXXXX.dat");
    CHECK(native_mkostemps(path,4,O_CLOEXEC|O_APPEND)==17&&(last_flags&O_CLOEXEC)&&(last_flags&O_APPEND)&&
          !strcmp(path+strlen(path)-4,".dat"));
    reset();strcpy(path,"/tmp/dir-XXXXXX");collisions=2;errno=EDOM;
    CHECK(native_mkdtemp(path)==path&&directory_calls==3&&!file_calls&&errno==EDOM);
    reset();strcpy(path,"/tmp/invalid-template");
    CHECK(native_mkstemp(path)==-1&&errno==EINVAL&&!entropy_calls&&!strcmp(path,"/tmp/invalid-template"));
    CHECK(native_mkstemp(NULL)==-1&&errno==EINVAL&&!entropy_calls);
    strcpy(path,"/tmp/file-XXXXXX.dat");
    CHECK(native_mkostemps(path,-1,0)==-1&&errno==EINVAL&&!entropy_calls);
    CHECK(native_mkostemps(path,PATH_MAX,0)==-1&&errno==EINVAL&&!entropy_calls);
    CHECK(native_mkostemps(path,4,O_TRUNC)==-1&&errno==EINVAL&&!entropy_calls);
    memset(path,'a',PATH_MAX);path[PATH_MAX]=0;
    CHECK(native_mkstemp(path)==-1&&errno==ENAMETOOLONG&&!entropy_calls);
    reset();strcpy(path,"/tmp/file-XXXXXX");entropy_error=EIO;
    CHECK(native_mkstemp(path)==-1&&errno==EIO&&!file_calls&&!strcmp(path,"/tmp/file-XXXXXX"));
    reset();strcpy(path,"/tmp/file-XXXXXX");operation_error=EMFILE;
    CHECK(native_mkstemp(path)==-1&&errno==EMFILE&&file_calls==1);
    reset();strcpy(path,"/tmp/file-XXXXXX");collisions=10000;
    CHECK(native_mkstemp(path)==-1&&errno==EEXIST&&file_calls>1&&file_calls<10000);
    reset();strcpy(path,"/tmp/dir-XXXXXX");operation_error=EACCES;
    CHECK(!native_mkdtemp(path)&&errno==EACCES&&directory_calls==1&&!file_calls);
    free(path);puts("Temporary object contracts PASS");return 0;
}
'''
    compile_and_run("temporary-object", code)
    print("Temporary object contracts PASS: exclusive 0600/0700 modes, collisions, suffix/flags, invalid inputs, entropy and descriptor failures")


if __name__ == "__main__":
    main()
