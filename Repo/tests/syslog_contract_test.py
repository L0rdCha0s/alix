#!/usr/bin/env python3
"""Production syslog formatting, settings snapshots and transport contracts."""
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run


def main():
    code = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <unistd.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr,"syslog line %d: %s\n",__LINE__,#c); abort(); } } while (0)
#define SYSCALL_LOG_MAX_BYTES 4096u
#define SYSCALL_FILE_LOG 999u
typedef struct { unsigned state; } alix_mutex_t;
static _Thread_local unsigned held;
static void alix_mutex_lock(alix_mutex_t *lock) {
    while (__atomic_exchange_n(&lock->state,1,__ATOMIC_ACQUIRE)) sched_yield(); ++held;
}
static void alix_mutex_unlock(alix_mutex_t *lock) {
    CHECK(held); --held; __atomic_store_n(&lock->state,0,__ATOMIC_RELEASE);
}
typedef struct {
    pthread_mutex_t lock;
    char records[512][4097];size_t lengths[512];
    unsigned count,serial,stderr_count;int transport_error;
} model_t;
static model_t *model;
static unsigned live;
static bool fail_allocation;
static void *tracked_calloc(size_t count,size_t size) {
    if(fail_allocation){fail_allocation=false;errno=ENOMEM;return NULL;}
    void*p=calloc(count,size);if(p)__atomic_add_fetch(&live,1,__ATOMIC_RELAXED);return p;
}
static void tracked_free(void*p) {if(p){CHECK(__atomic_fetch_sub(&live,1,__ATOMIC_RELAXED));free(p);}}
static int64_t sys_file_io(uint32_t operation,uint64_t data,uint64_t size,uint64_t third,uint64_t fourth) {
    CHECK(!held&&operation==SYSCALL_FILE_LOG&&!third&&!fourth&&size&&size<=SYSCALL_LOG_MAX_BYTES);
    CHECK(!pthread_mutex_lock(&model->lock));int error=model->transport_error;
    if(!error){CHECK(model->count<512);unsigned index=model->count++;memcpy(model->records[index],(void*)(uintptr_t)data,size);model->records[index][size]=0;model->lengths[index]=size;}
    CHECK(!pthread_mutex_unlock(&model->lock));return error?error:(int64_t)size;
}
static int sys_serial_write(const char*data,size_t size) {CHECK(!held&&size&&data[size-1]=='\n');++model->serial;return (int)size;}
static ssize_t model_write(int fd,const void*data,size_t size) {CHECK(!held&&fd==2&&size&&((const char*)data)[size-1]=='\n');++model->stderr_count;return size;}
static pid_t model_getpid(void) {return 17;}
static time_t model_time(time_t*out) {if(out)*out=1700000000;return 1700000000;}
static char *model_strerror(int error) {return error==123?"bad%code":strerror(error);}
#define calloc tracked_calloc
#define free tracked_free
#define write model_write
#define getpid model_getpid
#define time model_time
#define strerror model_strerror
#define openlog native_openlog
#define closelog native_closelog
#define setlogmask native_setlogmask
#define syslog native_syslog
#define vsyslog native_vsyslog
'''
    code += (ROOT / "include/syslog.h").read_text()
    source = (ROOT / "user/lib/syslog.c").read_text()
    code += "\n".join(line for line in source.splitlines() if not line.startswith("#include"))
    code += r'''
typedef struct {pthread_t thread;unsigned number;} job_t;
static void *worker(void*context) {
    job_t*job=context;const char*tag=(job->number&1)?"race-B":"race-A";
    for(unsigned item=0;item<16;++item){
        native_openlog(tag,LOG_PID,(job->number&1)?LOG_LOCAL1:LOG_LOCAL0);
        errno=123;native_syslog(LOG_INFO,"worker=%u item=%u saved=%m",job->number,item);CHECK(errno==123);
    }
    return NULL;
}
int main(void) {
    model=calloc(1,sizeof(*model));CHECK(model&&!pthread_mutex_init(&model->lock,NULL));
    char ident[8]="tag";native_openlog(ident,LOG_PID,LOG_LOCAL2);ident[0]='X';errno=123;
    native_syslog(LOG_WARNING,"literal=%%m saved=%m value=%u",7u);
    CHECK(errno==123&&model->count==1&&!strcmp(model->records[0],"<148>1700000000 tag[17]: literal=%m saved=bad%code value=7\n"));
    CHECK(native_setlogmask(LOG_UPTO(LOG_ERR))==255&&native_setlogmask(0)==15);
    native_syslog(LOG_INFO,"filtered");CHECK(model->count==1);
    native_syslog(LOG_USER|LOG_ERR,"allowed\nsecond\rline");CHECK(model->count==2&&strstr(model->records[1],"allowed second line\n"));
    native_closelog();CHECK(native_setlogmask(0)==15);native_setlogmask(255);
    native_syslog(LOG_NOTICE,"default");CHECK(!strcmp(model->records[2],"<13>1700000000: default\n"));
    unsigned before=model->count;native_syslog(1<<20,"invalid");CHECK(model->count==before);
    fail_allocation=true;errno=EDOM;native_syslog(LOG_ERR,"oom");CHECK(errno==EDOM&&model->count==before);
    native_openlog("fallback",LOG_CONS|LOG_PERROR,LOG_USER);model->transport_error=-EIO;errno=123;
    native_syslog(LOG_ERR,"fallback");CHECK(errno==123&&model->serial==1&&model->stderr_count==1&&model->count==before);
    model->transport_error=0;native_openlog(NULL,0,LOG_USER);
    char*large=calloc(6001,1);CHECK(large);memset(large,'a',6000);
    native_syslog(LOG_INFO,"%s",large);CHECK(model->lengths[model->count-1]==4096);
    native_syslog(LOG_INFO,large);CHECK(strstr(model->records[model->count-1],"[syslog format exceeds limit]"));free(large);
    before=model->count;job_t*jobs=calloc(8,sizeof(*jobs));CHECK(jobs);
    for(unsigned n=0;n<8;++n){jobs[n].number=n;CHECK(!pthread_create(&jobs[n].thread,NULL,worker,&jobs[n]));}
    for(unsigned n=0;n<8;++n)CHECK(!pthread_join(jobs[n].thread,NULL));
    CHECK(model->count==before+128);
    for(unsigned n=before;n<model->count;++n){
        const char*line=model->records[n];bool a=!strncmp(line,"<134>1700000000 race-A[17]: ",27),b=!strncmp(line,"<142>1700000000 race-B[17]: ",27);
        CHECK((a||b)&&strstr(line,"saved=bad%code\n"));
        CHECK(strchr(line,'\n')==line+model->lengths[n]-1);
    }
    free(jobs);CHECK(!pthread_mutex_destroy(&model->lock));free(model);CHECK(!live&&!held);
    puts("Production syslog contracts PASS");return 0;
}
'''
    compile_and_run("syslog", code)
    print("Syslog contracts PASS: masks, facilities, copied ident, percent-m, truncation, OOM/fallback and 128 concurrent settings snapshots")


if __name__ == "__main__":
    main()
