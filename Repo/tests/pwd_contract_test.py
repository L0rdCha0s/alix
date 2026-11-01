#!/usr/bin/env python3
"""Production reentrant Alix account parsing, ownership and failure contracts."""
import sys
sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition

source = (ROOT / "user/lib/pwd.c").read_text()
program = r'''
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdatomic.h>
#include <pthread.h>
#define CHECK(c) do { if(!(c)){fprintf(stderr,"pwd contract line %d: %s\n",__LINE__,#c);abort();} }while(0)
typedef uint32_t uid_t;
typedef uint32_t gid_t;
struct passwd {char *pw_name,*pw_passwd;uid_t pw_uid;gid_t pw_gid;char *pw_gecos,*pw_dir,*pw_shell;};
struct pwd_stat {uint64_t st_size;};
#define O_RDONLY 1u
#define O_CLOEXEC (1u << 17)
#define PWD_DATABASE_LIMIT (64u * 1024u)
static const char *database = "# comment\nbroken\noverflow:6777777777:1:Bad:/bad\nbadgid:37:4294967296:Bad:/bad\nalice:37:41:Alice Example:home/alice\r\nroot:0:0:Root:/root\nempty:42:41::\nmax:4294967295:4294967295:Max:/max";
static int open_error,stat_error,read_error;
static size_t forced_size;
static _Thread_local size_t cursor,opened,closed;
static _Thread_local int interrupted;
static atomic_int allocation_limit = -1;
static int allocation_fails(void){int value=atomic_load(&allocation_limit);if(value<0)return 0;if(!value)return 1;atomic_fetch_sub(&allocation_limit,1);return 0;}
static void *pwd_malloc(size_t n){return allocation_fails()?NULL:malloc(n);}
static void *pwd_calloc(size_t n,size_t size){return allocation_fails()?NULL:calloc(n,size);}
static int pwd_open(const char *path,uint64_t flags){CHECK(!strcmp(path,"/etc/passwd") && flags==(O_RDONLY|O_CLOEXEC));if(open_error){errno=open_error;return -1;}cursor=0;interrupted=0;++opened;return 97;}
static int pwd_fstat(int fd,struct pwd_stat *st){CHECK(fd==97);if(stat_error){errno=stat_error;return -1;}st->st_size=forced_size?forced_size:strlen(database);return 0;}
static ptrdiff_t pwd_read(int fd,void *output,size_t count){CHECK(fd==97);if(read_error && !(read_error==EINTR && interrupted++)){errno=read_error;return -1;}size_t length=strlen(database);size_t n=cursor<length?length-cursor:0;if(n>count)n=count;if(n>7)n=7;memcpy(output,database+cursor,n);cursor+=n;return (ptrdiff_t)n;}
static int pwd_close(int fd){CHECK(fd==97);++closed;return 0;}
#define malloc pwd_malloc
#define calloc pwd_calloc
#define stat pwd_stat
#define open pwd_open
#define fstat pwd_fstat
#define read pwd_read
#define close pwd_close
'''
start = source.index('typedef struct {')
program += source[start:source.index('} pwd_record_t;', start) + len('} pwd_record_t;')] + '\n'
for signature in ('static int pwd_read_text(', 'static int pwd_number(', 'static int pwd_parse(',
                  'static char *pwd_copy_field(', 'static int pwd_publish(', 'static int pwd_lookup(',
                  'int getpwuid_r(', 'int getpwnam_r('):
    program += function_definition(source, signature).replace('getpwuid_r(', 'test_getpwuid_r(').replace('getpwnam_r(', 'test_getpwnam_r(') + '\n'
program += r'''
#undef malloc
#undef calloc
static void check_entry(struct passwd *entry,char *buffer,size_t size,unsigned uid){
    char *fields[]={entry->pw_name,entry->pw_passwd,entry->pw_gecos,entry->pw_dir,entry->pw_shell};
    for(unsigned i=0;i<5;++i)CHECK(fields[i]>=buffer && fields[i]<buffer+size);
    CHECK(!entry->pw_passwd[0] && !entry->pw_shell[0]);
    CHECK(entry->pw_uid==uid && entry->pw_gid==(uid?41:0));
    CHECK(!strcmp(entry->pw_name,uid?"alice":"root"));
    CHECK(!strcmp(entry->pw_dir,uid?"/home/alice":"/root"));
    CHECK(!strcmp(entry->pw_gecos,uid?"Alice Example":"Root"));
}
static void sequential(void){
    struct passwd *entry=calloc(1,sizeof(*entry)),*result=(void *)1;char *buffer=malloc(1024);CHECK(entry && buffer);
    errno=123;CHECK(!test_getpwuid_r(37,entry,buffer,1024,&result) && result==entry && errno==123);check_entry(entry,buffer,1024,37);
    CHECK(!test_getpwnam_r("root",entry,buffer,1024,&result) && result==entry);check_entry(entry,buffer,1024,0);
    CHECK(!test_getpwuid_r(38,entry,buffer,1024,&result) && !result);
    CHECK(!test_getpwnam_r("absent",entry,buffer,1024,&result) && !result);
    CHECK(!test_getpwuid_r(UINT32_MAX,entry,buffer,1024,&result) && result && entry->pw_uid==UINT32_MAX && entry->pw_gid==UINT32_MAX && !strcmp(entry->pw_dir,"/max"));
    CHECK(!test_getpwuid_r(42,entry,buffer,1024,&result) && result && !entry->pw_dir[0]);
    CHECK(test_getpwuid_r(0,NULL,buffer,1024,&result)==EINVAL && !result);
    CHECK(test_getpwnam_r(NULL,entry,buffer,1024,&result)==EINVAL && !result);
    struct passwd saved=*entry;memset(buffer,0xa5,1024);
    CHECK(test_getpwuid_r(0,entry,buffer,1,&result)==ERANGE && !result && !memcmp(entry,&saved,sizeof(saved)));
    for(unsigned i=0;i<1024;++i)CHECK((unsigned char)buffer[i]==0xa5);
    uint32_t value;CHECK(!pwd_number("6777777777",10,&value));CHECK(!pwd_number("4294967296",10,&value));CHECK(pwd_number("4294967295",10,&value) && value==UINT32_MAX);
    open_error=ENOENT;CHECK(test_getpwuid_r(0,entry,buffer,1024,&result)==ENOENT && !result);open_error=0;
    stat_error=EIO;CHECK(test_getpwuid_r(0,entry,buffer,1024,&result)==EIO && !result);stat_error=0;
    forced_size=PWD_DATABASE_LIMIT+1;CHECK(test_getpwuid_r(0,entry,buffer,1024,&result)==EFBIG && !result);forced_size=0;
    read_error=EIO;CHECK(test_getpwuid_r(0,entry,buffer,1024,&result)==EIO && !result);read_error=EINTR;
    CHECK(!test_getpwuid_r(0,entry,buffer,1024,&result) && result);read_error=0;
    for(int i=0;i<3;++i){atomic_store(&allocation_limit,i);CHECK(test_getpwuid_r(0,entry,buffer,1024,&result)==ENOMEM && !result);atomic_store(&allocation_limit,-1);}
    CHECK(opened==closed);free(buffer);free(entry);
}
static void *worker(void *unused){
    (void)unused;struct passwd *entry=calloc(1,sizeof(*entry)),*result=NULL;char *buffer=malloc(1024);CHECK(entry && buffer);
    for(unsigned i=0;i<500;++i){unsigned uid=i%2?37:0;errno=100+(int)uid;
        CHECK(!test_getpwuid_r(uid,entry,buffer,1024,&result) && result==entry && errno==100+(int)uid);check_entry(entry,buffer,1024,uid);
        CHECK(!test_getpwnam_r(uid?"alice":"root",entry,buffer,1024,&result) && result==entry);check_entry(entry,buffer,1024,uid);}
    CHECK(opened==closed);free(buffer);free(entry);return NULL;
}
int main(void){sequential();pthread_t workers[8];for(unsigned i=0;i<8;++i)CHECK(!pthread_create(&workers[i],NULL,worker,NULL));for(unsigned i=0;i<8;++i)CHECK(!pthread_join(workers[i],NULL));puts("PWD_CONTRACT_TEST: PASS uid=1 name=1 missing=1 malformed=1 overflow=1 ownership=1 errors=1 oom=1 concurrent=8000");return 0;}
'''
compile_and_run('pwd-contract', program)
print('Production reentrant account contracts: PASS parsing, ownership, errors, OOM and 8000 concurrent lookups')
