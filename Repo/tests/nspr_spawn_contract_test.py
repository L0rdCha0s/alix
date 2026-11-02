#!/usr/bin/env python3
"""Fault every allocation/descriptor preparation step in actual NSPR spawn code."""
import re
import sys
sys.dont_write_bytecode=True
from audio_stream_contract_test import ROOT,compile_and_run,function_definition
from audio_hda_state_test import typedef

native=(ROOT/'ports/zen/upstream/firefox-159.0/nsprpub/pr/src/md/unix/uxproces.c').read_text()
library=(ROOT/'user/lib/spawn.c').read_text();wire=(ROOT/'include/syscall_defs.h').read_text()
code=r'''
#define _POSIX_C_SOURCE 200809L
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#define CHECK(c) do {if(!(c)){fprintf(stderr,"nspr spawn contract %d: %s\n",__LINE__,#c);abort();}}while(0)
static unsigned allocations,calls,fail_at;
static bool injected;
static int spawn_error;
static bool fail_step(void){++calls;if(calls==fail_at){injected=true;errno=EIO;return true;}return false;}
static void *owned_malloc(size_t n){if(fail_step())return NULL;void*p=malloc(n);if(p)++allocations;return p;}
static void *owned_calloc(size_t n,size_t s){if(fail_step())return NULL;void*p=calloc(n,s);if(p)++allocations;return p;}
static void *owned_realloc(void*p,size_t n){if(fail_step())return NULL;bool existed=p!=NULL;void*q=realloc(p,n);if(q&&!existed)++allocations;return q;}
static void owned_free(void*p){if(p){CHECK(allocations);--allocations;free(p);}}
static char *owned_strdup(const char*s){size_t n=strlen(s)+1;char*p=owned_malloc(n);if(p)memcpy(p,s,n);return p;}
static int checked_fcntl(int fd,int command,...){
    if(fail_step())return -1;if(command==F_GETFL)return fcntl(fd,command);
    CHECK(command==F_DUPFD_CLOEXEC);va_list args;va_start(args,command);int minimum=va_arg(args,int);va_end(args);return fcntl(fd,command,minimum);
}
static int checked_ioctl(int fd,unsigned long command,void *value){if(fail_step())return -1;return ioctl(fd,command,value);}
typedef int PRBool;
#define PR_TRUE 1
#define PR_FALSE 0
typedef struct {struct {int osfd;} md;} PRFilePrivate;
typedef struct {PRFilePrivate *secret;} PRFileDesc;
typedef struct {PRFileDesc *stdinFd,*stdoutFd,*stderrFd;char *currentDirectory,*fdInheritBuffer;} PRProcessAttr;
#define ACTIONS_MAGIC 0x53504641u
#define ACTION_LIMIT 256u
#define FILE_LIMIT 256
'''
for name in ('CLOSE','DUP2','OPEN','CHDIR'):
    code+=re.search(r'^#define SYSCALL_SPAWN_'+name+r'[^\n]*',wire,re.M).group(0)+'\n'
code+=typedef(wire,'syscall_spawn_action_t')+'\n'+typedef((ROOT/'include/spawn.h').read_text(),'posix_spawn_file_actions_t')+'\n'
code+=r'''
#define malloc owned_malloc
#define calloc owned_calloc
#define realloc owned_realloc
#define free owned_free
#define strdup owned_strdup
'''
for signature in ('int posix_spawn_file_actions_init(', 'int posix_spawn_file_actions_destroy(', 'static int add_action(',
                  'int posix_spawn_file_actions_addclose(', 'int posix_spawn_file_actions_adddup2(', 'int posix_spawn_file_actions_addchdir_np('):
    code+=function_definition(library,signature)+'\n'
code+=r'''
static void alix_environment_free(char **environment){if(!environment)return;for(unsigned i=0;environment[i];++i)free(environment[i]);free(environment);}
static char **alix_environment_copy(void){
    char **copy=calloc(3,sizeof(*copy));if(!copy)return NULL;
    copy[0]=strdup("VALUE=inherited");if(copy[0])copy[1]=strdup("NSPR_INHERIT_FDS=old");
    if(!copy[0]||!copy[1]){alix_environment_free(copy);return NULL;}return copy;
}
static int posix_spawn(pid_t *pid,const char*path,const posix_spawn_file_actions_t*actions,void*attributes,char*const*argv,char*const*environment){
    CHECK(!attributes && !strcmp(path,"/native-program") && !strcmp(argv[0],"program"));
    CHECK(actions->count>=7);unsigned duplicates=0,dirs=0,inherit=0;
    for(unsigned i=0;i<actions->count;++i){const syscall_spawn_action_t*a=&actions->actions[i];
        if(a->operation==SYSCALL_SPAWN_DUP2){CHECK(a->destination==(int)duplicates && a->fd>=3 && !(fcntl(a->fd,F_GETFL)&O_NONBLOCK));++duplicates;}
        else if(a->operation==SYSCALL_SPAWN_CHDIR){CHECK(!strcmp((const char*)(uintptr_t)a->path,"/native-cwd"));++dirs;}
    }
    for(unsigned i=0;environment[i];++i)if(!strncmp(environment[i],"NSPR_INHERIT_FDS=",17)){CHECK(!strcmp(environment[i],"NSPR_INHERIT_FDS=new"));++inherit;}
    CHECK(duplicates==3 && dirs==1 && inherit==1);
    if(fail_step())return ENOMEM;if(spawn_error)return spawn_error;*pid=123;return 0;
}
#define fcntl checked_fcntl
#define ioctl checked_ioctl
'''
code+=typedef(native,'AlixSpawnState')+'\n'+function_definition(native,'static int\n_MD_alix_spawn(')+'\n'
code+=r'''
#undef fcntl
#undef ioctl
static int pipes[3][2];static PRFilePrivate secrets[3];static PRFileDesc descriptors[3];
static PRProcessAttr attributes;
static char *arguments[]={"program",NULL};
static void exercise(unsigned failure,bool aliases){
    for(unsigned i=0;i<3;++i){int value=1;CHECK(!ioctl(pipes[i][0],FIONBIO,&value));secrets[i].md.osfd=aliases?pipes[0][0]:pipes[i][0];}
    bool before[256];for(unsigned i=0;i<256;++i)before[i]=fcntl((int)i,F_GETFD)>=0;
    calls=0;fail_at=failure;injected=false;pid_t pid=-777;int error=_MD_alix_spawn(&pid,"/native-program",arguments,NULL,&attributes);
    unsigned observed=calls;fail_at=0;
    if(failure){CHECK(injected && error && pid==-777);}else if(spawn_error){CHECK(error==spawn_error && pid==-777);}else CHECK(!error && pid==123);
    for(unsigned i=0;i<3;++i){int fd=secrets[i].md.osfd;CHECK((fcntl(fd,F_GETFL)&O_NONBLOCK)==((failure||spawn_error)?O_NONBLOCK:0));}
    for(unsigned i=0;i<256;++i)CHECK(before[i]==(fcntl((int)i,F_GETFD)>=0));CHECK(!allocations);
    if(!failure && !spawn_error){for(unsigned point=1;point<=observed;++point)exercise(point,aliases);}
}
int main(void){
    for(unsigned i=0;i<3;++i){CHECK(!pipe(pipes[i]));descriptors[i].secret=&secrets[i];}
    attributes=(PRProcessAttr){&descriptors[0],&descriptors[1],&descriptors[2],"/native-cwd","NSPR_INHERIT_FDS=new"};
    exercise(0,false);exercise(0,true);spawn_error=ENOENT;exercise(0,false);exercise(0,true);
    for(unsigned i=0;i<3;++i)CHECK(!close(pipes[i][0])&&!close(pipes[i][1]));
    CHECK(!allocations);puts("NSPR_SPAWN_CONTRACT: PASS every_preparation_fault=1 memory=1 fd_cleanup=1 status_restore=1 aliases=1 environment=1");return 0;
}
'''
compile_and_run('nspr-spawn-contract',code)
print('Actual NSPR spawn helper: PASS every preparation failure, environment ownership, alias/nonblock restoration and descriptor cleanup')
