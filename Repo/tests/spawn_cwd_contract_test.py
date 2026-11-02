#!/usr/bin/env python3
"""Execute production cwd-action capture/application and owned-path failure paths."""
import re
import sys
sys.dont_write_bytecode=True
from audio_stream_contract_test import ROOT,compile_and_run,function_definition
from audio_hda_state_test import typedef

kernel=(ROOT/'src/kernel/io/process.c').read_text()
library=(ROOT/'user/lib/spawn.c').read_text()
wire=(ROOT/'include/syscall_defs.h').read_text()
code=r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#define CHECK(c) do {if(!(c)){fprintf(stderr,"cwd contract %d: %s\n",__LINE__,#c);abort();}}while(0)
static unsigned allocations;
static bool fail_next;
static void *owned_malloc(size_t n){if(fail_next){fail_next=false;return NULL;}void*p=malloc(n);if(p)++allocations;return p;}
static void *owned_calloc(size_t n,size_t s){if(fail_next){fail_next=false;return NULL;}void*p=calloc(n,s);if(p)++allocations;return p;}
static void *owned_realloc(void *p,size_t n){if(fail_next){fail_next=false;return NULL;}void*q=realloc(p,n);if(q&&!p)++allocations;return q;}
static void owned_free(void *p){if(p){CHECK(allocations);--allocations;free(p);}}
static char *owned_strdup(const char *s){size_t n=strlen(s)+1;char*p=owned_malloc(n);if(p)memcpy(p,s,n);return p;}
#define malloc owned_malloc
#define calloc owned_calloc
#define realloc owned_realloc
#define free owned_free
#define strdup owned_strdup
#define ACTIONS_MAGIC 0x53504641u
#define ACTION_LIMIT 256u
#define CHILD_ARGUMENTS 256u
#define VFS_PATH_MAX 4096u
#define FD_TABLE_MAX_ENTRIES 256u
#define SYSCALL_OPEN_CLOEXEC (1u<<17)
#define FD_TABLE_CLOEXEC 1u
'''
for name in ('CLOSE','DUP2','OPEN','CHDIR'):
    code+=re.search(r'^#define SYSCALL_SPAWN_'+name+r'[^\n]*',wire,re.M).group(0)+'\n'
code+=typedef(wire,'syscall_spawn_action_t')+'\n'+typedef(wire,'syscall_spawn_t')+'\n'
code+=typedef((ROOT/'include/spawn.h').read_text(),'posix_spawn_file_actions_t')+'\n'
for signature in ('int posix_spawn_file_actions_init(', 'int posix_spawn_file_actions_destroy(',
                  'static int add_action(', 'int posix_spawn_file_actions_addchdir_np('):
    code+=function_definition(library,signature)+'\n'
code+=typedef(kernel,'child_action_t')+'\n'+typedef(kernel,'child_launch_work_t')+'\n'
code+=r'''
typedef struct {unsigned refs,id;bool directory;} vfs_node_t;
typedef struct {vfs_node_t *node;unsigned refs;} fd_description_t;
typedef struct {unsigned marker;} fd_table_t;
typedef struct {struct {fd_description_t *cwd;fd_table_t *files;uint32_t uid,gid;} launch;} child_record_t;
static vfs_node_t nodes[4]={{1,0,true},{1,1,true},{1,2,true},{1,3,false}};
static bool fail_cwd,fail_clone;
static unsigned guards;
static void spinlock_preempt_disable(void){++guards;}
static void spinlock_preempt_enable(void){CHECK(guards);--guards;}
static void *fd_description_context(fd_description_t *d){return d->node;}
static bool vfs_is_dir(vfs_node_t *n){return n->directory;}
static void vfs_node_release_owned(vfs_node_t *n){CHECK(n->refs>1);--n->refs;}
static int vfs_resolve_owned(vfs_node_t *base,const char *path,vfs_node_t **out){
    *out=NULL;unsigned index;
    if(!strcmp(path,"/a"))index=1;else if(!strcmp(path,"nested")&&base->id==1)index=2;
    else if(!strcmp(path,"file"))index=3;else return -ENOENT;
    ++nodes[index].refs;*out=&nodes[index];return 0;
}
static fd_description_t *process_cwd_description_create_owned(vfs_node_t *node){
    CHECK(node->directory&&node->refs>1);if(fail_cwd)return NULL;fd_description_t *d=calloc(1,sizeof(*d));if(d){d->node=node;d->refs=1;}return d;
}
static void fd_description_put(fd_description_t *d){if(d&&!--d->refs){vfs_node_release_owned(d->node);free(d);}}
static void fd_table_put(fd_table_t *t){free(t);}
static int fd_table_clone_deferred(fd_table_t *t,bool close_exec,fd_table_t **out){CHECK(guards&&t&&close_exec);*out=NULL;if(fail_clone)return -ENOMEM;*out=calloc(1,sizeof(**out));return *out?0:-ENOMEM;}
static int fd_table_close(fd_table_t *t,int fd){(void)t;(void)fd;abort();}
static int fd_table_set_flags(fd_table_t *t,int fd,uint32_t f){(void)t;(void)fd;(void)f;abort();}
static int fd_table_dup2(fd_table_t*t,int a,int b){(void)t;(void)a;(void)b;abort();}
static int fd_table_install_at(fd_table_t*t,int a,fd_description_t*d,uint32_t f){(void)t;(void)a;(void)d;(void)f;abort();}
static void *process_fd_retirement_queue(void){abort();}
static int io_vfs_open_owned(void*a,const char*b,uint32_t c,uint32_t d,uint32_t e,void*f,fd_description_t**g){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;abort();}
static bool user_copy_from_user(void *out,const void *in,size_t n){if(!in)return false;memcpy(out,in,n);return true;}
static int user_copy_cstring_from_user(char*out,size_t n,const char*in,size_t*length){if(!in)return -EFAULT;size_t count=strlen(in);if(count>=n)return -ENAMETOOLONG;memcpy(out,in,count+1);if(length)*length=count;return 0;}
'''
code+=function_definition(kernel,'static int child_capture_actions(')+'\n'
code+=function_definition(kernel,'static int child_apply_actions(')+'\n'
code+=r'''
static void run_case(const char *second,int expected,bool oom,bool clone_failure){
    posix_spawn_file_actions_t *actions=calloc(1,sizeof(*actions));child_launch_work_t *work=calloc(1,sizeof(*work)+1024);child_record_t *record=calloc(1,sizeof(*record));CHECK(actions&&work&&record);
    ++nodes[0].refs;record->launch.cwd=process_cwd_description_create_owned(&nodes[0]);record->launch.files=calloc(1,sizeof(fd_table_t));CHECK(record->launch.cwd&&record->launch.files);
    char *path=strdup("/a");CHECK(path);errno=EDOM;CHECK(!posix_spawn_file_actions_init(actions)&&!posix_spawn_file_actions_addchdir_np(actions,path)&&errno==EDOM);
    path[1]='x';free(path);CHECK(!posix_spawn_file_actions_addchdir_np(actions,second));
    syscall_spawn_t specification={.actions=(uintptr_t)actions->actions,.action_count=actions->count};size_t used=0;
    CHECK(!child_capture_actions(&specification,work,1024,&used) && !strcmp(work->data,"/a") && work->action_count==2);
    CHECK(!posix_spawn_file_actions_destroy(actions));free(actions);
    fail_cwd=oom;fail_clone=clone_failure;CHECK(child_apply_actions(record,work)==expected);fail_cwd=fail_clone=false;
    if(!expected)CHECK(record->launch.cwd->node==&nodes[2]);
    fd_description_put(record->launch.cwd);fd_table_put(record->launch.files);free(record);free(work);
    for(unsigned i=0;i<4;++i)CHECK(nodes[i].refs==1);CHECK(!guards&&!allocations);
}
int main(void){
    run_case("nested",0,false,false);run_case("missing",-ENOENT,false,false);run_case("file",-ENOTDIR,false,false);
    run_case("nested",-ENOMEM,true,false);run_case("nested",-ENOMEM,false,true);
    posix_spawn_file_actions_t *actions=calloc(1,sizeof(*actions));CHECK(actions&&!posix_spawn_file_actions_init(actions));
    errno=EDOM;CHECK(posix_spawn_file_actions_addchdir_np(actions,NULL)==EINVAL&&errno==EDOM&&!actions->count);
    fail_next=true;CHECK(posix_spawn_file_actions_addchdir_np(actions,"/a")==ENOMEM&&!actions->count&&errno==EDOM);
    CHECK(!posix_spawn_file_actions_destroy(actions));free(actions);CHECK(!allocations);
    puts("SPAWN_CWD_CONTRACT: PASS owned_paths=1 capture=1 cwd_refs=1 ordered=1 errors=1 oom=1");return 0;
}
'''
compile_and_run('spawn-cwd-contract',code)
print('Production spawn cwd contracts: PASS copied paths, ordered actions, directory ownership and allocation/failure cleanup')
