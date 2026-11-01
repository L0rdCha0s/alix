#!/usr/bin/env python3
"""Verify atomic owned FD-table inheritance and exec-time CLOEXEC filtering."""
from pathlib import Path
import contextlib, io, os, shlex, sys
sys.dont_write_bytecode=True
from audio_stream_contract_test import ROOT,compile_and_run
import fd_retirement_contract_test as retirement

tree=Path(os.environ.get('FD_CLONE_SOURCE_TREE',str(ROOT/'build/ports/zen/fd-clone')))
previous_tree=os.environ.get('FD_TABLE_SOURCE_TREE')
captured=[]
original=retirement.compile_and_run
try:
    os.environ['FD_TABLE_SOURCE_TREE']=str(tree)
    retirement.compile_and_run=lambda label,program:captured.append(program)
    with contextlib.redirect_stdout(io.StringIO()):retirement.main()
finally:
    retirement.compile_and_run=original
    if previous_tree is None:os.environ.pop('FD_TABLE_SOURCE_TREE',None)
    else:os.environ['FD_TABLE_SOURCE_TREE']=previous_tree
code=captured[0].replace('int main(void) {','static int retirement_main(void) {',1)
needle='static void spinlock_preempt_disable(void)'
assert needle in code
if 'spinlock_preempt_disabled(void)' not in code:
    code=code.replace(needle,'static bool spinlock_preempt_disabled(void) { return preempt_depth!=0; }\n'+needle,1)
code+=r'''
static int clone_owned(fd_table_t *source,bool exec,fd_table_t **out) {
    spinlock_preempt_disable();int result=fd_table_clone_deferred(source,exec,out);spinlock_preempt_enable();return result;
}
static fd_description_t *pin_owned(fd_table_t *table,int fd,uint32_t *flags) {
    fd_description_t *out=NULL;CHECK(!fd_table_pin(table,fd,&out,flags));return out;
}
static void snapshots(void) {
    uint64_t before=closes;fd_retirement_queue_t *q=fd_retirement_queue_create(32);CHECK(q);
    fd_table_t *source=fd_table_create_deferred(8,q),*all=NULL,*exec=NULL;CHECK(source);
    fd_description_t *a=new_description(q),*b=new_description(q);CHECK(a&&b);
    CHECK(fd_table_install_at(source,3,a,0)==3&&fd_table_install_at(source,4,a,FD_TABLE_CLOEXEC)==4&&
          fd_table_install_at(source,5,b,FD_TABLE_CLOEXEC)==5);
    fd_description_put(a);fd_description_put(b);
    CHECK(!clone_owned(source,false,&all)&&!clone_owned(source,true,&exec));
    uint32_t flags=99;fd_description_t *left=pin_owned(all,3,&flags);CHECK(flags==0);
    fd_description_t *right=pin_owned(exec,3,&flags);CHECK(left==right&&flags==0);
    CHECK(fd_description_context(left)==fd_description_context(right));
    fd_description_put(left);fd_description_put(right);
    CHECK(!fd_table_set_flags(all,3,FD_TABLE_CLOEXEC)&&!fd_table_get_flags(source,3,&flags)&&flags==0);
    CHECK(!fd_table_get_flags(all,4,&flags)&&flags==FD_TABLE_CLOEXEC);
    fd_description_t *missing=(void*)1;CHECK(fd_table_pin(exec,4,&missing,NULL)==-EBADF&&!missing);
    fd_table_put(source);while(drain(q,32)){}CHECK(closes==before);
    CHECK(!fd_table_close(all,3));left=pin_owned(exec,3,NULL);fd_description_put(left);
    fd_table_put(all);while(drain(q,32)){}CHECK(closes==before+1);
    fd_table_put(exec);while(drain(q,32)){}CHECK(closes==before+2);destroy_empty(q);
}
static void rollback(void) {
    fd_retirement_queue_t *q=fd_retirement_queue_create(8);fd_table_t *source=fd_table_create_deferred(8,q);CHECK(source);
    fd_description_t *a=new_description(q),*b=new_description(q);CHECK(a&&b);
    CHECK(fd_table_install_at(source,2,a,0)==2&&fd_table_install_at(source,4,b,0)==4);
    fd_description_put(a);fd_description_put(b);fd_table_t *out=(void*)1;
    CHECK(fd_table_clone_deferred(source,false,&out)==-EINVAL&&!out);
    fail_allocations=1;CHECK(clone_owned(source,false,&out)==-ENOMEM&&!out&&snapshot(q).live==3);
    uint32_t a_refs=a->references,b_refs=b->references;b->references=UINT32_MAX;
    CHECK(clone_owned(source,false,&out)==-EOVERFLOW&&!out&&a->references==a_refs+1);
    b->references=b_refs;while(drain(q,32)){}CHECK(a->references==a_refs&&b->references==b_refs);
    fd_table_shutdown(source);CHECK(clone_owned(source,false,&out)==-ECANCELED&&!out);
    fd_table_put(source);while(drain(q,32)){}destroy_empty(q);
}
typedef struct {fd_table_t *source;fd_description_t *description;fd_retirement_queue_t *queue;bool replace;} clone_arg_t;
static void *clone_worker(void *argument) {
    clone_arg_t *a=argument;
    for(unsigned i=0;i<256;++i) {
        if(a->replace) {
            int result=fd_table_close(a->source,3);CHECK(result==0||result==-EBADF);
            result=fd_table_install_at(a->source,3,a->description,i&1?FD_TABLE_CLOEXEC:0);CHECK(result==3);
        } else {
            fd_table_t *copy=NULL;CHECK(!clone_owned(a->source,false,&copy));
            fd_description_t *pin=NULL;uint32_t flags=0;int result=fd_table_pin(copy,3,&pin,&flags);
            CHECK((result==-EBADF&&!pin)||(result==0&&pin==a->description&&!(flags&~FD_TABLE_CLOEXEC)));
            fd_description_put(pin);fd_table_put(copy);
        }
        (void)drain(a->queue,8);
    }
    return NULL;
}
static void concurrent_snapshots(void) {
    fd_retirement_queue_t *q=fd_retirement_queue_create(4096);fd_table_t *s=fd_table_create_deferred(8,q);
    fd_description_t *d=new_description(q);CHECK(q&&s&&d&&fd_table_install_at(s,3,d,0)==3);
    clone_arg_t *args=calloc(8,sizeof(*args));pthread_t *threads=calloc(8,sizeof(*threads));CHECK(args&&threads);
    for(unsigned i=0;i<8;++i){args[i]=(clone_arg_t){s,d,q,i==0};CHECK(!pthread_create(&threads[i],NULL,clone_worker,&args[i]));}
    for(unsigned i=0;i<8;++i)CHECK(!pthread_join(threads[i],NULL));
    fd_description_put(d);fd_table_put(s);while(drain(q,32)){}destroy_empty(q);free(threads);free(args);
}
int main(void) {
    CHECK(!retirement_main());snapshots();rollback();concurrent_snapshots();
    CHECK(!allocations&&!held_locks&&!preempt_depth);
    puts("FD_CLONE: PASS shared_descriptions=1 separate_flags=1 cloexec=1 rollback=1 concurrent=1792");return 0;
}
'''
previous=os.environ.get('HOST_CC')
try:
    os.environ['HOST_CC']=shlex.join(shlex.split(previous or 'cc')+['-pthread'])
    compile_and_run('fd-clone',code)
finally:
    if previous is None:os.environ.pop('HOST_CC',None)
    else:os.environ['HOST_CC']=previous
print('Deferred descriptor-table inheritance contracts passed')
