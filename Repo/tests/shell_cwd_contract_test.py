#!/usr/bin/env python3
"""Production per-shell cwd and auth-home lifetime regression."""
import contextlib,io,os,shlex,sys
sys.dont_write_bytecode=True
from audio_stream_contract_test import ROOT,compile_and_run,function_definition
import vfs_bridge_contract_test as bridge_test

def main():
    captured=[];original=bridge_test.compile_and_run
    bridge_test.compile_and_run=lambda label,program:captured.append(program)
    try:
        with contextlib.redirect_stdout(io.StringIO()):bridge_test.main()
    finally:bridge_test.compile_and_run=original
    code=captured[0].replace('int main(void) {','static int initial_bridge_main(void) {',1)
    # Kernel heap frees are allowed under metadata spinlocks. Destructors retain
    # their separate explicit no-lock assertions below and in the base harness.
    code=code.replace('static void owned_free(void *p) { CHECK(!locks);','static void owned_free(void *p) {',1)
    code=code.replace('static _Thread_local unsigned locks,preempt,fail_allocations;','static _Thread_local unsigned locks,preempt,fail_allocations,calloc_countdown;',1)
    code=code.replace('static void *owned_calloc(size_t n,size_t size) { CHECK(!locks);','static void *owned_calloc(size_t n,size_t size) { CHECK(!locks); if(calloc_countdown && --calloc_countdown==0) return NULL;',1)
    def stripped(path):return '\n'.join(l for l in path.read_text().splitlines() if not l.startswith('#include '))
    stage=ROOT/os.environ.get('ALIX_SHELL_SOURCE','.')
    old=stripped(ROOT/'build/ports/zen/vfs-bridge/src/kernel/io/vfs_service.c')
    pre=r'''
typedef struct shell_actor shell_actor_t;
typedef struct shell_state {
    vfs_node_t *cwd; spinlock_t cwd_lock; fd_description_t *cwd_owner,*lifetime_owner; uint64_t owner_pid;
    spinlock_t actors_lock; shell_actor_t *actors; size_t actor_live; bool actors_closing,actors_paused;
    void (*stream_fn)(void *,const char *,size_t);void *stream_context;
} shell_state_t;
static void shell_actors_init(shell_state_t *s) { spinlock_init(&s->actors_lock);s->actors=NULL;s->actor_live=0;s->actors_closing=s->actors_paused=false; }
int fd_close(int fd) { (void)fd; CHECK(cleanup_worker && !locks && !preempt); return 0; }
static void shell_clear_active_shell(shell_state_t *s) { (void)s;CHECK(cleanup_worker && !locks && !preempt); }
static void shell_clear_console_tap_if_matches(void (*f)(void *,const char *,size_t),void *ctx) { (void)f;(void)ctx;CHECK(cleanup_worker && !locks && !preempt); }
'''
    assert old in code
    code=code.replace(old,pre+stripped(stage/'src/kernel/shell_cwd.c')+'\n'+stripped(stage/'src/kernel/io/vfs_service.c'),1)
    marker='void io_vfs_execute(io_request_t *r,io_service_result_t *result,fd_retirement_queue_t *q) {'
    code=code.replace(marker,'''static vfs_node_t *expected_shell_base;
static void (*shell_backend_hook)(io_request_t *);
'''+marker,1)
    code=code.replace('    vfs_node_t *cwd=io_request_cwd(r); CHECK(cwd && cwd->refs==1 && cwd->directory);',
                      '    if(shell_backend_hook) shell_backend_hook(r);\n    vfs_node_t *cwd=io_request_cwd(r); CHECK(cwd && cwd->refs==1 && cwd->directory);\n    if(expected_shell_base) CHECK(cwd==expected_shell_base);',1)
    code=code.replace('int process_io_wait_current(io_request_status_t *out) {',r'''
#include <setjmp.h>
static jmp_buf *abandon_environment;
static bool abandon_auth;
int process_io_wait_current(io_request_status_t *out) {''',1)
    code=code.replace('    CHECK(!preempt && !locks && registered);','''    CHECK(!preempt && !locks && registered);
    if(abandon_auth) {
        model_service->active=io_queue_take(model_service->queue); CHECK(model_service->active==registered);
        CHECK(!io_request_waiter_abandon(registered)); registered=NULL; longjmp(*abandon_environment,1);
    }''',1)
    source=(stage/'src/kernel/shell_service.c').read_text()
    start=source.index('typedef struct shell_session\n')
    end=source.index('} shell_login_job_t;',start)+len('} shell_login_job_t;')
    code+='\n#define PROCESS_NAME_MAX 32\n'+source[start:end]+r'''
static uint64_t login_ok,session_destructions,job_destructions;
static char *next_home;
typedef struct { uint32_t uid,gid; char *name,*home; } user_record_t;
static bool user_auth_lookup(const char *name,user_record_t *out) {
    CHECK(locks && !strcmp(name,"alice") && next_home); memset(out,0,sizeof(*out)); out->uid=37;out->gid=41;out->home=next_home;next_home=NULL;return true;
}
static bool user_auth_check_password(const char *user,const char *password) { CHECK(locks);return !strcmp(user,"alice")&&!strcmp(password,"pw"); }
static void user_auth_free_record(user_record_t *record) { if(record->name)free(record->name);if(record->home)free(record->home);memset(record,0,sizeof(*record)); }
static bool shell_session_append_locked(shell_session_t *session,const char *text,size_t bytes) {
    CHECK(locks && session->lock.value); if(bytes==9&&!memcmp(text,"login ok\n",9))++login_ok;return true;
}
'''
    for sig in ('static inline void shell_session_lock(', 'static inline void shell_session_unlock(',
                'static char *shellsvc_trim_whitespace(', 'static void shell_session_auth_reset(',
                'static bool shell_session_handle_login(', 'static int shell_session_lifetime_close(',
                'static int shell_login_job_close('):
        body=function_definition(source,sig)
        if sig.startswith('static int shell_session_lifetime_close'):
            body=body.replace('{','{\n    CHECK(cleanup_worker && !locks && !preempt); ++session_destructions;',1)
        if sig.startswith('static int shell_login_job_close'):
            body=body.replace('{','{\n    CHECK(cleanup_worker && !locks && !preempt); ++job_destructions;',1)
        code+=body+'\n'
    for name in ('shell_session_lifetime_ops','shell_login_job_ops'):
        code+=next(line for line in source.splitlines() if line.startswith('static const fd_ops_t '+name))+'\n'
    code+=function_definition(source,'static int shell_session_login_dispatch_locked(')+r'''
static char *copy_text(const char *text) { size_t n=strlen(text)+1;char *copy=calloc(n,1);CHECK(copy);memcpy(copy,text,n);return copy; }
static shell_state_t *make_shell(void) {
    shell_state_t *s=calloc(1,sizeof(*s));CHECK(s);s->owner_pid=2;
    spinlock_preempt_disable();CHECK(shell_cwd_init(s));spinlock_preempt_enable();return s;
}
static void discard_shell(shell_state_t *s) { shell_cwd_destroy(s);free(s); }
static void change_owner_during_wait(io_request_t *r) { (void)r;install(model_target,node_owner(new_node())); }
static void independent_sessions(void) {
    shell_state_t *a=make_shell();vfs_node_t *base_a=a->cwd;
    CHECK(io_vfs_change_cwd_kernel("B",2)==0);check_clean();shell_state_t *b=make_shell();vfs_node_t *base_b=b->cwd;
    CHECK(io_vfs_change_cwd_kernel("owner-moved",2)==0);check_clean();CHECK(current_process->cwd!=base_a&&current_process->cwd!=base_b);
    expected_shell_base=base_a;shell_backend_hook=change_owner_during_wait;
    CHECK(io_vfs_change_shell_cwd_kernel("child",a)==0);shell_backend_hook=NULL;expected_shell_base=NULL;check_clean();
    vfs_node_t *a_child=a->cwd;CHECK(a_child!=base_a && b->cwd==base_b);
    CHECK(shell_cwd_apply_current(b) && current_process->cwd==base_b);
    expected_shell_base=base_b;CHECK(io_vfs_change_shell_cwd_kernel("other",b)==0);expected_shell_base=NULL;check_clean();
    CHECK(a->cwd==a_child && b->cwd!=base_b && a->cwd!=b->cwd);
    fd_description_t *before=a->cwd_owner;fail_allocations=1;CHECK(io_vfs_change_shell_cwd_kernel("oom",a)==-ENOMEM && a->cwd_owner==before);check_clean();
    discard_shell(a);discard_shell(b);drain();
}
static shell_session_t *make_session(void) {
    shell_session_t *s=calloc(1,sizeof(*s));CHECK(s);spinlock_init(&s->lock);s->owner=current_process;s->state.owner_pid=1;
    spinlock_preempt_disable();CHECK(shell_cwd_init(&s->state));
    s->lifetime=fd_description_create_deferred(&shell_session_lifetime_ops,s,g_process_retirement);CHECK(s->lifetime);s->state.lifetime_owner=s->lifetime;
    spinlock_preempt_enable();return s;
}
static int login_line(shell_session_t *s,const char *text) { char *line=copy_text(text);shell_session_lock(s);return shell_session_login_dispatch_locked(s,line); }
static shell_session_t *auth_session;
static void close_auth_during_wait(io_request_t *r) {
    (void)r;CHECK(!locks&&!preempt);shell_session_lock(auth_session);auth_session->closed=true;shell_session_unlock(auth_session);fd_description_put(auth_session->lifetime);
    CHECK(session_destructions==0);
}
static void drain_prior_auth_job(io_request_t *r) {
    CHECK(!strcmp((const char *)((io_vfs_operation_t *)io_request_buffer(r))->data,"/home/alice"));
    CHECK(auth_session->auth_busy && auth_session->auth_generation==2);
    (void)fd_retirement_queue_drain(g_process_retirement,64);
    CHECK(auth_session->auth_busy && auth_session->auth_generation==2);
}
static void authentication_home(void) {
    shell_session_t *s=make_session();auth_session=s;vfs_node_t *base=s->state.cwd,*owner_default=current_process->cwd;
    next_home=copy_text("home/alice");CHECK(login_line(s,"alice")==0 && s->awaiting_password && !s->auth_busy);
    /* Keep generation one's cleanup pending until generation two waits. */
    shell_backend_hook=drain_prior_auth_job;expected_shell_base=base;uint64_t before=login_ok;
    CHECK(login_line(s,"pw")==0);shell_backend_hook=NULL;expected_shell_base=NULL;check_clean();
    CHECK(login_ok==before+1 && s->authenticated && !s->auth_busy && s->state.cwd!=base && current_process->cwd==owner_default);
    CHECK(shell_cwd_apply_current(&s->state) && current_process->cwd==s->state.cwd);
    s->closed=true;fd_description_put(s->lifetime);drain();CHECK(session_destructions==1);session_destructions=0;

    s=make_session();auth_session=s;next_home=copy_text("/home/alice");CHECK(login_line(s,"alice")==0);drain();
    shell_backend_hook=close_auth_during_wait;before=login_ok;CHECK(login_line(s,"pw")==-1);
    shell_backend_hook=NULL;CHECK(session_destructions==0 && login_ok==before);check_clean();CHECK(session_destructions==1);session_destructions=0;

    s=make_session();auth_session=s;next_home=copy_text("/home/alice");CHECK(login_line(s,"alice")==0);drain();
    abandon_environment=calloc(1,sizeof(*abandon_environment));CHECK(abandon_environment);abandon_auth=true;
    if(setjmp(*abandon_environment)==0) { (void)login_line(s,"pw");CHECK(false); }
    abandon_auth=false;CHECK(s->auth_busy && !registered && model_service->active);
    run_worker(model_service);check_clean();CHECK(!s->auth_busy && !session_destructions);
    free(abandon_environment);abandon_environment=NULL;s->closed=true;fd_description_put(s->lifetime);drain();CHECK(session_destructions==1);session_destructions=0;
}
static void authentication_failures(void) {
    shell_session_t *s=make_session();
    for(unsigned nth=1;nth<=2;++nth) {
        char *line=copy_text("alice");calloc_countdown=nth;shell_session_lock(s);
        CHECK(shell_session_login_dispatch_locked(s,line)==-1 && !s->auth_busy && !s->authenticated && s->lifetime->references==1);
        CHECK(!calloc_countdown);drain();
    }
    next_home=copy_text("/home/alice");CHECK(login_line(s,"alice")==0);drain();
    vfs_node_t *before=s->state.cwd;unsigned handled=worker_calls;char *line=copy_text("pw");calloc_countdown=3;shell_session_lock(s);
    CHECK(shell_session_login_dispatch_locked(s,line)==0 && s->authenticated && !s->auth_busy && s->state.cwd==before && worker_calls==handled);
    CHECK(!calloc_countdown);check_clean();s->closed=true;fd_description_put(s->lifetime);drain();
    s=make_session();next_home=copy_text("/home/alice");CHECK(login_line(s,"alice")==0);drain();
    uint64_t ok_before=login_ok;fail_register=true;CHECK(login_line(s,"pw")==-1 && !s->auth_busy && login_ok==ok_before);fail_register=false;
    check_clean();s->closed=true;fd_description_put(s->lifetime);drain();session_destructions=0;
}
typedef struct { shell_state_t *shell;fd_description_t *a,*b;unsigned iterations;bool writer; } shell_race_t;
static void *shell_racer(void *opaque) {
    shell_race_t *a=opaque;
    for(unsigned i=0;i<a->iterations;++i) { spinlock_preempt_disable();
        if(a->writer) { fd_description_t *d=i&1?a->a:a->b;CHECK(fd_description_get(d));CHECK(!shell_cwd_replace_owned(a->shell,d)); }
        else { fd_description_t *d=shell_cwd_acquire(a->shell);CHECK(d==a->a||d==a->b);fd_description_put(d); }
        spinlock_preempt_enable();
    }return NULL;
}
static void concurrent_shell_owners(void) {
    enum{N=4,ITERATIONS=4000};shell_state_t *shell=make_shell();fd_description_t *a=node_owner(new_node()),*b=node_owner(new_node());
    spinlock_preempt_disable();CHECK(fd_description_get(a));CHECK(!shell_cwd_replace_owned(shell,a));spinlock_preempt_enable();
    pthread_t *threads=calloc(N,sizeof(*threads));shell_race_t *args=calloc(N,sizeof(*args));CHECK(threads&&args);
    for(unsigned i=0;i<N;++i){args[i]=(shell_race_t){shell,a,b,ITERATIONS,i==0};CHECK(!pthread_create(&threads[i],NULL,shell_racer,&args[i]));}
    for(unsigned i=0;i<N;++i)CHECK(!pthread_join(threads[i],NULL));free(args);free(threads);discard_shell(shell);fd_description_put(a);fd_description_put(b);drain();
}
int main(void) {
    CHECK(!initial_bridge_main());g_process_retirement=NULL;g_process_retirement_worker=NULL;g_process_retirement_start=0;g_vfs_service_start=0;root=NULL;
    process_resource_system_init();root=new_node();current_process=new_process(NULL);current_process->pid=1;install(current_process,node_owner(new_node()));process_set_identity(current_process,37,41);
    model_target=new_process(current_process);model_target->pid=2;current_process->next=model_target;g_process_list=current_process;drain();CHECK(io_vfs_service_start());model_service=g_vfs_service;
    independent_sessions();authentication_home();authentication_failures();concurrent_shell_owners();check_clean();
    drop_process(model_target);drop_process(current_process);current_process=NULL;g_process_list=NULL;drain();
    io_queue_shutdown(model_service->queue);CHECK(!io_queue_destroy(model_service->queue));free(model_service->result);free(model_service);g_vfs_service=NULL;
    cleanup_worker=true;vfs_node_release(root);cleanup_worker=false;fd_retirement_queue_shutdown(g_process_retirement);CHECK(!fd_retirement_queue_destroy(g_process_retirement));
    CHECK(!allocations&&!preempt&&!locks&&!registered);
    puts("shell cwd: PASS two independent bases, owner changes, unlocked auth, close/cancel lifetime, 16000 concurrent owners");return 0;
}
'''
    previous=os.environ.get('HOST_CC');os.environ['HOST_CC']=shlex.join(shlex.split(previous or 'cc')+['-pthread'])
    try:compile_and_run('shell-cwd',code)
    finally:
        if previous is None:os.environ.pop('HOST_CC',None)
        else:os.environ['HOST_CC']=previous
    print('per-shell cwd and auth-home production contracts: PASS')

if __name__=='__main__':main()
