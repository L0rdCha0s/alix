#!/usr/bin/env python3
"""Stage signal integration hunks while preserving the active kernel/runtime."""
from pathlib import Path
import difflib
import hashlib
import json
import sys

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
PENDING=HERE/"pending"
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/"tests"))
from audio_stream_contract_test import function_definition

def replace(text,old,new):
    if text.count(old)!=1:raise RuntimeError("source context changed: "+old[:100])
    return text.replace(old,new,1)

def main():
    changes={};originals={}
    def read(name): originals[name]=(ROOT/name).read_text();return originals[name]
    name="include/syscall_defs.h";text=read(name)
    text=replace(text,"    SYSCALL_TIMEZONE_INFO = 58,","""    SYSCALL_TIMEZONE_INFO = 58,
    SYSCALL_SIGACTION = 59,
    SYSCALL_SIGPROCMASK = 60,
    SYSCALL_SIGALTSTACK = 61,
    SYSCALL_SIGRETURN = 62,
    SYSCALL_RAISE = 63,
    SYSCALL_KILL = 64,
    SYSCALL_SLEEP_INTERRUPTIBLE = 65,""")
    text=replace(text,"#define SYSCALL_FUTEX_WAIT_FOREVER", "#define SYSCALL_FUTEX_INTERRUPTED (-4)\n#define SYSCALL_FUTEX_WAIT_FOREVER")
    changes[name]=text
    name="include/process_internal.h";text=read(name)
    text=replace(text,'#include "process.h"','#include "process.h"\n#include "process_signal.h"')
    text=replace(text,"    bool futex_notified;","""    bool futex_notified;
    bool futex_interrupted;
    alix_sigset_t signal_mask,signal_pending;
    alix_siginfo_t signal_info[ALIX_SIGNAL_COUNT];
    alix_stack_t signal_altstack;
    struct process_signal_frame *signal_frames;
    uint64_t signal_sequence;
    uint32_t signal_depth;
    int signal_fault_status;
    bool signal_onstack,signal_sleeping,signal_sleep_interrupted;
    wait_queue_t signal_wait_queue;""")
    text=replace(text,"    uint64_t user_exit_owner_tid;","""    uint64_t user_exit_owner_tid;
    alix_sigaction_t signal_actions[ALIX_SIGNAL_COUNT];
    alix_sigset_t signal_pending;
    alix_siginfo_t signal_info[ALIX_SIGNAL_COUNT];""")
    text=replace(text,"extern const uint8_t g_user_preempt_stub[66];","extern const uint8_t g_user_preempt_stub[ALIX_PREEMPT_STUB_SIZE];\nextern const uint8_t g_user_signal_restorer[ALIX_SIGNAL_RESTORER_SIZE];")
    text=replace(text,"#define USER_PREEMPT_STUB_SIZE 66u","#define USER_PREEMPT_STUB_SIZE ALIX_PREEMPT_STUB_SIZE")
    text=replace(text,"bool process_vm_fault_locked(","bool process_vm_contains_locked(process_t *process, uintptr_t address);\nbool process_vm_fault_locked(")
    changes[name]=text
    name="src/kernel/process/process_vm.c";text=read(name)
    text=replace(text,"bool process_vm_fault_locked(","bool process_vm_contains_locked(process_t *process, uintptr_t address)\n{\n    return process && vm_find_area(process->vm_areas, address) != NULL;\n}\n\nbool process_vm_fault_locked(")
    changes[name]=text
    name="src/kernel/process/process_thread.c";text=read(name)
    text=replace(text,"    thread->is_user = is_user_thread;","""    thread->is_user = is_user_thread;
    thread->signal_altstack.ss_flags = ALIX_SS_DISABLE;
    thread_t *signal_creator = current_thread_local();
    if (is_user_thread && signal_creator && signal_creator->process == process)
        thread->signal_mask = signal_creator->signal_mask;""")
    changes[name]=text
    name="src/kernel/process/process_common.c";text=read(name)
    text=replace(text,"const uint8_t g_user_preempt_stub[66] = {","""const uint8_t g_user_signal_restorer[ALIX_SIGNAL_RESTORER_SIZE] = {
    0x48, 0x89, 0xE7,                       /* mov rdi,rsp: exact user-frame address */
    0xB8, SYSCALL_SIGRETURN, 0, 0, 0,        /* mov eax,SIGRETURN */
    0xCD, 0x80, 0x0F, 0x0B                 /* int80; ud2 if an invalid return fails */
};

const uint8_t g_user_preempt_stub[ALIX_PREEMPT_STUB_SIZE] = {
    0x48, 0x8D, 0x64, 0x24, 0x80,          /* lea rsp,[rsp-128]: preserve red zone/flags */""")
    text=replace(text,"    0xC3                                /* ret */","    0xC2, 0x80, 0x00                    /* ret 128: resume with original RSP */")
    body=function_definition(text,"static void thread_free_resources(")
    altered=replace(body,"    process_t *owner_proc = thread->process;","    process_signal_thread_cleanup(thread);\n    process_t *owner_proc = thread->process;")
    text=replace(text,body,altered)
    changes[name]=text
    name="src/kernel/process/process_memory.c";text=read(name)
    anchor="bool process_stack_handle_page_fault(process_t *process, uintptr_t fault_addr, uintptr_t rsp)"
    helper="""/* Bounded preparation for a signal frame. New main-stack pages use the
 * same no-wait commit/retirement path as page-fault recovery. Other owned
 * stack/heap/VM ranges are validated by the subsequent safe copy itself. */
bool process_signal_prepare_user_frame(process_t *process, uintptr_t address, size_t bytes)
{
    if (!process || !bytes || address > UINTPTR_MAX - bytes) return false;
    uintptr_t end = address + bytes;
    uintptr_t bottom = process_stack_bottom(process);
    uint64_t flags = process_memory_lock(process);
    bool okay = true;
    if (address < process->user_stack_top && end > bottom)
        okay = address >= bottom && end <= process->user_stack_top &&
               process_stack_ensure_range(process, address, bytes);
    process_memory_unlock(process, flags);
    return okay;
}

"""
    helper+="""/* Permission faults can have a nonpresent PTE after MADV_DONTNEED.
 * Classify by logical ownership, without populating or waiting on a mapping. */
bool process_signal_address_mapped(process_t *process, uintptr_t address)
{
    if (!process) return false;
    uint64_t flags = process_memory_lock(process);
    uintptr_t stack_bottom = process_stack_bottom(process);
    bool mapped = (address >= process->user_heap_base && address < process->user_heap_brk) ||
                  (stack_bottom && address >= stack_bottom && address < process->user_stack_top) ||
                  process_vm_contains_locked(process, address);
    for (process_user_region_t *region = process->user_regions; !mapped && region; region = region->next)
        mapped = address >= region->user_base && address - region->user_base < region->mapped_size;
    process_memory_unlock(process, flags);
    return mapped;
}

"""
    text=replace(text,anchor,helper+anchor)
    text=replace(text,"    memcpy(stub_ptr, g_user_exit_stub, sizeof(g_user_exit_stub));","    memcpy(stub_ptr, g_user_exit_stub, sizeof(g_user_exit_stub));\n    memcpy((uint8_t *)stub_ptr + ALIX_SIGNAL_RESTORER_OFFSET, g_user_signal_restorer, sizeof(g_user_signal_restorer));")
    changes[name]=text
    name="src/kernel/process/process_scheduler.c";text=read(name)
    body=function_definition(text,"bool process_handle_exception(")
    body=replace(body,"        process_exit(-1);","        int status = thread->signal_fault_status ? thread->signal_fault_status : -1;\n        thread->signal_fault_status = 0;\n        process_exit(status);")
    old=function_definition(text,"bool process_handle_exception(");text=replace(text,old,body)
    changes[name]=text
    name="src/arch/x86/interrupts.c";text=read(name)
    text='#include "process_signal.h"\n'+text
    text=replace(text,"static void page_fault_handler(interrupt_frame_t *frame, uint64_t error_code)\n{","""static void page_fault_handler(exception_frame_t *saved)
{
    interrupt_frame_t *frame = &saved->cpu;
    uint64_t error_code = saved->error_code;""")
    text=replace(text,'    fault_report("page_fault", frame, error_code, true, true, fault_address);',
                 '    if (process_signal_fault(saved, fault_address)) return;\n    fault_report("page_fault", frame, error_code, true, true, fault_address);')
    text=replace(text,"    interrupt_frame_t *frame = &saved->cpu;\n    switch (saved->vector)",
                 "    interrupt_frame_t *frame = &saved->cpu;\n    if (saved->vector != 14 && process_signal_fault(saved, 0)) return;\n    switch (saved->vector)")
    text=replace(text,"case 14: page_fault_handler(frame, saved->error_code); return;","case 14: page_fault_handler(saved); return;")
    changes[name]=text
    name="src/kernel/syscall.c";text=read(name)
    text='#include "process_signal.h"\n'+text
    text=replace(text,"    uint64_t syscall_id = frame->rax;","    uint64_t syscall_id = frame->rax;\n    uint64_t signal_preempt_resume = 0;")
    text=replace(text,"                uint64_t resume = process_take_preempt_resume_rip();","                uint64_t resume = process_take_preempt_resume_rip();\n                signal_preempt_resume = resume;")
    text=replace(text,"        case SYSCALL_EXIT:\n",'''        case SYSCALL_SIGACTION:
            result = process_signal_sigaction((int)frame->rdi, frame->rsi, frame->rdx, frame->r10); break;
        case SYSCALL_SIGPROCMASK:
            result = process_signal_sigprocmask((int)frame->rdi, frame->rsi, frame->rdx); break;
        case SYSCALL_SIGALTSTACK:
            result = process_signal_sigaltstack(frame->rdi, frame->rsi, frame->rdx, frame->rsp); break;
        case SYSCALL_SIGRETURN:
            result = process_signal_return(frame, frame->rdi);
            if (result == 0) { process_signal_syscall_return(frame, 0); return frame->rax; }
            break;
        case SYSCALL_RAISE:
            result = process_signal_raise((int)frame->rdi, frame->rsi); break;
        case SYSCALL_KILL:
            result = process_signal_kill((int32_t)frame->rdi, (int)frame->rsi); break;
        case SYSCALL_SLEEP_INTERRUPTIBLE:
            result = process_signal_sleep((uint32_t)frame->rdi, frame->rsi); break;
        case SYSCALL_EXIT:
''')
    text=replace(text,"    frame->rax = (uint64_t)result;\n    return (uint64_t)result;",'''    frame->rax = (uint64_t)result;
    process_signal_syscall_return(frame, signal_preempt_resume);
    return frame->rax;''')
    changes[name]=text
    name="src/kernel/process/process_futex.c";text=read(name)
    text=replace(text,"    if (timeout_ms == 0)",'''    if (process_signal_pending_locked(thread))
    {
        scheduler_lock_release(flags);
        return SYSCALL_FUTEX_INTERRUPTED;
    }
    if (timeout_ms == 0)''')
    text=replace(text,"    thread->futex_waiting = true;","    thread->futex_interrupted = false;\n    thread->futex_waiting = true;")
    text=replace(text,"    bool notified = futex_notified(thread);","    bool notified = futex_notified(thread);\n    bool interrupted = thread->futex_interrupted;\n    thread->futex_interrupted = false;")
    text=replace(text,"    return notified ? SYSCALL_FUTEX_OK : SYSCALL_FUTEX_TIMED_OUT;", "    return interrupted ? SYSCALL_FUTEX_INTERRUPTED : notified ? SYSCALL_FUTEX_OK : SYSCALL_FUTEX_TIMED_OUT;")
    changes[name]=text
    name="user/lib/usyscall.h";text=read(name)
    text=replace(text,'#include "types.h"','#include "types.h"\n#include "signal_abi.h"')
    declarations='''int sys_sigaction(int number, const alix_sigaction_t *action, alix_sigaction_t *old, size_t size);
int sys_sigprocmask(int how, const alix_sigset_t *set, alix_sigset_t *old);
int sys_sigaltstack(const alix_stack_t *stack, alix_stack_t *old, size_t size);
int sys_sigreturn(uintptr_t frame);
int sys_raise(int number, uint64_t thread);
int sys_kill(int32_t pid, int number);
int sys_sleep_interruptible(uint32_t milliseconds, uint32_t *remaining);
'''
    text=replace(text,"int sys_sleep_ms(uint32_t ms);","int sys_sleep_ms(uint32_t ms);\n"+declarations)
    changes[name]=text
    name="user/lib/syscall.c";text=read(name)
    text+='''
int sys_sigaction(int number,const alix_sigaction_t *action,alix_sigaction_t *old,size_t size)
{ return (int)syscall4(SYSCALL_SIGACTION,number,(long)action,(long)old,(long)size); }
int sys_sigprocmask(int how,const alix_sigset_t *set,alix_sigset_t *old)
{ return (int)syscall3(SYSCALL_SIGPROCMASK,how,(long)set,(long)old); }
int sys_sigaltstack(const alix_stack_t *stack,alix_stack_t *old,size_t size)
{ return (int)syscall3(SYSCALL_SIGALTSTACK,(long)stack,(long)old,(long)size); }
int sys_sigreturn(uintptr_t frame) { return (int)syscall1(SYSCALL_SIGRETURN,(long)frame); }
int sys_raise(int number,uint64_t thread) { return (int)syscall2(SYSCALL_RAISE,number,(long)thread); }
int sys_kill(int32_t pid,int number) { return (int)syscall2(SYSCALL_KILL,pid,number); }
int sys_sleep_interruptible(uint32_t milliseconds,uint32_t *remaining)
{ return (int)syscall2(SYSCALL_SLEEP_INTERRUPTIBLE,milliseconds,(long)remaining); }
'''
    changes[name]=text
    name="include/pthread.h";text=read(name)
    # Keep the existing pthread ABI; signals use native TIDs and the shared mask.
    insertion='#include "signal.h"\n'
    text=insertion+text
    text=replace(text,"int pthread_equal(pthread_t", "int pthread_sigmask(int how, const sigset_t *set, sigset_t *old);\nint pthread_kill(pthread_t thread, int number);\nint pthread_equal(pthread_t")
    changes[name]=text
    name="user/lib/pthread.c";text=read(name)
    text=replace(text,"result != SYSCALL_FUTEX_OK && result != SYSCALL_FUTEX_AGAIN", "result != SYSCALL_FUTEX_OK && result != SYSCALL_FUTEX_AGAIN && result != -EINTR")
    changes[name]=text
    name="user/lib/libc.c";text=read(name)
    text=replace(text,"result != SYSCALL_FUTEX_OK && result != SYSCALL_FUTEX_AGAIN", "result != SYSCALL_FUTEX_OK && result != SYSCALL_FUTEX_AGAIN && result != -EINTR")
    text=replace(text,"status != 0 && status != SYSCALL_FUTEX_AGAIN", "status != 0 && status != SYSCALL_FUTEX_AGAIN && status != -EINTR")
    old=function_definition(text,"int alix_cond_timedwait(")
    new=replace(old,"    int result = sys_futex_wait(&condition->sequence, sequence, timeout_ms);",'''    uint64_t now = sys_monotonic_millis();
    uint64_t deadline = timeout_ms > UINT64_MAX - now ? UINT64_MAX : now + timeout_ms;
    uint32_t remaining = timeout_ms;
    int result;
    for (;;)
    {
        result = sys_futex_wait(&condition->sequence, sequence, remaining);
        if (result != -EINTR) break;
        if (timeout_ms != ALIX_WAIT_FOREVER)
        {
            now = sys_monotonic_millis();
            if (now >= deadline) { result = SYSCALL_FUTEX_TIMED_OUT; break; }
            remaining = (uint32_t)(deadline - now);
        }
    }''')
    text=replace(text,old,new)
    old=function_definition(text,"void abort(")
    new=replace(old,"    raise(SIGABRT);",'''    sigset_t set;
    (void)sigemptyset(&set); (void)sigaddset(&set, SIGABRT);
    (void)sigprocmask(SIG_UNBLOCK, &set, NULL);
    (void)raise(SIGABRT);''')
    text=replace(text,old,new)
    old=function_definition(text,"int nanosleep(")
    new='''int nanosleep(const struct timespec *duration, struct timespec *remaining)
{
    if (!duration || duration->tv_sec < 0 || duration->tv_nsec < 0 || duration->tv_nsec >= 1000000000L)
    { errno = EINVAL; return -1; }
    time_t seconds = duration->tv_sec;
    long nanoseconds = duration->tv_nsec;
    const uint32_t chunk_seconds = 4294967u;
    while (seconds >= chunk_seconds)
    {
        uint32_t left = 0;
        int status = sys_sleep_interruptible(chunk_seconds * 1000u, &left);
        if (status < 0)
        {
            if (status == -EINTR && remaining)
            {
                remaining->tv_sec = seconds - chunk_seconds + left / 1000u;
                remaining->tv_nsec = nanoseconds + (long)(left % 1000u) * 1000000L;
                if (remaining->tv_nsec >= 1000000000L) { ++remaining->tv_sec; remaining->tv_nsec -= 1000000000L; }
            }
            errno = -status; return -1;
        }
        seconds -= chunk_seconds;
    }
    uint32_t milliseconds = (uint32_t)seconds * 1000u + (uint32_t)((nanoseconds + 999999L) / 1000000L);
    uint32_t left = 0;
    int status = sys_sleep_interruptible(milliseconds, &left);
    if (status < 0)
    {
        if (status == -EINTR && remaining)
        {
            remaining->tv_sec = left / 1000u;
            remaining->tv_nsec = (long)(left % 1000u) * 1000000L;
            if (remaining->tv_sec > seconds || (remaining->tv_sec == seconds && remaining->tv_nsec > nanoseconds))
            { remaining->tv_sec = seconds; remaining->tv_nsec = nanoseconds; }
        }
        errno = -status; return -1;
    }
    if (remaining) { remaining->tv_sec = 0; remaining->tv_nsec = 0; }
    return 0;
}'''
    text=replace(text,old,new)
    changes[name]=text

    for name,text in changes.items():
        path=PENDING/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
    # Hand-authored new ABI/module files and the replacement libc signal module
    # are kept alongside generated integration edits.
    for path in PENDING.rglob("*"):
        if not path.is_file() or path.suffix not in {".c", ".h", ".py", ".S"}:continue
        name=path.relative_to(PENDING).as_posix()
        if name not in changes:
            changes[name]=path.read_text()
            originals[name]=(ROOT/name).read_text() if (ROOT/name).exists() else ""
    patch=[];records=[]
    for name in sorted(changes):
        old=originals[name];new=changes[name]
        records.append({"path":name,"base_sha256":hashlib.sha256(old.encode()).hexdigest() if (ROOT/name).exists() else None,
                        "pending_sha256":hashlib.sha256(new.encode()).hexdigest()})
        patch.extend(difflib.unified_diff(old.splitlines(True),new.splitlines(True),
                     fromfile="a/Repo/"+name if (ROOT/name).exists() else "/dev/null",tofile="b/Repo/"+name))
    (HERE/"signals.pending.patch").write_text("".join(patch))
    (HERE/"pending.json").write_text(json.dumps({"applied":False,"files":records},indent=2)+"\n")
    print(f"Staged {len(records)} signal files; active tree unchanged")

if __name__=="__main__":main()
