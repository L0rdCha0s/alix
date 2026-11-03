#ifndef ALIX_SIGNAL_ABI_H
#define ALIX_SIGNAL_ABI_H
#include "types.h"

#define ALIX_SIGNAL_COUNT 32u
#define ALIX_SIGNAL_MASK 0x7FFFFFFFULL
#define ALIX_SIGHUP 1
#define ALIX_SIGINT 2
#define ALIX_SIGQUIT 3
#define ALIX_SIGILL 4
#define ALIX_SIGTRAP 5
#define ALIX_SIGABRT 6
#define ALIX_SIGBUS 7
#define ALIX_SIGFPE 8
#define ALIX_SIGKILL 9
#define ALIX_SIGUSR1 10
#define ALIX_SIGSEGV 11
#define ALIX_SIGUSR2 12
#define ALIX_SIGPIPE 13
#define ALIX_SIGALRM 14
#define ALIX_SIGTERM 15
#define ALIX_SIGCHLD 17
#define ALIX_SIGCONT 18
#define ALIX_SIGSTOP 19
#define ALIX_SIGTSTP 20
#define ALIX_SIGTTIN 21
#define ALIX_SIGTTOU 22
#define ALIX_SIGURG 23
#define ALIX_SIGXCPU 24
#define ALIX_SIGXFSZ 25
#define ALIX_SIGVTALRM 26
#define ALIX_SIGPROF 27
#define ALIX_SIGWINCH 28
#define ALIX_SIGIO 29
#define ALIX_SIGSYS 31

#define ALIX_SIG_BLOCK 0
#define ALIX_SIG_UNBLOCK 1
#define ALIX_SIG_SETMASK 2
#define ALIX_SIG_PENDING 3
#define ALIX_SA_SIGINFO 0x01u
#define ALIX_SA_NODEFER 0x02u
#define ALIX_SA_ONSTACK 0x04u
#define ALIX_SA_RESETHAND 0x08u
#define ALIX_SA_RESTART 0x10u
#define ALIX_SS_ONSTACK 0x01
#define ALIX_SS_DISABLE 0x02
#define ALIX_MINSIGSTKSZ 16384u
#define ALIX_SIGSTKSZ 65536u
#define ALIX_SI_USER 0
#define ALIX_SI_TKILL (-1)
#define ALIX_CLD_EXITED 1
#define ALIX_CLD_KILLED 2
#define ALIX_CLD_DUMPED 3
#define ALIX_CLD_TRAPPED 4
#define ALIX_CLD_STOPPED 5
#define ALIX_CLD_CONTINUED 6
#define ALIX_SEGV_MAPERR 1
#define ALIX_SEGV_ACCERR 2
#define ALIX_ILL_ILLOPC 1
#define ALIX_FPE_INTDIV 1

#define ALIX_SIGNAL_ABI_VERSION 1u
#define ALIX_UC_FXSAVE64 1ULL
#define ALIX_SIGNAL_FRAME_MAGIC 0x414C495853494746ULL
#define ALIX_SIGNAL_MAX_DEPTH 32u
#define ALIX_SIGNAL_RESTORER_OFFSET 0x200u
#define ALIX_SIGNAL_RESTORER_SIZE 12u
#define ALIX_PREEMPT_RETURN_OFFSET 38u
#define ALIX_PREEMPT_SAVE_BYTES 264u
#define ALIX_PREEMPT_STUB_SIZE 73u

typedef uint64_t alix_sigset_t;
typedef struct
{
    uintptr_t handler;
    alix_sigset_t mask;
    uint32_t flags, reserved;
} alix_sigaction_t;
typedef struct
{
    void *ss_sp;
    size_t ss_size;
    int32_t ss_flags;
    uint32_t reserved;
} alix_stack_t;
typedef struct
{
    int32_t si_signo, si_errno, si_code, si_status;
    void *si_addr;
    int32_t si_pid;
    uint32_t si_uid;
    uint64_t si_tid, si_trapno, si_error, reserved;
} alix_siginfo_t;
typedef struct
{
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rsi, rdi, rbp, rdx, rcx, rbx, rax;
    uint64_t rip, cs, rflags, rsp, ss;
    uint64_t trapno, error_code, cr2, reserved;
    uint8_t fpregs[512] __attribute__((aligned(16)));
} alix_mcontext_t;
typedef struct alix_ucontext
{
    uint32_t uc_version, uc_size;
    uint64_t uc_flags;
    struct alix_ucontext *uc_link;
    alix_sigset_t uc_sigmask;
    alix_stack_t uc_stack;
    uint64_t reserved;
    alix_mcontext_t uc_mcontext;
} alix_ucontext_t;
typedef struct
{
    uint64_t magic;
    uint32_t version, size;
    uint64_t owner_tid, sequence;
    uintptr_t frame_address;
    uint64_t reserved[3];
    alix_siginfo_t info;
    alix_ucontext_t context;
} alix_signal_frame_t;

#define ALIX_SIGJUMP_VERSION 1u
#define ALIX_SIGJUMP_CAPTURE 0u
#define ALIX_SIGJUMP_RESTORE 1u
#define ALIX_SIGJUMP_SAVE_MASK 1u
#define ALIX_SIGJUMP_REGISTER_BYTES 64u

typedef struct
{
    uint64_t rbx, rbp, r12, r13, r14, r15, rsp, rip;
    uint32_t version, size;
    uint64_t owner_tid, epoch, frame_sequence, saved_mask;
    uint32_t flags, reserved;
    uint64_t reserved_words[2];
} alix_sigjmp_state_t;

#endif
