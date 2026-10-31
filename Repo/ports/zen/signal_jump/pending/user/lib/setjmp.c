#include "setjmp.h"
#include "syscall_defs.h"

__attribute__((naked, returns_twice))
int setjmp(jmp_buf env __attribute__((unused)))
{
    __asm__ volatile(
        "movq %rbx, 0(%rdi)\n"
        "movq %rbp, 8(%rdi)\n"
        "movq %r12, 16(%rdi)\n"
        "movq %r13, 24(%rdi)\n"
        "movq %r14, 32(%rdi)\n"
        "movq %r15, 40(%rdi)\n"
        "leaq 8(%rsp), %rax\n"
        "movq %rax, 48(%rdi)\n"
        "movq (%rsp), %rax\n"
        "movq %rax, 56(%rdi)\n"
        "xorl %eax, %eax\n"
        "ret\n");
}

__attribute__((naked, noreturn))
void longjmp(jmp_buf env __attribute__((unused)), int value __attribute__((unused)))
{
    __asm__ volatile(
        "movl %esi, %eax\n"
        "test %eax, %eax\n"
        "jne 1f\n"
        "movl $1, %eax\n"
        "1:\n"
        "movq 0(%rdi), %rbx\n"
        "movq 8(%rdi), %rbp\n"
        "movq 16(%rdi), %r12\n"
        "movq 24(%rdi), %r13\n"
        "movq 32(%rdi), %r14\n"
        "movq 40(%rdi), %r15\n"
        "movq 48(%rdi), %rsp\n"
        "jmp *56(%rdi)\n");
}

_Static_assert(sizeof(sigjmp_buf) == 128, "native signal checkpoint ABI");
_Static_assert(__builtin_offsetof(alix_sigjmp_state_t, version) == 64, "existing register prefix");

/* Save the caller's activation before entering any C helper. A successful
 * kernel RESTORE returns directly to that activation, never to this wrapper. */
__attribute__((naked, returns_twice))
int sigsetjmp(sigjmp_buf env __attribute__((unused)), int savemask __attribute__((unused)))
{
    __asm__ volatile(
        "movq %%rbx, 0(%%rdi)\n"
        "movq %%rbp, 8(%%rdi)\n"
        "movq %%r12, 16(%%rdi)\n"
        "movq %%r13, 24(%%rdi)\n"
        "movq %%r14, 32(%%rdi)\n"
        "movq %%r15, 40(%%rdi)\n"
        "leaq 8(%%rsp), %%rax\n"
        "movq %%rax, 48(%%rdi)\n"
        "movq (%%rsp), %%rax\n"
        "movq %%rax, 56(%%rdi)\n"
        "movl %%esi, %%r10d\n"
        "movq %%rdi, %%rsi\n"
        "xorl %%edi, %%edi\n"
        "movl $128, %%edx\n"
        "movl %[number], %%eax\n"
        "int $0x80\n"
        "testl %%eax, %%eax\n"
        "js 1f\n"
        "ret\n"
        "1:\n"
        "movl $127, %%edi\n"
        "movl %[exit_number], %%eax\n"
        "int $0x80\n"
        "ud2\n"
        : : [number] "i" (SYSCALL_SIGNAL_JUMP), [exit_number] "i" (SYSCALL_EXIT) : "memory", "cc");
}

__attribute__((naked, noreturn))
void siglongjmp(sigjmp_buf env __attribute__((unused)), int value __attribute__((unused)))
{
    __asm__ volatile(
        "movl %%esi, %%r10d\n"
        "movq %%rdi, %%rsi\n"
        "movl $1, %%edi\n"
        "movl $128, %%edx\n"
        "movl %[number], %%eax\n"
        "int $0x80\n"
        /* Only a failed restore returns here. No libc locks or exit callbacks
         * are safe when abandoning a signal handler with invalid metadata. */
        "movl $127, %%edi\n"
        "movl %[exit_number], %%eax\n"
        "int $0x80\n"
        "ud2\n"
        : : [number] "i" (SYSCALL_SIGNAL_JUMP), [exit_number] "i" (SYSCALL_EXIT) : "memory", "cc");
}
