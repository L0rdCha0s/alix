#include "setjmp.h"

__attribute__((naked, returns_twice))
int setjmp(jmp_buf env)
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
void longjmp(jmp_buf env, int value)
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
