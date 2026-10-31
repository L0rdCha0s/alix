#!/usr/bin/env python3
"""Execute production stack-guard setup and failure paths with scripted entropy."""
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run


def main():
    source = (ROOT / "user/lib/stack_protector.c").read_text()
    # The runtime preinit hook must not execute against host libc before this
    # harness has installed its entropy/exit fixtures. Keep the real globals,
    # attributes and function bodies; replace only their syscall boundary.
    hook = "typedef void (*runtime_hook_t)(void);"
    if hook not in source:
        raise AssertionError("stack protector runtime hook boundary changed")
    production = "\n".join(
        line for line in source.split(hook, 1)[0].splitlines()
        if not line.startswith("#include ")
    )
    program = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "stack protector contract line %d: %s\n", __LINE__, #c); abort(); } } while (0)
static int test_getentropy(void *buffer, size_t length);
static int test_serial_write(const char *message, size_t length);
__attribute__((noreturn)) static void test_sys_exit(int status);
/* Do not interpose the host's own compiler/runtime guard symbols. */
#define __stack_chk_guard alix_test_stack_chk_guard
#define __stack_chk_fail alix_test_stack_chk_fail
#define getentropy test_getentropy
#define sys_serial_write test_serial_write
#define sys_exit test_sys_exit
'''
    program += production + r'''

static uintptr_t entropy_words[8];
static int entropy_errors[8];
static unsigned entropy_available, entropy_calls, serial_calls, exit_calls;
static int exit_status, serial_result;
static size_t serial_length;
static char serial_message[128];
static bool exit_armed;
static jmp_buf exit_target;

static int test_getentropy(void *buffer, size_t length)
{
    CHECK(entropy_calls < entropy_available);
    CHECK(buffer == &__stack_chk_guard && length == sizeof(__stack_chk_guard));
    unsigned index = entropy_calls++;
    /* Failure can leave partial/nonzero output: it must still be rejected. */
    memcpy(buffer, &entropy_words[index], length);
    return entropy_errors[index];
}

static int test_serial_write(const char *message, size_t length)
{
    CHECK(message && length && length < sizeof(serial_message));
    CHECK(serial_calls++ == 0);
    memcpy(serial_message, message, length);
    serial_length = length;
    return serial_result;
}

__attribute__((noreturn)) static void test_sys_exit(int status)
{
    CHECK(exit_armed);
    ++exit_calls;
    exit_status = status;
    longjmp(exit_target, 1);
}

static void reset(void)
{
    __stack_chk_guard = 0;
    memset(entropy_words, 0, sizeof(entropy_words));
    memset(entropy_errors, 0, sizeof(entropy_errors));
    memset(serial_message, 0xa5, sizeof(serial_message));
    entropy_available = entropy_calls = serial_calls = exit_calls = 0;
    serial_length = 0;
    serial_result = 0;
    exit_status = -1;
    exit_armed = false;
}

static void check_abort(const char *expected)
{
    size_t length = strlen(expected);
    CHECK(exit_calls == 1 && exit_status == 127);
    CHECK(serial_calls == 1 && serial_length == length);
    CHECK(!memcmp(serial_message, expected, length));
    CHECK((unsigned char)serial_message[length] == 0xa5);
}

static void expect_initialize_failure(void)
{
    exit_armed = true;
    if (setjmp(exit_target) == 0)
    {
        stack_protector_initialize();
        CHECK(!"failed entropy must terminate without publishing a fallback");
    }
    exit_armed = false;
    check_abort("ALIX_STACK_PROTECTOR: entropy unavailable\n");
}

static void success_at_each_attempt(void)
{
    for (unsigned index = 0; index < 8; ++index)
    {
        reset();
        entropy_available = index + 1;
        uintptr_t expected = UINT64_C(0x8f12030105a60709) + index;
        entropy_words[index] = expected;
        stack_protector_initialize();
        CHECK(__stack_chk_guard == expected);
        CHECK(entropy_calls == index + 1 && serial_calls == 0 && exit_calls == 0);
    }
    /* Rejecting only zero must not mask entropy into a predictable value. */
    reset(); entropy_available = 1; entropy_words[0] = 1;
    stack_protector_initialize();
    CHECK(__stack_chk_guard == 1 && entropy_calls == 1);
    reset(); entropy_available = 1; entropy_words[0] = UINTPTR_MAX;
    stack_protector_initialize();
    CHECK(__stack_chk_guard == UINTPTR_MAX && entropy_calls == 1);
}

static void entropy_failures(void)
{
    reset(); entropy_available = 8;
    expect_initialize_failure();
    CHECK(entropy_calls == 8 && __stack_chk_guard == 0);

    for (unsigned index = 0; index < 8; ++index)
    {
        reset(); entropy_available = index + 1;
        entropy_errors[index] = -1;
        /* A nonzero word delivered with an error is not usable entropy. */
        entropy_words[index] = UINT64_C(0x123456789abcdef0);
        expect_initialize_failure();
        CHECK(entropy_calls == index + 1);
    }
    reset(); entropy_available = 1; entropy_errors[0] = -1;
    serial_result = -1;
    expect_initialize_failure();
    CHECK(entropy_calls == 1);
}

static void corruption_failures(void)
{
    for (unsigned unavailable_serial = 0; unavailable_serial < 2; ++unavailable_serial)
    {
        reset();
        __stack_chk_guard = UINT64_C(0x1122334455667788);
        serial_result = unavailable_serial ? -1 : 0;
        exit_armed = true;
        if (setjmp(exit_target) == 0)
        {
            __stack_chk_fail();
            CHECK(!"stack corruption must terminate");
        }
        exit_armed = false;
        check_abort("ALIX_STACK_PROTECTOR: stack corruption\n");
        CHECK(entropy_calls == 0);
        CHECK(__stack_chk_guard == UINT64_C(0x1122334455667788));
    }
}

int main(void)
{
    success_at_each_attempt();
    entropy_failures();
    corruption_failures();
    puts("production stack protector entropy, bounded retry and raw-exit contracts passed");
    return 0;
}
'''
    compile_and_run("stack-protector", program)
    print("stack protector initialization and failure contracts passed")


if __name__ == "__main__":
    main()
