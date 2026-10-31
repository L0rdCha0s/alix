#!/usr/bin/env python3
"""Execute native signal registration, synchronous raise and abort on the host."""
import os
import re
import shlex
import sys

sys.dont_write_bytecode = True
from audio_stream_contract_test import ROOT, compile_and_run, function_definition


def rename(text):
    text = "\n".join(line for line in text.splitlines() if not line.startswith("#include"))
    names = {"signal": "alix_test_signal", "raise": "alix_test_raise", "abort": "alix_test_abort",
             "sig_atomic_t": "alix_test_sig_atomic_t", "errno": "test_errno", "sys_exit": "test_sys_exit"}
    for name, replacement in names.items():
        text = re.sub(r"\b" + name + r"\b", replacement, text)
    return re.sub(r"\b(SIG[A-Z0-9_]+)\b", r"ALIX_TEST_\1", text)


def main():
    source = (ROOT / "user/lib/signal.c").read_text()
    header = (ROOT / "include/signal.h").read_text()
    libc = (ROOT / "user/lib/libc.c").read_text()
    program = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "signal contract line %d: %s\n", __LINE__, #c); abort(); } } while (0)
static _Thread_local int test_errno;
static _Thread_local pthread_t expected_caller;
static _Thread_local unsigned calls_a, calls_b;
static _Thread_local int expected_signal;
static uint64_t all_calls;
static pthread_t main_thread;
static jmp_buf exit_target;
static bool exit_armed;
static unsigned exit_calls;
static int exit_status;
__attribute__((noreturn)) static void test_sys_exit(int status)
{
    CHECK(pthread_equal(pthread_self(), main_thread) && exit_armed);
    ++exit_calls;
    exit_status = status;
    longjmp(exit_target, 1);
}
'''
    program += rename(header) + "\n" + rename(source) + "\n"
    program += rename(function_definition(libc, "void abort(void)")) + r'''

static void handle_a(int number)
{
    CHECK(number == expected_signal && pthread_equal(pthread_self(), expected_caller));
    ++calls_a;
    __atomic_fetch_add(&all_calls, 1, __ATOMIC_RELAXED);
}

static void handle_b(int number)
{
    CHECK(number == expected_signal && pthread_equal(pthread_self(), expected_caller));
    ++calls_b;
    __atomic_fetch_add(&all_calls, 1, __ATOMIC_RELAXED);
}

static unsigned nested_calls, outer_calls;
static void nested_handler(int number)
{
    CHECK(number == ALIX_TEST_SIGTERM && pthread_equal(pthread_self(), expected_caller));
    ++nested_calls;
}
static void outer_handler(int number)
{
    CHECK(number == ALIX_TEST_SIGFPE && pthread_equal(pthread_self(), expected_caller));
    ++outer_calls;
    CHECK(alix_test_raise(ALIX_TEST_SIGTERM) == 0);
}

static void registration_and_validation(void)
{
    CHECK(ALIX_TEST_SIGINT == 2 && ALIX_TEST_SIGILL == 4 && ALIX_TEST_SIGABRT == 6);
    CHECK(ALIX_TEST_SIGFPE == 8 && ALIX_TEST_SIGSEGV == 11 && ALIX_TEST_SIGTERM == 15);
    expected_signal = ALIX_TEST_SIGINT;
    test_errno = 73;
    CHECK(alix_test_signal(ALIX_TEST_SIGINT, handle_a) == ALIX_TEST_SIG_DFL);
    CHECK(alix_test_raise(ALIX_TEST_SIGINT) == 0 && alix_test_raise(ALIX_TEST_SIGINT) == 0);
    CHECK(calls_a == 2 && calls_b == 0 && test_errno == 73);
    CHECK(alix_test_signal(ALIX_TEST_SIGINT, handle_b) == handle_a);
    CHECK(alix_test_raise(ALIX_TEST_SIGINT) == 0 && calls_b == 1);
    CHECK(alix_test_signal(ALIX_TEST_SIGINT, ALIX_TEST_SIG_IGN) == handle_b);
    CHECK(alix_test_raise(ALIX_TEST_SIGINT) == 0 && calls_a == 2 && calls_b == 1);
    CHECK(alix_test_signal(ALIX_TEST_SIGINT, handle_a) == ALIX_TEST_SIG_IGN);
    test_errno = 0;
    CHECK(alix_test_signal(ALIX_TEST_SIGINT, ALIX_TEST_SIG_ERR) == ALIX_TEST_SIG_ERR && test_errno == EINVAL);
    CHECK(alix_test_raise(ALIX_TEST_SIGINT) == 0 && calls_a == 3);
    CHECK(alix_test_signal(ALIX_TEST_SIGINT, handle_b) == handle_a);
    static const int invalid[] = { INT_MIN, -1, 0, 1, 3, 5, 7, 9, 10, 12, 13, 14, 16, 31, INT_MAX };
    for (size_t index = 0; index < sizeof(invalid)/sizeof(invalid[0]); ++index)
    {
        test_errno = 0;
        CHECK(alix_test_signal(invalid[index], handle_a) == ALIX_TEST_SIG_ERR && test_errno == EINVAL);
        test_errno = 0;
        CHECK(alix_test_raise(invalid[index]) == -1 && test_errno == EINVAL);
    }
    CHECK(alix_test_signal(ALIX_TEST_SIGINT, ALIX_TEST_SIG_DFL) == handle_b);
    CHECK(alix_test_signal(ALIX_TEST_SIGTERM, nested_handler) == ALIX_TEST_SIG_DFL);
    CHECK(alix_test_signal(ALIX_TEST_SIGFPE, outer_handler) == ALIX_TEST_SIG_DFL);
    CHECK(alix_test_raise(ALIX_TEST_SIGFPE) == 0 && alix_test_raise(ALIX_TEST_SIGFPE) == 0);
    CHECK(nested_calls == 2 && outer_calls == 2);
}

static void expect_default_exit(int number)
{
    alix_test_signal(number, ALIX_TEST_SIG_DFL);
    exit_calls = 0; exit_status = -1; exit_armed = true;
    if (setjmp(exit_target) == 0)
    {
        alix_test_raise(number);
        CHECK(!"default signal disposition returned");
    }
    exit_armed = false;
    CHECK(exit_calls == 1 && exit_status == 128 + number);
}

static unsigned abort_handler_calls;
static void abort_handler(int number)
{
    CHECK(number == ALIX_TEST_SIGABRT && pthread_equal(pthread_self(), expected_caller));
    ++abort_handler_calls;
    /* Changing the disposition inside a returning handler cannot make abort
     * return or skip its mandatory raw termination. */
    CHECK(alix_test_signal(ALIX_TEST_SIGABRT, ALIX_TEST_SIG_IGN) == abort_handler);
}

static void termination_contracts(void)
{
    static const int supported[] = {ALIX_TEST_SIGINT, ALIX_TEST_SIGILL, ALIX_TEST_SIGABRT,
                                   ALIX_TEST_SIGFPE, ALIX_TEST_SIGSEGV, ALIX_TEST_SIGTERM};
    for (size_t index = 0; index < sizeof(supported)/sizeof(supported[0]); ++index)
        expect_default_exit(supported[index]);
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        alix_test_signal(ALIX_TEST_SIGABRT,
                         mode == 0 ? ALIX_TEST_SIG_DFL : mode == 1 ? ALIX_TEST_SIG_IGN : abort_handler);
        exit_calls = 0; exit_status = -1; exit_armed = true;
        if (setjmp(exit_target) == 0)
        {
            alix_test_abort();
            CHECK(!"abort returned");
        }
        exit_armed = false;
        CHECK(exit_calls == 1 && exit_status == 134);
    }
    CHECK(abort_handler_calls == 1);
}

typedef struct {
    pthread_t thread;
    unsigned number, calls;
    unsigned *ready;
    bool *go;
} worker_t;

static void *worker_main(void *argument)
{
    worker_t *worker = argument;
    expected_caller = pthread_self(); expected_signal = ALIX_TEST_SIGTERM;
    calls_a = calls_b = 0;
    __atomic_fetch_add(worker->ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(worker->go, __ATOMIC_ACQUIRE)) sched_yield();
    for (unsigned index = 0; index < 5000; ++index)
    {
        int marker = (int)worker->number + 1000;
        test_errno = marker;
        signal_handler_t previous = alix_test_signal(ALIX_TEST_SIGTERM, index & 1 ? handle_a : handle_b);
        CHECK(previous == handle_a || previous == handle_b);
        CHECK(test_errno == marker);
        CHECK(alix_test_raise(ALIX_TEST_SIGTERM) == 0 && test_errno == marker);
        if ((index & 127) == 0)
        {
            CHECK(alix_test_raise(-1) == -1 && test_errno == EINVAL);
            CHECK(alix_test_signal(ALIX_TEST_SIGTERM, ALIX_TEST_SIG_ERR) == ALIX_TEST_SIG_ERR);
            CHECK(test_errno == EINVAL);
        }
    }
    worker->calls = calls_a + calls_b;
    return NULL;
}

static void concurrent_registry_and_raise(void)
{
    worker_t *workers = calloc(8, sizeof(*workers));
    unsigned *ready = calloc(1, sizeof(*ready)); bool *go = calloc(1, sizeof(*go));
    CHECK(workers && ready && go);
    all_calls = 0;
    alix_test_signal(ALIX_TEST_SIGTERM, handle_a);
    test_errno = 991;
    for (unsigned index = 0; index < 8; ++index)
    {
        workers[index].number = index; workers[index].ready = ready; workers[index].go = go;
        CHECK(pthread_create(&workers[index].thread, NULL, worker_main, &workers[index]) == 0);
    }
    while (__atomic_load_n(ready, __ATOMIC_ACQUIRE) != 8) sched_yield();
    __atomic_store_n(go, true, __ATOMIC_RELEASE);
    for (unsigned index = 0; index < 8; ++index)
    {
        CHECK(pthread_join(workers[index].thread, NULL) == 0);
        CHECK(workers[index].calls == 5000);
    }
    CHECK(all_calls == 40000 && test_errno == 991);
    free(go); free(ready); free(workers);
}

int main(void)
{
    main_thread = expected_caller = pthread_self();
    registration_and_validation();
    termination_contracts();
    concurrent_registry_and_raise();
    puts("production signal registration, same-caller raise, concurrency and abort contracts passed");
    return 0;
}
'''
    previous = os.environ.get("HOST_CC")
    os.environ["HOST_CC"] = shlex.join(shlex.split(previous or "cc") + ["-pthread"])
    try:
        compile_and_run("signal", program)
    finally:
        if previous is None:
            os.environ.pop("HOST_CC", None)
        else:
            os.environ["HOST_CC"] = previous
    print("native signal registry and synchronous delivery contracts passed")


if __name__ == "__main__":
    main()
