#include "process_internal.h"
#include "shell_service.h"
#include "io_vfs_service.h"
#include "heap.h"
#include "libc.h"

typedef struct
{
    int first, second, status, running;
    char path[VFS_PATH_MAX];
    fd_description_t *original_cwd;
    const char *failure;
} shell_cwd_boot_t;

static bool shell_cwd_boot_command(shell_cwd_boot_t *test, int handle, const char *command)
{
    if (shell_service_exec((uint32_t)handle, command, strlen(command)) != 0) return false;
    uint32_t frequency = timer_frequency();
    uint64_t deadline = timer_ticks() + (uint64_t)(frequency ? frequency : 1000u) * 5u;
    for (;;)
    {
        if (shell_service_poll((uint32_t)handle, NULL, 0, &test->status, &test->running) < 0) return false;
        if (!test->running)
        {
            if (test->status != 0) return false;
            /* Allow the runner's final process_exit after it publishes its
             * completion, then let poll retire the now-quiescent runner. */
            process_sleep_ms(1);
            return shell_service_poll((uint32_t)handle, NULL, 0, &test->status, &test->running) >= 0 &&
                   !test->running && test->status == 0;
        }
        if (timer_ticks() >= deadline) return false;
        process_sleep_ms(1);
    }
}

static bool shell_cwd_boot_matches(shell_cwd_boot_t *test, int handle, const char *path)
{
    ssize_t length = shell_service_get_cwd((uint32_t)handle, test->path, sizeof(test->path));
    return length == (ssize_t)strlen(path) && strcmp(test->path, path) == 0;
}

bool shell_cwd_boot_test(void)
{
    shell_cwd_boot_t *test = calloc(1, sizeof(*test));
    if (!test) { serial_printf("SHELL_CWD_TEST: FAIL controller allocation"); return false; }
    test->first = test->second = -1;
#define REQUIRE(value, label) do { if (!(value)) { test->failure = (label); goto failed; } } while (0)
    serial_printf("SHELL_CWD_TEST: start two independent sessions");
    REQUIRE(vfs_mkdir(vfs_root(), "/tmp") != NULL, "tmp parent");
    REQUIRE(vfs_mkdir(vfs_root(), "/tmp/shell-cwd-test") != NULL, "fixture parent");
    REQUIRE(vfs_mkdir(vfs_root(), "/tmp/shell-cwd-test/a") != NULL, "first directory");
    REQUIRE(vfs_mkdir(vfs_root(), "/tmp/shell-cwd-test/a/child") != NULL, "first child");
    REQUIRE(vfs_mkdir(vfs_root(), "/tmp/shell-cwd-test/b") != NULL, "second directory");
    REQUIRE(vfs_mkdir(vfs_root(), "/tmp/shell-cwd-test/b/child") != NULL, "second child");
    spinlock_preempt_disable();
    test->original_cwd = process_acquire_cwd_owner(process_current(), NULL, NULL);
    spinlock_preempt_enable();
    REQUIRE(test->original_cwd != NULL, "save original cwd");
    test->first = shell_service_open_session();
    test->second = shell_service_open_session();
    REQUIRE(test->first > 0 && test->second > 0 && test->first != test->second, "two session handles");
    REQUIRE(shell_cwd_boot_command(test, test->first, "cd /tmp/shell-cwd-test/a"), "first absolute cd");
    REQUIRE(shell_cwd_boot_command(test, test->second, "cd /tmp/shell-cwd-test/b"), "second absolute cd");
    REQUIRE(shell_cwd_boot_matches(test, test->first, "/tmp/shell-cwd-test/a"), "first session retained base");
    REQUIRE(shell_cwd_boot_matches(test, test->second, "/tmp/shell-cwd-test/b"), "second session retained base");
    REQUIRE(io_vfs_change_cwd_kernel("/tmp", 0) == 0, "external owner cwd change");
    REQUIRE(shell_cwd_boot_command(test, test->first, "cd child"), "first independent relative cd");
    REQUIRE(shell_cwd_boot_matches(test, test->first, "/tmp/shell-cwd-test/a/child"), "first relative result");
    REQUIRE(shell_cwd_boot_matches(test, test->second, "/tmp/shell-cwd-test/b"), "second base unchanged");
    REQUIRE(shell_cwd_boot_command(test, test->second, "cd child"), "second independent relative cd");
    REQUIRE(shell_cwd_boot_matches(test, test->second, "/tmp/shell-cwd-test/b/child"), "second relative result");
    REQUIRE(shell_cwd_boot_matches(test, test->first, "/tmp/shell-cwd-test/a/child"), "first base unchanged");
    REQUIRE(shell_cwd_boot_command(test, test->first, "cd .."), "first relative parent");
    REQUIRE(shell_cwd_boot_matches(test, test->first, "/tmp/shell-cwd-test/a"), "first parent result");
    REQUIRE(shell_service_close_session((uint32_t)test->first), "first close"); test->first = -1;
    REQUIRE(shell_service_close_session((uint32_t)test->second), "second close"); test->second = -1;
    spinlock_preempt_disable();
    int restored = process_set_cwd_description_owned(process_current(), test->original_cwd);
    if (!restored) test->original_cwd = NULL;
    spinlock_preempt_enable();
    REQUIRE(restored == 0, "restore original cwd");
    free(test);
    serial_printf("SHELL_CWD_TEST: PASS sessions=2 independent_relative=1 owner_changes=1 close=1");
    return true;
failed:
    serial_printf("SHELL_CWD_TEST: FAIL %s", test->failure ? test->failure : "unknown");
    /* The boot hook keeps diagnostics alive. Retain this heap controller if a
     * session or runner is still active; no shared callback record is freed. */
    return false;
#undef REQUIRE
}
