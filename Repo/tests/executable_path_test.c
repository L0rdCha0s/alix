#include "unistd.h"
#include "stdlib.h"
#include "string.h"
#include "errno.h"
#include "spawn.h"
#include "sys/wait.h"
#include "stdio.h"
#include "serial.h"

#define TARGET_NAME "native-executable-path-test-name-longer-than-process-name-limit.elf"
#define TARGET_PATH "/tmp/" TARGET_NAME
#define CHECK(c,label) do { if (!(c)) { serial_printf("EXECUTABLE_PATH_TEST: FAIL %s line=%u errno=%d\n",label,__LINE__,errno); return 1; } } while (0)
static char *constructor_path;
static ssize_t constructor_length;
__attribute__((constructor)) static void before_main(void)
{
    constructor_path = malloc(SYSCALL_EXECUTABLE_PATH_MAX);
    constructor_length = constructor_path ? alix_get_executable_path(constructor_path, SYSCALL_EXECUTABLE_PATH_MAX) : -1;
}
static int spawn_child(const char *path, bool search)
{
    char **arguments = calloc(3, sizeof(*arguments));
    if (!arguments) return 1;
    arguments[0] = strdup("deceptive-argv-zero"); arguments[1] = strdup("child");
    if (!arguments[0] || !arguments[1]) { free(arguments[0]); free(arguments[1]); free(arguments); return 1; }
    pid_t pid = 0; int status = -1;
    int error = search ? posix_spawnp(&pid, path, NULL, NULL, arguments, NULL) :
                         posix_spawn(&pid, path, NULL, NULL, arguments, NULL);
    free(arguments[0]); free(arguments[1]); free(arguments);
    return error || waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}
int main(int argc, char **argv)
{
    bool child = argc > 1 && !strcmp(argv[1], "child");
    const char *expected = child ? TARGET_PATH : "/tmp/test.elf";
    CHECK(constructor_path && constructor_length == (ssize_t)strlen(expected) && !strcmp(constructor_path, expected),
          "canonical path available before main");
    char *buffer = malloc(SYSCALL_EXECUTABLE_PATH_MAX); CHECK(buffer, "heap reply");
    memset(buffer, 0x5a, SYSCALL_EXECUTABLE_PATH_MAX);
    CHECK(alix_get_executable_path(buffer, (size_t)constructor_length) == -1 && errno == ERANGE && buffer[0] == 0x5a,
          "short reply is not truncated success");
    CHECK(alix_get_executable_path(buffer, 0) == -1 && errno == ERANGE && buffer[0] == 0x5a, "zero capacity");
    CHECK(alix_get_executable_path(NULL, SYSCALL_EXECUTABLE_PATH_MAX) == -1 && errno == EFAULT, "invalid reply pointer");
    CHECK(alix_get_executable_path((char *)"readonly", SYSCALL_EXECUTABLE_PATH_MAX) == -1 && errno == EFAULT,
          "read-only reply rejected");
    CHECK(alix_get_executable_path(buffer, (size_t)constructor_length + 1) == constructor_length && !strcmp(buffer, expected),
          "exact reply includes terminator");
    if (child)
    {
        CHECK(!strcmp(argv[0], "deceptive-argv-zero"), "explicit argv zero");
        argv[0][0] = 'X';
        CHECK(!chdir("/") && alix_get_executable_path(buffer, SYSCALL_EXECUTABLE_PATH_MAX) == constructor_length && !strcmp(buffer, expected),
              "path independent of argv mutation and cwd");
        serial_printf("EXECUTABLE_PATH_TEST: CHILD PASS constructor=1 argv_independent=1 cwd_independent=1 long_name=1\n");
    }
    else
    {
        CHECK(!rename("/tmp/test.elf", TARGET_PATH), "rename current executable");
        CHECK(!chdir("/tmp") && !spawn_child("../tmp/" TARGET_NAME, false), "relative native child launch");
        CHECK(!setenv("PATH", "/missing:/tmp", 1) && !spawn_child(TARGET_NAME, true), "PATH native child launch");
        CHECK(alix_get_executable_path(buffer, SYSCALL_EXECUTABLE_PATH_MAX) == constructor_length && !strcmp(buffer, expected),
              "immutable parent launch snapshot after rename");
        CHECK(!unlink(TARGET_PATH), "remove guest fixture");
        serial_printf("EXECUTABLE_PATH_TEST: PASS kernel_loader=1 spawn=1 search=1 constructor=1 rename_snapshot=1 reply_checks=1\n");
    }
    free(buffer); free(constructor_path); return 0;
}
