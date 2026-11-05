#include "stdio.h"
#include "unistd.h"
#include "sys/wait.h"
#include "time.h"
#include "errno.h"
#include "string.h"

/* A normal userland launcher: fork a child, replace its image, and propagate
 * its status while reporting elapsed wall time. */
int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: time command [argument ...]\n"); return 2; }
    struct timespec before, after;
    if (clock_gettime(CLOCK_MONOTONIC, &before)) return 1;
    pid_t child = fork();
    if (child < 0) { fprintf(stderr, "time: fork: %s\n", strerror(errno)); return 1; }
    if (!child)
    {
        execvp(argv[1], argv + 1);
        int error = errno;
        fprintf(stderr, "time: %s: %s\n", argv[1], strerror(error));
        _exit(error == ENOENT ? 127 : 126);
    }
    int status;
    pid_t waited;
    do waited = waitpid(child, &status, 0); while (waited < 0 && errno == EINTR);
    if (waited < 0 || clock_gettime(CLOCK_MONOTONIC, &after)) return 1;
    int64_t milliseconds = (after.tv_sec - before.tv_sec) * 1000 + (after.tv_nsec - before.tv_nsec) / 1000000;
    fprintf(stderr, "real %lld.%03llds\n", (long long)(milliseconds / 1000), (long long)(milliseconds % 1000));
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
