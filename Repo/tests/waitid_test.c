#include "alix_process.h"
#include "errno.h"
#include "fcntl.h"
#include "pthread.h"
#include "serial.h"
#include "stdlib.h"
#include "string.h"
#include "sys/mman.h"
#include "sys/wait.h"
#include "unistd.h"
#include "usyscall.h"

#define PROGRAM "/tmp/test.elf"
#define CHECK(c, label) do { if (!(c)) { serial_printf("WAITID_TEST: FAIL %s line=%u errno=%d\n", label, __LINE__, errno); return 1; } } while (0)
typedef struct
{
    pthread_t thread;
    unsigned cpu, consume, failed;
    pid_t pid;
    int result, error, status;
    siginfo_t info;
} wait_job_t;
typedef struct
{
    wait_job_t jobs[8];
    char *arguments[4];
    siginfo_t info, empty;
    int status, pipes[2];
    char bytes[16];
} wait_fixture_t;

static void *wait_worker(void *context)
{
    wait_job_t *job = context;
    if (sys_thread_set_affinity(job->cpu) || sys_thread_cpu() != job->cpu) job->failed = 1;
    if (!job->consume)
    {
        for (unsigned index = 0; index < 8; ++index)
        {
            job->result = waitid(P_PID, job->pid, &job->info, WEXITED | WNOWAIT);
            if (job->result || job->info.si_pid != job->pid || job->info.si_code != CLD_EXITED ||
                job->info.si_status != 37 || job->info.si_signo != SIGCHLD) job->failed = 1;
        }
    }
    else
    {
        memset(&job->info, 0x5a, sizeof(job->info));
        job->status = 0x5a5a5a5a;
        job->result = job->cpu & 1 ? waitpid(job->pid, &job->status, 0) :
                                   waitid(P_PID, job->pid, &job->info, WEXITED);
        job->error = errno;
    }
    return NULL;
}

static int child(const char *mode)
{
    if (!strcmp(mode, "slow")) { sys_sleep_ms(750); return 37; }
    if (!strcmp(mode, "exit")) return 255;
    if (!strcmp(mode, "signal")) { raise(SIGTERM); return 1; }
    if (!strcmp(mode, "writer")) { sys_sleep_ms(750); CHECK(write(4, "ORPHAN", 6) == 6, "orphan writer"); return 0; }
    if (!strcmp(mode, "owner"))
    {
        wait_fixture_t *test = calloc(1, sizeof(*test)); CHECK(test, "owner heap");
        test->arguments[0] = PROGRAM; test->arguments[1] = "writer";
        pid_t pid = alix_spawn_argv(PROGRAM, test->arguments); CHECK(pid > 0, "owner child");
        CHECK(write(4, "READY", 5) == 5, "owner marker");
        (void)waitid(P_PID, pid, &test->info, WEXITED | WNOWAIT);
        CHECK(0, "killed waitid owner resumed");
    }
    CHECK(0, "unknown child mode");
}

int main(int argc, char **argv)
{
    if (argc > 1) return child(argv[1]);
    wait_fixture_t *test = calloc(1, sizeof(*test)); CHECK(test, "heap fixture");
    test->arguments[0] = PROGRAM; test->arguments[1] = "slow";
    CHECK(waitid(P_ALL, 0, &test->info, WEXITED | WNOHANG) == -1 && errno == ECHILD, "empty registry");
    pid_t pid = alix_spawn_argv(PROGRAM, test->arguments); CHECK(pid > 0, "slow child");
    memset(&test->info, 0x5a, sizeof(test->info)); errno = EDOM;
    CHECK(!waitid(P_PID, pid, &test->info, WEXITED | WNOHANG | WNOWAIT) &&
          !memcmp(&test->info, &test->empty, sizeof(test->info)) && errno == EDOM, "WNOHANG zeros info and preserves errno");
    CHECK(!waitid(P_PID, pid, &test->info, WEXITED | WNOWAIT) && test->info.si_pid == pid &&
          test->info.si_signo == SIGCHLD && test->info.si_code == CLD_EXITED &&
          test->info.si_status == 37 && test->info.si_uid == getuid(), "blocking non-consuming status");
    CHECK(waitid(P_PID, pid, NULL, WEXITED) == -1 && errno == EFAULT, "null output");
    CHECK(waitid(P_PID, pid, (siginfo_t *)1, WEXITED) == -1 && errno == EFAULT, "invalid output");
    siginfo_t *readonly = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(readonly != MAP_FAILED, "read-only destination");
    CHECK(waitid(P_PID, pid, readonly, WEXITED) == -1 && errno == EFAULT, "copy failure preserves child");
    CHECK(!munmap(readonly, 4096), "release destination");
    CHECK(waitid((idtype_t)99, pid, &test->info, WEXITED) == -1 && errno == EINVAL, "invalid selector");
    CHECK(waitid(P_PID, 0, &test->info, WEXITED) == -1 && errno == EINVAL, "zero PID");
    CHECK(waitid(P_PID, pid, &test->info, WNOHANG) == -1 && errno == EINVAL, "event selection required");
    CHECK(waitid(P_PGID, 0, &test->info, WEXITED) == -1 && errno == ENOTSUP, "unsupported groups");
    CHECK(waitid(P_PID, pid, &test->info, WEXITED | WCONTINUED) == -1 && errno == ENOTSUP, "unsupported job control");
    for (unsigned consume = 0; consume < 2; ++consume)
    {
        memset(test->jobs, 0, sizeof(test->jobs));
        for (unsigned cpu = 0; cpu < 8; ++cpu)
        {
            wait_job_t *job = &test->jobs[cpu]; job->cpu = cpu; job->pid = pid; job->consume = consume;
            CHECK(!pthread_create(&job->thread, NULL, wait_worker, job), "wait worker creation");
        }
        unsigned winners = 0, losers = 0;
        for (unsigned cpu = 0; cpu < 8; ++cpu)
        {
            wait_job_t *job = &test->jobs[cpu];
            CHECK(!pthread_join(job->thread, NULL) && !job->failed, "pinned worker completion");
            if (!consume) continue;
            if ((cpu & 1) ? job->result == pid && WIFEXITED(job->status) && WEXITSTATUS(job->status) == 37 :
                            !job->result && job->info.si_pid == pid && job->info.si_status == 37) ++winners;
            else if (job->result == -1 && job->error == ECHILD && job->status == 0x5a5a5a5a &&
                     job->info.si_pid == 0x5a5a5a5a) ++losers;
        }
        if (consume) CHECK(winners == 1 && losers == 7, "mixed waitid/waitpid exactly once reap");
    }
    test->arguments[1] = "exit";
    pid = alix_spawn_argv(PROGRAM, test->arguments); CHECK(pid > 0, "exit 255 child");
    CHECK(!waitid(P_ALL, 123, &test->info, WEXITED) && test->info.si_pid == pid &&
          test->info.si_status == 255 && test->info.si_code == CLD_EXITED, "P_ALL consuming status");
    CHECK(waitpid(pid, &test->status, WNOHANG) == -1 && errno == ECHILD, "waitid removes registry entry");
    test->arguments[1] = "signal";
    pid = alix_spawn_argv(PROGRAM, test->arguments); CHECK(pid > 0, "signal child");
    CHECK(!waitid(P_PID, pid, &test->info, WEXITED | WNOWAIT) && test->info.si_pid == pid &&
          test->info.si_code == CLD_KILLED && test->info.si_status == SIGTERM, "signal cause");
    CHECK(waitpid(pid, &test->status, 0) == pid && WIFSIGNALED(test->status) && WTERMSIG(test->status) == SIGTERM, "peek then waitpid");
    CHECK(!pipe(test->pipes) && test->pipes[0] == 3 && test->pipes[1] == 4 &&
          !fcntl(3, F_SETFD, FD_CLOEXEC), "abandoned waiter pipe");
    test->arguments[1] = "owner";
    pid = alix_spawn_argv(PROGRAM, test->arguments); CHECK(pid > 0 && !close(4), "waiting owner");
    CHECK(read(3, test->bytes, 5) == 5 && !memcmp(test->bytes, "READY", 5), "owner entered wait");
    sys_sleep_ms(100);
    CHECK(!kill(pid, SIGKILL) && !waitid(P_PID, pid, &test->info, WEXITED) &&
          test->info.si_code == CLD_KILLED && test->info.si_status == SIGKILL, "killed waiter retirement");
    CHECK(read(3, test->bytes, 6) == 6 && !memcmp(test->bytes, "ORPHAN", 6) &&
          read(3, test->bytes, 1) == 0 && !close(3), "descendant survives abandoned waitid");
    free(test);
    serial_printf("WAITID_TEST: PASS cpus=8 peeks=64 mixed_reap=1 nohang=1 copy_rollback=1 signal=1 killed_waiter=1\n");
    return 0;
}
