#include "alix_audio.h"
#include "alix_process.h"
#include "userlib.h"
#include "pthread.h"
#include "stdio.h"
#include "stdlib.h"
#include "errno.h"
#include "fcntl.h"
#include "sys/stat.h"
#include "unistd.h"
#include "serial.h"
#include "usyscall.h"
#include "string.h"
#include "signal.h"
#include "sys/wait.h"

#define WORKERS 8u
#define ROUNDS 32u
#define FRAMES 64u
#define CHECK(value, label) do { if (!(value)) { serial_printf("AUDIO_OWNED_TEST: FAIL %s errno=%d\n", label, errno); return 1; } } while (0)
typedef struct shared shared_t;
typedef struct { shared_t *shared; unsigned cpu; pthread_t thread; } worker_t;
struct shared
{
    int handle;
    unsigned char *pcm;
    volatile uint32_t ready, go, failures, mask;
    worker_t workers[WORKERS];
};

static int write_all(int handle, const void *pcm, size_t bytes)
{
    size_t done = 0;
    while (done < bytes)
    {
        ssize_t result = alix_audio_write(handle, (const unsigned char *)pcm + done, bytes - done);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0 || (size_t)result > bytes - done || result % 4) return -1;
        done += (size_t)result;
    }
    return 0;
}

static void *writer(void *argument)
{
    worker_t *worker = argument;
    shared_t *shared = worker->shared;
    if (sys_thread_set_affinity(worker->cpu) != 0 || sys_thread_cpu() != worker->cpu)
        __atomic_add_fetch(&shared->failures, 1u, __ATOMIC_RELAXED);
    __atomic_add_fetch(&shared->ready, 1u, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&shared->go, __ATOMIC_ACQUIRE)) sys_yield();
    for (unsigned round = 0; round < ROUNDS; ++round)
        if (write_all(shared->handle, shared->pcm, FRAMES * 4))
            __atomic_add_fetch(&shared->failures, 1u, __ATOMIC_RELAXED);
    __atomic_fetch_or(&shared->mask, 1u << worker->cpu, __ATOMIC_RELEASE);
    return NULL;
}

static int child_writer(int argc, char **argv)
{
    CHECK(argc == 4, "child arguments");
    unsigned char *pcm = malloc(262144);
    CHECK(pcm, "child heap PCM");
    memset(pcm, 0x18, 262144);
    int handle = atoi(argv[2]), marker = atoi(argv[3]);
    CHECK(alix_audio_write(handle, pcm, 65536) > 0 && write(marker, "A", 1) == 1 && close(marker) == 0,
          "inherited child channel committed PCM");
    for (;;) CHECK(write_all(handle, pcm, 262144) == 0, "child sustained PCM");
}

static int killed_writer(const unsigned char *pcm)
{
    int handle = alix_audio_open(0);
    int *pipes = calloc(2, sizeof(*pipes)), *status = malloc(sizeof(*status));
    char **arguments = calloc(5, sizeof(*arguments));
    char *audio_number = malloc(32), *marker_number = malloc(32), *marker = malloc(1);
    syscall_process_info_t *snapshot = calloc(256, sizeof(*snapshot));
    CHECK(handle >= 0 && pipes && status && arguments && audio_number && marker_number && marker && snapshot,
          "killed writer heap state");
    CHECK(pipe(pipes) == 0 && fcntl(pipes[0], F_SETFD, FD_CLOEXEC) == 0, "child ready pipe");
    snprintf(audio_number, 32, "%d", handle); snprintf(marker_number, 32, "%d", pipes[1]);
    arguments[0] = "/tmp/test.elf"; arguments[1] = "audio-writer";
    arguments[2] = audio_number; arguments[3] = marker_number;
    pid_t child = alix_spawn_argv(arguments[0], arguments);
    CHECK(child > 0 && close(pipes[1]) == 0 && alix_audio_close(handle) == 0 &&
          read(pipes[0], marker, 1) == 1 && *marker == 'A' && close(pipes[0]) == 0,
          "child inherited audio after parent close");
    bool blocked = false;
    for (unsigned attempt = 0; attempt < 100 && !blocked; ++attempt)
    {
        ssize_t count = sys_proc_snapshot(snapshot, 256);
        CHECK(count >= 0 && count <= 256, "child audio I/O snapshot");
        for (ssize_t index = 0; index < count; ++index)
            if (snapshot[index].pid == (uint64_t)child && snapshot[index].thread_state == SYSCALL_THREAD_STATE_BLOCKED)
                blocked = true;
        if (!blocked) sys_sleep_ms(1);
    }
    CHECK(blocked && kill(child, SIGKILL) == 0 && waitpid(child, status, 0) == child &&
          WIFSIGNALED(*status) && WTERMSIG(*status) == SIGKILL, "kill/reap a blocked final audio owner");
    handle = alix_audio_open(0);
    CHECK(handle >= 0, "post-kill channel open");
    uint64_t deadline = sys_monotonic_millis() + 3000;
    int result;
    do
    {
        result = write_all(handle, pcm, 4800 * 4);
        if (!result || errno != EBUSY) break;
        sys_sleep_ms(1);
    } while (sys_monotonic_millis() < deadline);
    CHECK(!result && alix_audio_drain(handle) == 0 && alix_audio_close(handle) == 0,
          "queued PCM survives killed waiter without stranding the device");
    free(snapshot); free(marker); free(marker_number); free(audio_number); free(arguments); free(status); free(pipes);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "audio-writer")) return child_writer(argc, argv);
    alix_audio_status_t *status = calloc(1, sizeof(*status));
    unsigned char *pcm = malloc(4800 * 4);
    shared_t *shared = calloc(1, sizeof(*shared));
    CHECK(status && pcm && shared, "heap fixture");
    for (size_t index = 0; index < 4800 * 4; ++index) pcm[index] = (unsigned char)(index & 15u);
    CHECK(alix_audio_open(2) == -1 && errno == EINVAL, "unknown open flags");
    int handle;
    uint64_t ready_deadline = sys_monotonic_millis() + 10000;
    do
    {
        handle = alix_audio_open(ALIX_AUDIO_CLOEXEC);
        if (handle >= 0 || errno != ENODEV) break;
        sys_sleep_ms(10);
    } while (sys_monotonic_millis() < ready_deadline);
    CHECK(handle >= 0 && fcntl(handle, F_GETFD) == FD_CLOEXEC, "private CLOEXEC audio channel");
    struct stat *metadata = calloc(1, sizeof(*metadata));
    CHECK(metadata && fstat(handle, metadata) == 0 && S_ISCHR(metadata->st_mode), "audio character metadata");
    CHECK(alix_audio_get_status(handle, status) == 0 && status->version == 1 && status->size == sizeof(*status) &&
          status->rate == 48000 && status->channels == 2 && status->frame_bytes == 4 &&
          !status->submitted_frames && !status->played_frames && !status->flags, "native format and initial position");
    CHECK(read(handle, pcm, 4) == -1 && errno == EBADF && lseek(handle, 0, SEEK_SET) == -1 && errno == ESPIPE,
          "output-only nonseekable channel");
    CHECK(alix_audio_write(handle, pcm, 3) == -1 && errno == EINVAL &&
          alix_audio_write(handle, NULL, 4) == -1 && errno == EFAULT, "invalid PCM inputs");
    CHECK(sys_file_io(SYSCALL_FILE_AUDIO_STATUS, handle, (uintptr_t)status, sizeof(*status)-1, 1) == -EINVAL &&
          sys_file_io(SYSCALL_FILE_AUDIO_STATUS, handle, (uintptr_t)status, sizeof(*status), 2) == -ENOTSUP,
          "status size and version bounds");
    CHECK(alix_audio_get_status(handle, NULL) == -1 && errno == EFAULT, "status copy validation");
    CHECK(write_all(handle, pcm, 4800 * 4) == 0, "real HDA PCM enqueue");
    CHECK(alix_audio_get_status(handle, status) == 0 && status->submitted_frames == 4800 &&
          status->played_frames <= 4800 && status->queued_frames == 4800-status->played_frames && !status->dropped_frames,
          "played versus queued frame accounting");
    CHECK(alix_audio_drain(handle) == 0 && alix_audio_get_status(handle, status) == 0 &&
          status->played_frames == 4800 && !status->queued_frames && !status->dropped_frames && !status->flags,
          "hardware DMA completed all submitted frames");
    int alias = dup(handle);
    CHECK(alias >= 0 && alix_audio_close(handle) == 0 &&
          alix_audio_get_status(handle, status) == -1 && errno == EBADF, "close one alias");
    shared->handle = alias; shared->pcm = pcm;
    for (unsigned cpu = 0; cpu < WORKERS; ++cpu)
    {
        shared->workers[cpu].shared = shared; shared->workers[cpu].cpu = cpu;
        CHECK(pthread_create(&shared->workers[cpu].thread, NULL, writer, &shared->workers[cpu]) == 0, "SMP writer start");
    }
    while (__atomic_load_n(&shared->ready, __ATOMIC_ACQUIRE) != WORKERS) sys_yield();
    __atomic_store_n(&shared->go, 1u, __ATOMIC_RELEASE);
    for (unsigned cpu = 0; cpu < WORKERS; ++cpu)
        CHECK(pthread_join(shared->workers[cpu].thread, NULL) == 0, "SMP writer join");
    uint64_t expected = 4800 + WORKERS * ROUNDS * FRAMES;
    CHECK(!shared->failures && shared->mask == 255 && alix_audio_drain(alias) == 0 &&
          alix_audio_get_status(alias, status) == 0 && status->submitted_frames == expected &&
          status->played_frames == expected && !status->queued_frames && !status->dropped_frames && !status->flags,
          "eight-CPU writes share one exact hardware position");
    FILE *file = fopen("/tmp/audio-owned-regular", "w+");
    CHECK(file && alix_audio_write(fileno(file), pcm, 4) == -1 && errno == ENOTTY && ftell(file) == 0 &&
          alix_audio_get_status(fileno(file), status) == -1 && errno == ENOTTY && fclose(file) == 0,
          "audio operations reject ordinary descriptors without writing them");
    CHECK(write_all(alias, pcm, 4800 * 4) == 0 && alix_audio_close(alias) == 0, "close with queued DMA");
    sys_sleep_ms(250);
    handle = alix_audio_open(0);
    CHECK(handle >= 0, "fresh channel open");
    uint64_t deadline = sys_monotonic_millis() + 3000;
    int fresh_write;
    do
    {
        fresh_write = write_all(handle, pcm, 4800 * 4);
        if (!fresh_write || errno != EBUSY) break;
        sys_sleep_ms(1);
    } while (sys_monotonic_millis() < deadline);
    CHECK(fresh_write == 0 && alix_audio_drain(handle) == 0 &&
          alix_audio_get_status(handle, status) == 0 && status->played_frames == 4800 && !status->dropped_frames &&
          alix_audio_close(handle) == 0, "fresh channel after final-owner close");
    CHECK(killed_writer(pcm) == 0, "killed blocked writer lifecycle");
    free(metadata); free(shared); free(pcm); free(status);
    serial_printf("AUDIO_OWNED_TEST: PASS cpus=8 frames=21184 position=hardware alias=1 close_queued=1 killed_waiter=1\n");
    return 0;
}
