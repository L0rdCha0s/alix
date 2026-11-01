/* Exercise upstream libc++ random_device with the actual Alix entropy API. */
#include <algorithm>
#include <atomic>
#include <memory>
#include <random>
#include <thread>
#include <vector>

#include "errno.h"
#include "fcntl.h"
#include "serial.h"
#include "signal.h"
#include "stdlib.h"
#include "string.h"
#include "sys/random.h"
#include "unistd.h"
#include "usyscall.h"

static_assert(std::random_device::min() == 0 && std::random_device::max() == 0xffffffffu);
static std::atomic<unsigned> abort_phase{0};
static void expected_abort(int number)
{
    unsigned phase = abort_phase.load(std::memory_order_acquire);
    if (number != SIGABRT || (phase != 1 && phase != 2)) _Exit(1);
    static constexpr char unsupported[] = "CPP_RANDOM_TEST: unsupported PASS\n";
    static constexpr char invalid[] = "CPP_RANDOM_TEST: invalid_token PASS\n";
    /* Do not allocate or enter a stdio mutex from a signal handler. */
    if (phase == 1) sys_serial_write(unsupported, sizeof(unsupported) - 1);
    else sys_serial_write(invalid, sizeof(invalid) - 1);
    _Exit(0);
}

#define CHECK(c, label) do { if (!(c)) { serial_printf("CPP_RANDOM_TEST: FAIL %s line=%u errno=%d\n", label, __LINE__, errno); return 1; } } while (0)
static constexpr unsigned workers_count = 8;
static constexpr unsigned samples_count = 512;
struct Shared;
struct Worker {
    Shared *shared;
    unsigned cpu;
    std::thread thread;
    unsigned samples[samples_count];
};
struct Shared {
    std::atomic<unsigned> ready{0}, start{0}, failures{0}, cpu_mask{0};
    Worker workers[workers_count];
};
static void generate(Worker *worker)
{
    Shared *shared = worker->shared;
    if (sys_thread_set_affinity(worker->cpu) || sys_thread_cpu() != worker->cpu)
        shared->failures.fetch_add(1);
    shared->cpu_mask.fetch_or(1u << worker->cpu);
    auto device = std::make_unique<std::random_device>();
    if (device->entropy() < 0 || device->entropy() > 32) shared->failures.fetch_add(1);
    shared->ready.fetch_add(1, std::memory_order_release);
    while (!shared->start.load(std::memory_order_acquire)) sys_yield();
    for (unsigned i = 0; i < samples_count; ++i) worker->samples[i] = (*device)();
}

int main(int argc, char **argv)
{
    if (argc == 2)
    {
        auto action = static_cast<struct sigaction *>(calloc(1, sizeof(struct sigaction)));
        CHECK(action, "abort action allocation");
        action->sa_handler = expected_abort;
        CHECK(!sigemptyset(&action->sa_mask) && !sigaction(SIGABRT, action, nullptr), "expected failure handler");
        free(action);
        if (!strcmp(argv[1], "unsupported"))
        {
            auto word = std::make_unique<unsigned>(0xa5a5a5a5u);
            CHECK(getentropy(word.get(), sizeof(*word)) == -1 && errno == ENOSYS && *word == 0xa5a5a5a5u,
                  "native entropy unavailable without output mutation");
            auto device = std::make_unique<std::random_device>();
            abort_phase.store(1, std::memory_order_release);
            *word = (*device)();
        }
        else
        {
            CHECK(!strcmp(argv[1], "invalid"), "known failure mode");
            abort_phase.store(2, std::memory_order_release);
            auto device = std::make_unique<std::random_device>("alix-invalid-random-token");
            (void)device;
        }
        CHECK(false, "random-device failure returned or used a substitute");
    }
    CHECK(argc == 1 && sysconf(_SC_NPROCESSORS_ONLN) == workers_count, "eight CPU guest");
    auto shared = std::make_unique<Shared>();
    for (unsigned i = 0; i < workers_count; ++i)
    {
        shared->workers[i].shared = shared.get(); shared->workers[i].cpu = i;
        shared->workers[i].thread = std::thread(generate, &shared->workers[i]);
    }
    uint64_t deadline = sys_monotonic_millis() + 5000;
    while (shared->ready.load(std::memory_order_acquire) != workers_count)
    {
        CHECK(sys_monotonic_millis() < deadline, "workers become ready");
        sys_yield();
    }
    shared->start.store(1, std::memory_order_release);
    for (auto &worker : shared->workers) worker.thread.join();
    CHECK(!shared->failures.load() && shared->cpu_mask.load() == 255, "all pinned generators");
    std::vector<unsigned> samples;
    samples.reserve(workers_count * samples_count);
    for (const auto &worker : shared->workers)
        samples.insert(samples.end(), worker.samples, worker.samples + samples_count);
    std::sort(samples.begin(), samples.end());
    auto unique = std::unique(samples.begin(), samples.end());
    CHECK(unique - samples.begin() >= workers_count * samples_count - 6, "nonrepeating entropy samples");

    // The getentropy implementation must work without allocating a file slot.
    std::vector<int> aliases;
    aliases.reserve(256);
    for (unsigned i = 0; i < 257; ++i)
    {
        int fd = dup(STDIN_FILENO);
        if (fd < 0) break;
        aliases.push_back(fd);
    }
    CHECK(aliases.size() >= 240 && aliases.size() <= 253 && errno == EMFILE, "private descriptor table exhausted");
    auto device = std::make_unique<std::random_device>("/dev/urandom");
    unsigned previous = (*device)();
    bool changed = false;
    for (unsigned i = 0; i < 32; ++i) if ((*device)() != previous) changed = true;
    CHECK(changed, "entropy with no available descriptors");
    for (int fd : aliases) CHECK(!close(fd), "release descriptor aliases");
    serial_printf("CPP_RANDOM_TEST: PASS cpus=8 samples=4096 fd_pressure=1\n");
    return 0;
}
