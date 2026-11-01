/* Actual upstream libc++/libc++abi acceptance in Alix, not a stand-in engine. */
#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <cmath>
#include <fstream>

#include "userlib.h"
#include "serial.h"
#include "stdlib.h"
#include "errno.h"
#include "unistd.h"
#include "sched.h"

static std::atomic<unsigned> main_tls_destroyed{0};
static bool main_passed;
static unsigned exit_order;

struct MainTls {
    ~MainTls() { if (record) main_tls_destroyed.fetch_add(1); }
    unsigned initialized = 23;
    bool record = false;
};
static thread_local MainTls main_tls;

static void exit_callback()
{
    if (main_tls_destroyed.load() != 1 || exit_order != 0) main_passed = false;
    ++exit_order;
}

struct GlobalLifetime {
    ~GlobalLifetime()
    {
        bool pass = main_passed && exit_order == 1 && main_tls_destroyed.load() == 1;
        serial_printf("CPP_STDLIB_TEST: exit %s\n", pass ? "PASS" : "FAIL");
        if (!pass) _Exit(1);
    }
} global_lifetime;

struct Shared {
    std::mutex mutex;
    std::condition_variable changed;
    std::atomic<unsigned> destructors{0};
    std::atomic<unsigned> failures{0};
    unsigned ready = 0;
    unsigned completed = 0;
    unsigned count = 0;
    unsigned cpu_mask = 0;
    bool start = false;
};

struct ThreadLifetime {
    Shared *shared = nullptr;
    ~ThreadLifetime() { if (shared) shared->destructors.fetch_add(1); }
};
static thread_local ThreadLifetime lifetime;
static thread_local unsigned initialized_tls = 17;

static bool file_stream_roundtrip(unsigned index)
{
    const std::string path = "/tmp/cxx-file-" + std::to_string(getpid()) + "-" + std::to_string(index);
    std::string bytes(1024, '\0');
    for (unsigned i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<char>((i + index) % 251);
    auto output = std::make_unique<std::ofstream>(path, std::ios::binary | std::ios::trunc);
    output->write(bytes.data(), bytes.size());
    output->close();
    bool okay = !output->fail();
    output->open(path, std::ios::binary | std::ios::app);
    output->write("tail", 4);
    output->close();
    okay = okay && !output->fail();
    bytes += "tail";
    auto stream = std::make_unique<std::fstream>(path, std::ios::in | std::ios::out | std::ios::binary);
    std::string result(bytes.size(), '\0');
    stream->read(result.data(), result.size());
    okay = okay && stream->gcount() == static_cast<std::streamsize>(bytes.size()) && result == bytes;
    const std::streamoff far = (std::streamoff(1) << 33) + 7;
    stream->seekg(far);
    okay = okay && !stream->fail() && stream->tellg() == std::streampos(far);
    stream->seekg(0);
    stream->seekp(1);
    stream->put('!');
    stream->flush();
    stream->seekg(0);
    stream->read(result.data(), result.size());
    bytes[1] = '!';
    okay = okay && !stream->fail() && result == bytes;
    stream->close();
    okay = okay && !stream->fail() && unlink(path.c_str()) == 0;
    auto missing = std::make_unique<std::ifstream>(path);
    return okay && !missing->is_open() && missing->fail();
}

static void worker(Shared *shared, unsigned index)
{
    if (sys_thread_set_affinity(index) != 0 || sched_yield() != 0 || sched_getcpu() != static_cast<int>(index))
        shared->failures.fetch_add(1);
    lifetime.shared = shared;
    if (!file_stream_roundtrip(index)) shared->failures.fetch_add(1);
    if (initialized_tls != 17) shared->failures.fetch_add(1);
    initialized_tls += index + 1;
    std::unique_lock<std::mutex> lock(shared->mutex);
    shared->cpu_mask |= 1u << index;
    ++shared->ready;
    shared->changed.notify_all();
    shared->changed.wait(lock, [shared] { return shared->start; });
    lock.unlock();
    for (unsigned round = 0; round < 128; ++round)
    {
        std::lock_guard<std::mutex> hold(shared->mutex);
        unsigned prior = shared->count;
        if ((round & 15u) == 0) std::this_thread::yield();
        shared->count = prior + 1;
        if (initialized_tls != 18 + index) shared->failures.fetch_add(1);
    }
    lock.lock();
    ++shared->completed;
    shared->changed.notify_all();
}

struct alignas(256) Aligned { unsigned char data[256]; };

int main()
{
    main_tls.record = true;
    bool okay = main_tls.initialized == 23 && atexit(exit_callback) == 0;
    std::vector<std::string> words;
    words.emplace_back("native");
    words.emplace_back(200, 'z');
    words.emplace_back("Alix");
    std::sort(words.begin(), words.end());
    okay = okay && words.front() == "Alix" && words[2].size() == 200;
    std::string joined = words[0] + ":" + words[1];
    okay = okay && joined == "Alix:native";
    std::vector<unsigned> values;
    for (unsigned i = 0; i < 4096; ++i) values.push_back(4095 - i);
    std::sort(values.begin(), values.end());
    for (unsigned i = 0; i < values.size(); ++i) okay = okay && values[i] == i;

    auto aligned = std::make_unique<Aligned>();
    okay = okay && reinterpret_cast<uintptr_t>(aligned.get()) % 256 == 0;
    for (unsigned i = 0; i < 256; ++i) aligned->data[i] = static_cast<unsigned char>(i);
    for (unsigned i = 0; i < 256; ++i) okay = okay && aligned->data[i] == static_cast<unsigned char>(i);
    aligned.reset();

    std::size_t consumed = 0;
    okay = okay && std::stoll(" -9223372036854775808suffix", &consumed) == (-9223372036854775807LL - 1);
    okay = okay && consumed == 21;
    okay = okay && std::stod("0x1.8p+1") == 3.0;
    double parsed = 0;
    const char decimal[] = "1.2345678901234567";
    auto parsed_result = std::from_chars(decimal, decimal + sizeof(decimal) - 1, parsed);
    okay = okay && parsed_result.ec == std::errc{} && parsed == 1.2345678901234567;
    char *end = nullptr;
    errno = 0;
    double tiny = strtod("5e-324", &end);
    okay = okay && tiny > 0 && *end == '\0';
    errno = 0;
    double huge = strtod("1e9999", &end);
    okay = okay && std::isinf(huge) && errno == ERANGE && *end == '\0';

    auto started = std::chrono::steady_clock::now();
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
    auto elapsed = std::chrono::steady_clock::now() - started;
    okay = okay && elapsed >= std::chrono::milliseconds(20);
    okay = okay && std::thread::hardware_concurrency() == 8;

    auto shared = std::make_unique<Shared>();
    std::vector<std::thread> threads;
    threads.reserve(8);
    for (unsigned index = 0; index < 8; ++index) threads.emplace_back(worker, shared.get(), index);
    {
        std::unique_lock<std::mutex> lock(shared->mutex);
        bool ready = shared->changed.wait_for(lock, std::chrono::seconds(5), [&shared] { return shared->ready == 8; });
        okay = okay && ready;
        shared->start = true;
        shared->changed.notify_all();
    }
    for (auto &thread : threads) thread.join();
    okay = okay && shared->completed == 8 && shared->count == 1024 && shared->cpu_mask == 0xFF;
    okay = okay && shared->failures.load() == 0 && shared->destructors.load() == 8;
    serial_printf("CPP_STDLIB_TEST: files %s threads=8 binary=1 append=1 seek64=1 missing=1\n",
                  shared->failures.load() == 0 ? "PASS" : "FAIL");
    main_passed = okay;
    serial_printf("CPP_STDLIB_TEST: main %s workers=8 cpu_mask=0x%X counter=%u tls_dtors=%u\n",
                  okay ? "PASS" : "FAIL", shared->cpu_mask, shared->count, shared->destructors.load());
    return okay ? 0 : 1;
}
