#include "dlfcn.h"
#include "elf.h"
#include "errno.h"
#include "fcntl.h"
#include "link.h"
#include "pthread.h"
#include "serial.h"
#include "stdlib.h"
#include "string.h"
#include "sys/auxv.h"
#include "sys/mman.h"
#include "sys/resource.h"
#include "unistd.h"
#include "usyscall.h"

#define CHECK(c, label) do { if (!(c)) { serial_printf("BASE_ELF_RSS_TEST: FAIL %s line=%u errno=%d\n", label, __LINE__, errno); return 1; } } while (0)
#define PAGES 128u
typedef struct fixture fixture_t;
typedef struct { pthread_t thread; fixture_t *test; unsigned cpu, failed; unsigned char *pages; } image_job_t;
struct fixture
{
    image_job_t jobs[8];
    unsigned ready, release, failed, main_seen, library_seen, nested, tls_seen, note_seen;
    void *handle;
    int close_result;
    int (*value)(void);
    uintptr_t headers, random, path;
    syscall_resource_usage_v2_t before, during, after;
    struct rusage usage;
    Dl_info address;
    Elf64_Ehdr ehdr;
    Elf64_Phdr disk_header;
    pthread_t closer;
};
static void *close_library(void *context)
{
    fixture_t *test = context; test->close_result = dlclose(test->handle); return NULL;
}
static int stop_iteration(struct dl_phdr_info *info, size_t size, void *context)
{
    (void)info; (void)size; (void)context; return 17;
}
static int image_callback(struct dl_phdr_info *info, size_t size, void *context)
{
    fixture_t *test = context;
    if (size < sizeof(*info) || !info->dlpi_phdr || !info->dlpi_phnum || !info->dlpi_name)
    { test->failed = 1; return 1; }
    if (!*info->dlpi_name)
    {
        if (info->dlpi_addr || (uintptr_t)info->dlpi_phdr != test->headers ||
            info->dlpi_phnum != getauxval(AT_PHNUM)) test->failed = 2;
        ++test->main_seen;
    }
    if (strstr(info->dlpi_name, "libalix-phdr.so"))
    {
        ++test->library_seen;
        if (!info->dlpi_addr || pthread_create(&test->closer, NULL, close_library, test) ||
            pthread_join(test->closer, NULL) || test->close_result) { test->failed = 3; return 1; }
        /* Another CPU closed the final external handle. Snapshot ownership
         * must still protect code and the full PT_TLS/PT_NOTE metadata. */
        if (test->value() != 42) test->failed = 4;
        for (unsigned i = 0; i < info->dlpi_phnum; ++i)
        {
            const Elf64_Phdr *p = &info->dlpi_phdr[i];
            if (p->p_type == PT_TLS && p->p_memsz >= sizeof(int)) ++test->tls_seen;
            if (p->p_type == PT_NOTE && p->p_filesz >= sizeof(Elf64_Nhdr)) ++test->note_seen;
        }
        test->nested = dl_iterate_phdr(stop_iteration, NULL) == 17;
    }
    return 0;
}
static void *image_worker(void *context)
{
    image_job_t *job = context; fixture_t *test = job->test;
    if (sys_thread_set_affinity(job->cpu) || sys_thread_cpu() != job->cpu) job->failed = 1;
    for (unsigned i = 0; i < 128; ++i)
    {
        errno = EDOM;
        if (getauxval(AT_PHDR) != test->headers || getauxval(AT_RANDOM) != test->random ||
            getauxval(AT_EXECFN) != test->path || errno != EDOM) job->failed = 2;
    }
    job->pages = mmap(NULL, PAGES * 4096u, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (job->pages == MAP_FAILED) job->failed = 3;
    else
    {
        for (unsigned i = 0; i < PAGES; ++i) job->pages[i * 4096u] = (unsigned char)i;
        if (mprotect(job->pages, PAGES * 4096u, PROT_READ) ||
            mprotect(job->pages, PAGES * 4096u, PROT_READ | PROT_WRITE)) job->failed = 4;
    }
    __atomic_add_fetch(&test->ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&test->release, __ATOMIC_ACQUIRE)) sys_yield();
    if (job->pages != MAP_FAILED && munmap(job->pages, PAGES * 4096u)) job->failed = 5;
    return NULL;
}
typedef struct { struct timeval user, system; long minor, major; } old_usage_t;
int old_getrusage(int, old_usage_t *) __asm__("getrusage");
int main(void)
{
    _Static_assert(sizeof(Elf32_Nhdr) == 12 && sizeof(Elf64_Phdr) == 56, "native ELF metadata layouts");
    fixture_t *test = calloc(1, sizeof(*test)); CHECK(test, "heap fixture");
    errno = EDOM;
    CHECK(getauxval(AT_PAGESZ) == 4096 && !getauxval(AT_BASE) && errno == EDOM, "zero-valued and ordinary metadata");
    CHECK(!getauxval(0x7fffffff) && errno == ENOENT, "absent auxiliary entry");
    test->headers = getauxval(AT_PHDR); test->random = getauxval(AT_RANDOM); test->path = getauxval(AT_EXECFN);
    CHECK(test->headers && test->random && test->path && getauxval(AT_PHENT) == sizeof(Elf64_Phdr) &&
          getauxval(AT_PHNUM) > 0 && getauxval(AT_UID) == getuid() && getauxval(AT_EGID) == getegid() &&
          !strcmp((void *)getauxval(AT_PLATFORM), "x86_64") && getauxval(AT_CLKTCK) > 0, "native auxiliary entries");
    unsigned entropy = 0;
    for (unsigned i = 0; i < 16; ++i) entropy |= ((unsigned char *)test->random)[i];
    CHECK(entropy, "kernel-backed random bytes");
    int fd = open((const char *)test->path, O_RDONLY);
    CHECK(fd >= 0 && pread(fd, &test->ehdr, sizeof(test->ehdr), 0) == sizeof(test->ehdr) &&
          test->ehdr.e_entry == getauxval(AT_ENTRY) && test->ehdr.e_phnum == getauxval(AT_PHNUM), "captured running executable identity");
    for (unsigned i = 0; i < test->ehdr.e_phnum; ++i)
        CHECK(pread(fd, &test->disk_header, sizeof(test->disk_header), test->ehdr.e_phoff + i * sizeof(Elf64_Phdr)) == sizeof(Elf64_Phdr) &&
              !memcmp(&test->disk_header, (const Elf64_Phdr *)test->headers + i, sizeof(Elf64_Phdr)), "captured program headers match ELF bytes");
    CHECK(!close(fd), "executable close");
    CHECK(sys_process(SYSCALL_PROCESS_ELF_INFO, 1, sizeof(syscall_elf_info_t) + test->ehdr.e_phnum * sizeof(Elf64_Phdr), 0) == -EFAULT,
          "metadata copy rejects kernel-invalid user pointer");
    test->handle = dlopen("/tmp/libalix-phdr.so", RTLD_NOW); CHECK(test->handle, "load real ELF fixture");
    test->value = dlsym(test->handle, "phdr_fixture_value"); CHECK(test->value, "fixture function");
    CHECK(!dl_iterate_phdr(image_callback, test) && !test->failed && test->main_seen == 1 &&
          test->library_seen == 1 && test->nested && test->tls_seen == 1 && test->note_seen >= 1,
          "reentrant loader callbacks retain code, TLS and note headers");
    CHECK(!dladdr((const void *)test->value, &test->address), "snapshot release permits real unload");
    struct { old_usage_t usage; uint64_t guard; } *legacy = calloc(1, sizeof(*legacy)); CHECK(legacy, "legacy output fixture");
    legacy->guard = UINT64_C(0x1234abcd5678abcd);
    CHECK(!old_getrusage(RUSAGE_SELF, &legacy->usage) && legacy->guard == UINT64_C(0x1234abcd5678abcd), "installed rusage ABI stays bounded");
    free(legacy);
    CHECK(!sys_resource_usage(SYSCALL_USAGE_SELF, &test->before.usage, sizeof(test->before)) &&
          test->before.usage.version == 2 && test->before.peak_resident_pages >= test->before.resident_pages &&
          test->before.resident_pages > 0, "initial resident accounting");
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    {
        image_job_t *job = &test->jobs[cpu]; job->test = test; job->cpu = cpu;
        CHECK(!pthread_create(&job->thread, NULL, image_worker, job), "eight memory workers");
    }
    uint64_t deadline = sys_monotonic_millis() + 10000;
    while (__atomic_load_n(&test->ready, __ATOMIC_ACQUIRE) < 8 && sys_monotonic_millis() < deadline) sys_yield();
    CHECK(test->ready == 8, "worker readiness");
    CHECK(!sys_resource_usage(SYSCALL_USAGE_SELF, &test->during.usage, sizeof(test->during)) &&
          test->during.resident_pages >= test->before.resident_pages + 8 * PAGES &&
          test->during.peak_resident_pages >= test->during.resident_pages, "real committed pages counted across CPUs");
    __atomic_store_n(&test->release, 1, __ATOMIC_RELEASE);
    for (unsigned cpu = 0; cpu < 8; ++cpu)
        CHECK(!pthread_join(test->jobs[cpu].thread, NULL) && !test->jobs[cpu].failed, "worker metadata and mapping completion");
    CHECK(!sys_resource_usage(SYSCALL_USAGE_SELF, &test->after.usage, sizeof(test->after)) &&
          test->after.resident_pages + 8 * PAGES <= test->during.resident_pages &&
          test->after.peak_resident_pages >= test->during.peak_resident_pages &&
          !getrusage(RUSAGE_SELF, &test->usage) && test->usage.ru_maxrss >= (long)test->during.peak_resident_pages * 4,
          "resident count falls after unmap while peak KiB remains");
    free(test);
    serial_printf("BASE_ELF_RSS_TEST: PASS cpus=8 auxv=1 phdr=1 callback_close=1 nested=1 notes=1 rss_pages=1024 legacy_abi=1\n");
    return 0;
}
