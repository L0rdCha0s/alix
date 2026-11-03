#include "errno.h"
#include "pthread.h"
#include "serial.h"
#include "stdlib.h"
#include "string.h"
#include "usyscall.h"

#define COUNT 1024u
#define CHECK(c, label) do { if (!(c)) { serial_printf("RANDOM_TEST: FAIL %s line=%u\n", label, __LINE__); return 1; } } while (0)
typedef struct { pthread_t thread; unsigned cpu, failed; long *values; } random_job_t;
typedef struct
{
    random_job_t jobs[8];
    long serial[COUNT], concurrent[COUNT], expected[16];
    int rand_values[16];
    char state_a[256], state_b[256];
} random_fixture_t;

static int compare(const void *left, const void *right)
{
    long a = *(const long *)left, b = *(const long *)right;
    return (a > b) - (a < b);
}
static void *random_worker(void *context)
{
    random_job_t *job = context;
    if (sys_thread_set_affinity(job->cpu) || sys_thread_cpu() != job->cpu) job->failed = 1;
    for (unsigned index = 0; index < COUNT / 8; ++index) job->values[index] = random();
    return NULL;
}
int main(void)
{
    random_fixture_t *test = calloc(1, sizeof(*test)); CHECK(test, "heap fixture");
    srandom(1234); errno = EDOM;
    for (unsigned index = 0; index < 16; ++index) test->expected[index] = random();
    srandom(1234);
    for (unsigned index = 0; index < 16; ++index) CHECK(random() == test->expected[index], "deterministic seeding");
    CHECK(errno == EDOM, "errno preserved");
    srand(72);
    for (unsigned index = 0; index < 16; ++index) test->rand_values[index] = rand();
    srand(72); srandom(5678);
    for (unsigned index = 0; index < 16; ++index)
    { (void)random(); CHECK(rand() == test->rand_values[index], "rand stream independent"); }
    srandom(2468);
    unsigned wide = 0;
    for (unsigned index = 0; index < COUNT; ++index)
    {
        test->serial[index] = random();
        CHECK(test->serial[index] >= 0 && test->serial[index] <= 0x7fffffffL, "31-bit range");
        if (test->serial[index] > 32767) ++wide;
    }
    CHECK(wide > COUNT / 2, "full random range");
    srandom(2468);
    for (unsigned cpu = 0; cpu < 8; ++cpu)
    {
        random_job_t *job = &test->jobs[cpu]; job->cpu = cpu; job->values = test->concurrent + cpu * (COUNT / 8);
        CHECK(!pthread_create(&job->thread, NULL, random_worker, job), "worker creation");
    }
    for (unsigned cpu = 0; cpu < 8; ++cpu)
        CHECK(!pthread_join(test->jobs[cpu].thread, NULL) && !test->jobs[cpu].failed, "pinned worker completion");
    qsort(test->serial, COUNT, sizeof(long), compare); qsort(test->concurrent, COUNT, sizeof(long), compare);
    CHECK(!memcmp(test->serial, test->concurrent, sizeof(test->serial)), "concurrent calls preserve serial stream");
    for (unsigned size = 8; size <= 256; size *= 2)
    {
        char *original = initstate(42, test->state_a, size); CHECK(original, "state initialization");
        for (unsigned index = 0; index < 8; ++index) (void)random();
        CHECK(setstate(original) == test->state_a, "save state position");
        memcpy(test->state_b, test->state_a, size);
        CHECK(setstate(test->state_a) == original, "state activation");
        for (unsigned index = 0; index < 16; ++index) test->expected[index] = random();
        CHECK(setstate(test->state_b) == test->state_a, "restore copied state");
        for (unsigned index = 0; index < 16; ++index) CHECK(random() == test->expected[index], "state position roundtrip");
        CHECK(setstate(original) == test->state_b, "restore original owner before freeing state");
    }
    srandom(1357); long first = random(); srandom(1357);
    CHECK(!initstate(9, test->state_a, 7) && random() == first, "undersized state leaves generator unchanged");
    free(test);
    serial_printf("RANDOM_TEST: PASS cpus=8 calls=1024 states=6 range=31 reseed=1 rand_independent=1\n");
    return 0;
}
