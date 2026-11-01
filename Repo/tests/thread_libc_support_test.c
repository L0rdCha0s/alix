#include "userlib.h"
#include "serial.h"
#include "stdlib.h"
#include "errno.h"

#define WORKERS 4u
#define ROUNDS 64u
#define MAX_SIZE ((size_t)-1)

extern int __cxa_atexit(void (*function)(void *), void *argument, void *dso);
extern void __cxa_finalize(void *dso);
extern int __cxa_thread_atexit_impl(void (*function)(void *), void *argument, void *dso);

typedef struct shared shared_t;
typedef struct
{
    shared_t *shared;
    alix_thread_t thread;
    uint32_t index;
    uint32_t repopulated;
    uint32_t reused;
    uint32_t tls_order;
} worker_t;

struct shared
{
    alix_recursive_mutex_t recursive;
    alix_once_t once;
    alix_tls_key_t repopulated_key;
    alix_tls_key_t old_key;
    alix_tls_key_t reused_key;
    worker_t workers[WORKERS];
    volatile uint32_t ready;
    volatile uint32_t start;
    volatile uint32_t once_attempts;
    volatile uint32_t once_calls;
    volatile uint32_t failures;
    volatile uint32_t cpu_mask;
    uint32_t initialized;
    uint32_t protected_count;
    alix_thread_t exit_thread;
    volatile uint32_t exit_ready;
    volatile uint32_t exit_gate;
    volatile uint32_t exit_attempted;
};

/* Static/heap storage is intentional: Alix stacks belong to one thread only. */
static shared_t *g_shared;
static uint32_t main_tls_destroyed;
static uint32_t finalized_order;
static uint32_t exit_order;
static unsigned char dso_a, dso_b;
static unsigned values[] = { 1, 2, 3 };

static void fail_worker(shared_t *shared)
{
    __atomic_add_fetch(&shared->failures, 1u, __ATOMIC_RELAXED);
}

static bool wait_value(volatile uint32_t *value, uint32_t expected)
{
    uint64_t started = sys_monotonic_millis();
    while (__atomic_load_n(value, __ATOMIC_ACQUIRE) != expected)
    {
        if (sys_monotonic_millis() - started > 5000) return false;
        sys_yield();
    }
    return true;
}

static void initialize_once(void)
{
    __atomic_add_fetch(&g_shared->once_calls, 1u, __ATOMIC_RELAXED);
    /* All four CPUs attempt the same once object before initialization ends. */
    if (!wait_value(&g_shared->once_attempts, WORKERS)) fail_worker(g_shared);
    sys_sleep_ms(5);
    g_shared->initialized = 0x1234ABCD;
}

static void deleted_key_destructor(void *argument)
{
    worker_t *worker = argument;
    fail_worker(worker->shared);
}

static void repopulated_destructor(void *argument)
{
    worker_t *worker = argument;
    shared_t *shared = worker->shared;
    if (alix_thread_self() != worker->thread || worker->tls_order != 21 ||
        alix_tls_get(shared->repopulated_key) != NULL)
    {
        fail_worker(shared);
    }
    ++worker->repopulated;
    /* Refill even on pass four: cleanup must stop at its documented bound. */
    if (alix_tls_set(shared->repopulated_key, worker) != 0) fail_worker(shared);
}

static void reused_key_destructor(void *argument)
{
    worker_t *worker = argument;
    if (worker->tls_order != 21 || alix_tls_get(worker->shared->reused_key) != NULL)
        fail_worker(worker->shared);
    ++worker->reused;
}

static void tls_first(void *argument)
{
    worker_t *worker = argument;
    worker->tls_order = worker->tls_order * 10u + 1u;
}

static void tls_second(void *argument)
{
    worker_t *worker = argument;
    worker->tls_order = worker->tls_order * 10u + 2u;
}

static void worker_main(void *argument)
{
    worker_t *worker = argument;
    shared_t *shared = worker->shared;
    if (sys_thread_set_affinity(worker->index) != 0 || sys_thread_cpu() != worker->index)
        fail_worker(shared);
    else
        __atomic_fetch_or(&shared->cpu_mask, 1u << worker->index, __ATOMIC_RELAXED);

    /* Main holds this mutex until every worker has checked non-owner paths. */
    if (alix_recursive_mutex_trylock(&shared->recursive) ||
        alix_recursive_mutex_unlock(&shared->recursive) != -EPERM ||
        alix_tls_get(shared->old_key) != NULL ||
        alix_tls_set(shared->old_key, worker) != 0)
    {
        fail_worker(shared);
    }
    __atomic_add_fetch(&shared->ready, 1u, __ATOMIC_RELEASE);
    if (!wait_value(&shared->start, 1)) { fail_worker(shared); return; }
    if (alix_tls_get(shared->old_key) != NULL ||
        alix_tls_get(shared->reused_key) != NULL ||
        alix_tls_set(shared->old_key, worker) != -EINVAL ||
        alix_tls_key_delete(shared->old_key) != -EINVAL ||
        alix_tls_set(shared->reused_key, worker) != 0 ||
        alix_tls_set(shared->repopulated_key, worker) != 0 ||
        __cxa_thread_atexit_impl(tls_first, worker, NULL) != 0 ||
        __cxa_thread_atexit_impl(tls_second, worker, NULL) != 0)
    {
        fail_worker(shared);
    }

    __atomic_add_fetch(&shared->once_attempts, 1u, __ATOMIC_RELEASE);
    if (alix_call_once(&shared->once, initialize_once) != 0 ||
        shared->initialized != 0x1234ABCD)
    {
        fail_worker(shared);
    }
    for (unsigned i = 0; i < ROUNDS; ++i)
    {
        if (alix_recursive_mutex_lock(&shared->recursive) != 0 ||
            alix_recursive_mutex_lock(&shared->recursive) != 0 ||
            !alix_recursive_mutex_trylock(&shared->recursive))
        {
            fail_worker(shared);
            return;
        }
        uint32_t prior = shared->protected_count;
        if ((i & 7u) == 0) sys_yield();
        shared->protected_count = prior + 1u;
        for (unsigned depth = 0; depth < 3; ++depth)
            if (alix_recursive_mutex_unlock(&shared->recursive) != 0) fail_worker(shared);

        unsigned char *block = aligned_alloc(64, 128);
        if (!block || ((uintptr_t)block & 63u)) { fail_worker(shared); return; }
        memset(block, (int)(worker->index + 1), 128);
        sys_yield();
        for (unsigned j = 0; j < 128; ++j)
            if (block[j] != worker->index + 1) fail_worker(shared);
        free(block);
    }
}

static bool bytes_equal(const unsigned char *bytes, size_t size, unsigned char value)
{
    for (size_t i = 0; i < size; ++i) if (bytes[i] != value) return false;
    return true;
}

static bool allocation_tests(void)
{
    /* Empty arrays still need distinct, freeable ownership: upstream Wasm
     * metadata treats a NULL allocation as failure even for zero elements. */
    void **empty = malloc(5 * sizeof(*empty));
    if (!empty) return false;
    empty[0] = calloc(0, 0);
    empty[1] = calloc(0, sizeof(uint64_t));
    empty[2] = calloc(1, 0);
    empty[3] = calloc(MAX_SIZE, 0);
    empty[4] = calloc(0, MAX_SIZE);
    for (unsigned index = 0; index < 5; ++index)
    {
        if (!empty[index] || ((uintptr_t)empty[index] & 15u)) return false;
        for (unsigned prior = 0; prior < index; ++prior)
            if (empty[index] == empty[prior]) return false;
    }
    for (unsigned index = 0; index < 5; ++index) free(empty[index]);
    free(empty);
    unsigned char *preserved = malloc(96);
    if (!preserved) return false;
    memset(preserved, 0xA5, 96);
    /* A failed realloc must preserve both ownership and all previous bytes. */
    if (realloc(preserved, MAX_SIZE) != NULL || !bytes_equal(preserved, 96, 0xA5)) return false;
    void *prior_break = sys_sbrk(0);
    if (malloc(MAX_SIZE - 1024) != NULL || calloc(1, MAX_SIZE - 1024) != NULL ||
        aligned_alloc(16, MAX_SIZE - 1023) != NULL || sys_sbrk(0) != prior_break ||
        !bytes_equal(preserved, 96, 0xA5)) return false;
    free(preserved);
    if (malloc(MAX_SIZE) != NULL || calloc(MAX_SIZE, 2) != NULL) return false;
    errno = 0;
    if (aligned_alloc(24, 96) != NULL || errno != EINVAL) return false;
    errno = 0;
    if (aligned_alloc(64, 65) != NULL || errno != EINVAL) return false;
    if (aligned_alloc((MAX_SIZE >> 1) + 1, (MAX_SIZE >> 1) + 1) != NULL) return false;
    void *out = &dso_a;
    if (posix_memalign(&out, 3, 128) != EINVAL || out != &dso_a ||
        posix_memalign(&out, 64, MAX_SIZE) != ENOMEM || out != &dso_a) return false;
    if (posix_memalign(&out, 256, 257) != 0 || !out || ((uintptr_t)out & 255u)) return false;
    memset(out, 0xA6, 257);
    free(out);

    for (unsigned round = 0; round < 96; ++round)
    {
        size_t alignment = (size_t)16 << (round % 9);
        size_t size = alignment * (1u + round % 3);
        unsigned char *before = malloc(37 + round % 7);
        unsigned char *block = aligned_alloc(alignment, size);
        unsigned char *after = malloc(83);
        if (!before || !block || !after || ((uintptr_t)block & (alignment - 1))) return false;
        memset(before, 0xB1, 37 + round % 7);
        memset(block, 0x5C, size);
        memset(after, 0xD2, 83);
        size_t smaller = size / 2 + 1;
        unsigned char *resized = realloc(block, smaller);
        if (!resized || !bytes_equal(resized, smaller, 0x5C)) return false;
        block = realloc(resized, size + 93);
        if (!block || !bytes_equal(block, smaller, 0x5C) ||
            !bytes_equal(before, 37 + round % 7, 0xB1) || !bytes_equal(after, 83, 0xD2)) return false;
        /* Alternate freeing adjacent blocks to exercise both coalescing sides. */
        if (round & 1) { free(before); free(after); free(block); }
        else { free(block); free(before); free(after); }
    }
    return true;
}

typedef struct { unsigned char key, identity, check; } sort_item_t;

static int compare_items(const void *left, const void *right)
{
    const sort_item_t *a = left, *b = right;
    return (a->key > b->key) - (a->key < b->key);
}

static bool sorting_tests(void)
{
    sort_item_t *items = malloc(257 * sizeof(*items));
    unsigned char *seen = calloc(257, 1);
    if (!items || !seen) return false;
    /* Odd element widths and duplicate keys catch whole-element swap errors. */
    for (unsigned count = 0; count <= 256; ++count)
    {
        memset(seen, 0, 257);
        for (unsigned i = 0; i < count; ++i)
            items[i] = (sort_item_t){ (unsigned char)((i * 97 + count) % 17),
                                     (unsigned char)i, (unsigned char)(i ^ 0xA5) };
        qsort(items, count, sizeof(*items), compare_items);
        for (unsigned i = 0; i < count; ++i)
        {
            if ((i && items[i - 1].key > items[i].key) ||
                items[i].identity >= count || seen[items[i].identity] ||
                items[i].check != (unsigned char)(items[i].identity ^ 0xA5)) return false;
            seen[items[i].identity] = 1;
        }
        if (count)
        {
            sort_item_t *found = bsearch(&items[count / 2], items, count, sizeof(*items), compare_items);
            if (!found || found->key != items[count / 2].key) return false;
        }
    }
    free(seen);
    free(items);
    return true;
}

static bool integer_tests(void)
{
    char *end;
    const char *none = "  -+12";
    errno = EDOM;
    if (strtoll(none, &end, 10) != 0 || end != none || errno != EDOM) return false;
    if (strtoll(" -9223372036854775808!", &end, 10) != (-0x7FFFFFFFFFFFFFFFLL - 1) ||
        *end != '!' || errno != EDOM) return false;
    errno = 0;
    if (strtoll("9223372036854775808tail", &end, 10) != 0x7FFFFFFFFFFFFFFFLL ||
        *end != 't' || errno != ERANGE) return false;
    errno = 0;
    if (strtoll("-9223372036854775809tail", &end, 10) != (-0x7FFFFFFFFFFFFFFFLL - 1) ||
        *end != 't' || errno != ERANGE) return false;
    errno = 0;
    if (strtoull("18446744073709551615!", &end, 10) != (unsigned long long)-1 ||
        *end != '!' || errno != 0) return false;
    if (strtoull("-1!", &end, 10) != (unsigned long long)-1 || *end != '!' || errno != 0) return false;
    if (strtoull("184467440737095516160000end", &end, 10) != (unsigned long long)-1 ||
        *end != 'e' || errno != ERANGE) return false;
    errno = 0;
    if (strtoul("0xFf!", &end, 0) != 255 || *end != '!' ||
        strtol("077!", &end, 0) != 63 || *end != '!' ||
        strtol("08", &end, 0) != 0 || *end != '8' ||
        strtol("0x", &end, 16) != 0 || *end != 'x' ||
        strtol("zZ?", &end, 36) != 1295 || *end != '?' ||
        strtol("10102", &end, 2) != 10 || *end != '2' || errno != 0) return false;
    none = "123";
    if (strtol(none, &end, 1) != 0 || end != none || errno != EINVAL) return false;
    return true;
}

static void finalized(void *argument)
{
    unsigned value = *(unsigned *)argument;
    finalized_order = finalized_order * 10u + value;
    if (value == 3) __cxa_finalize(&dso_a);
}

static void main_tls_cleanup(void *unused)
{
    (void)unused;
    ++main_tls_destroyed;
}

static void exit_late(void) { exit_order = exit_order * 10u + 3u; }
static void exit_middle(void) { exit_order = exit_order * 10u + 1u; }
static void exit_cxa(void *unused) { (void)unused; exit_order = exit_order * 10u + 2u; }

static void exit_first(void)
{
    exit_order = exit_order * 10u + 4u;
    if (atexit(exit_late) != 0) fail_worker(g_shared);
    __atomic_store_n(&g_shared->exit_gate, 1u, __ATOMIC_RELEASE);
    if (!wait_value(&g_shared->exit_attempted, 1)) fail_worker(g_shared);
    /* The other CPU enters exit while this winning exit still has callbacks. */
    sys_sleep_ms(50);
}

static void exit_last(void)
{
    bool okay = main_tls_destroyed == 1 && exit_order == 4321 &&
                __atomic_load_n(&g_shared->exit_attempted, __ATOMIC_ACQUIRE) == 1 &&
                __atomic_load_n(&g_shared->failures, __ATOMIC_RELAXED) == 0;
    serial_printf("LIBC_SUPPORT_TEST: exit %s order=%u tls=%u concurrent=1\n",
                  okay ? "PASS" : "FAIL", exit_order, main_tls_destroyed);
}

static void concurrent_exit(void *argument)
{
    shared_t *shared = argument;
    if (sys_thread_set_affinity(1) != 0) fail_worker(shared);
    __atomic_store_n(&shared->exit_ready, 1u, __ATOMIC_RELEASE);
    if (!wait_value(&shared->exit_gate, 1)) { fail_worker(shared); return; }
    __atomic_store_n(&shared->exit_attempted, 1u, __ATOMIC_RELEASE);
    exit(99);
}

int main(void)
{
    if (!allocation_tests()) { serial_printf("LIBC_SUPPORT_TEST: FAIL allocation\n"); return 1; }
    if (!integer_tests()) { serial_printf("LIBC_SUPPORT_TEST: FAIL integer parsing\n"); return 1; }
    if (!sorting_tests()) { serial_printf("LIBC_SUPPORT_TEST: FAIL sorting\n"); return 1; }
    if (__cxa_atexit(finalized, &values[0], &dso_a) != 0 ||
        __cxa_atexit(finalized, &values[1], &dso_b) != 0 ||
        __cxa_atexit(finalized, &values[2], &dso_a) != 0)
    { serial_printf("LIBC_SUPPORT_TEST: FAIL finalize setup\n"); return 1; }
    __cxa_finalize(&dso_a);
    __cxa_finalize(&dso_a);
    if (finalized_order != 31) { serial_printf("LIBC_SUPPORT_TEST: FAIL filtered finalize\n"); return 1; }
    __cxa_finalize(&dso_b);
    if (finalized_order != 312) { serial_printf("LIBC_SUPPORT_TEST: FAIL finalize order\n"); return 1; }

    shared_t *shared = calloc(1, sizeof(*shared));
    if (!shared) { serial_printf("LIBC_SUPPORT_TEST: FAIL shared allocation\n"); return 1; }
    g_shared = shared;
    alix_recursive_mutex_init(&shared->recursive);
    if (alix_recursive_mutex_lock(&shared->recursive) != 0 ||
        alix_tls_key_create(&shared->repopulated_key, repopulated_destructor) != 0 ||
        alix_tls_key_create(&shared->old_key, deleted_key_destructor) != 0)
    { serial_printf("LIBC_SUPPORT_TEST: FAIL thread primitives\n"); return 1; }
    for (unsigned i = 0; i < WORKERS; ++i)
    {
        shared->workers[i].index = i;
        shared->workers[i].shared = shared;
        if (alix_thread_create(&shared->workers[i].thread, "libc_support", worker_main, &shared->workers[i]) != 0)
        { serial_printf("LIBC_SUPPORT_TEST: FAIL worker create\n"); return 1; }
    }
    if (!wait_value(&shared->ready, WORKERS) ||
        alix_tls_key_delete(shared->old_key) != 0 ||
        alix_tls_key_create(&shared->reused_key, reused_key_destructor) != 0 ||
        shared->reused_key == shared->old_key ||
        (uint32_t)shared->reused_key != (uint32_t)shared->old_key ||
        alix_recursive_mutex_unlock(&shared->recursive) != 0)
    { serial_printf("LIBC_SUPPORT_TEST: FAIL key reuse\n"); return 1; }
    __atomic_store_n(&shared->start, 1u, __ATOMIC_RELEASE);
    for (unsigned i = 0; i < WORKERS; ++i)
    {
        if (alix_thread_join(shared->workers[i].thread, NULL) != 0)
        { serial_printf("LIBC_SUPPORT_TEST: FAIL join\n"); return 1; }
        if (shared->workers[i].repopulated != 4 || shared->workers[i].reused != 1 ||
            shared->workers[i].tls_order != 21) fail_worker(shared);
    }
    if (shared->failures || shared->once_calls != 1 || shared->cpu_mask != 0xF ||
        shared->protected_count != WORKERS * ROUNDS ||
        alix_call_once(&shared->once, initialize_once) != 0 || shared->once_calls != 1 ||
        alix_tls_key_delete(shared->repopulated_key) != 0 ||
        alix_tls_key_delete(shared->reused_key) != 0)
    { serial_printf("LIBC_SUPPORT_TEST: FAIL cleanup or contention failures=%u count=%u\n", shared->failures, shared->protected_count); return 1; }

    if (alix_thread_create(&shared->exit_thread, "exit_contender", concurrent_exit, shared) != 0 ||
        alix_thread_detach(shared->exit_thread) != 0 || !wait_value(&shared->exit_ready, 1) ||
        __cxa_thread_atexit_impl(main_tls_cleanup, NULL, NULL) != 0 ||
        atexit(exit_last) != 0 || atexit(exit_middle) != 0 ||
        __cxa_atexit(exit_cxa, NULL, &dso_a) != 0 || atexit(exit_first) != 0)
    { serial_printf("LIBC_SUPPORT_TEST: FAIL exit setup\n"); return 1; }
    serial_printf("LIBC_SUPPORT_TEST: main PASS workers=4 cpu_mask=0xF once=1 tsd_passes=4 counter=%u\n",
                  shared->protected_count);
    /* Keep shared state alive until process termination cancels the exit loser. */
    return 0;
}
