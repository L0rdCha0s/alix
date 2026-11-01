#include "process_internal.h"
#include "io_vfs_service.h"
#include "heap.h"
#include "libc.h"
#include "errno.h"

/* These probes exist only in an IO_VFS_SELFTEST image. They hold the real VFS
 * tree lock and observe real protected handler entry; no backend is replaced. */
extern void vfs_selftest_lock_tree(void);
extern void vfs_selftest_unlock_tree(void);
extern uint32_t io_vfs_selftest_active_handlers(void);

typedef struct
{
    bool start, entered, returned;
    ssize_t result;
    char output[128];
} vfs_boot_caller_t;

typedef struct
{
    vfs_boot_caller_t caller;
    process_t *caller_process;
    fd_description_t *saved_cwd;
    io_service_status_t service_status;
    char *output, *long_target;
    bool tree_locked;
    const char *failure;
} vfs_boot_state_t;

static uint64_t vfs_boot_deadline(void)
{
    uint32_t frequency = timer_frequency();
    return timer_ticks() + (uint64_t)(frequency ? frequency : 1000u) * 5u;
}

static bool vfs_boot_caller_blocked(process_t *process)
{
    uint64_t flags = scheduler_lock_acquire("vfs_boot_probe");
    spinlock_lock(&process->threads_lock);
    thread_t *thread = process->main_thread;
    bool blocked = thread && thread->state == THREAD_STATE_BLOCKED && thread->waiting_queue &&
                   !thread->in_transition && !thread_in_run_queue_load(thread) &&
                   __atomic_load_n(&thread->running_cpu, __ATOMIC_ACQUIRE) == RUN_QUEUE_CPU_INVALID;
    spinlock_unlock(&process->threads_lock);
    scheduler_lock_release(flags);
    return blocked;
}

static void vfs_boot_caller_entry(void *argument)
{
    vfs_boot_caller_t *caller = argument;
    while (!__atomic_load_n(&caller->start, __ATOMIC_ACQUIRE)) process_sleep_ms(1);
    __atomic_store_n(&caller->entered, true, __ATOMIC_RELEASE);
    caller->result = io_vfs_readlink_kernel("/tmp/vfs-owned-test/link", caller->output, sizeof(caller->output));
    __atomic_store_n(&caller->returned, true, __ATOMIC_RELEASE);
}

static bool vfs_boot_link(vfs_boot_state_t *state, const char *path, const char *target)
{
    ssize_t count = vfs_readlink_snapshot(vfs_root(), path, state->output, VFS_PATH_MAX, VFS_UID_ROOT, VFS_GID_ROOT);
    if (count >= 0)
        return (size_t)count == strlen(target) && memcmp(state->output, target, (size_t)count) == 0;
    if (count != -ENOENT) return false; /* Preserve any unrelated existing node. */
    return vfs_symlink(vfs_root(), target, path) != NULL;
}

bool vfs_io_boot_test(void)
{
    vfs_boot_state_t *state = calloc(1, sizeof(*state));
    if (!state) { serial_printf("VFS_IO_TEST: FAIL controller allocation"); return false; }
    state->output = malloc(VFS_PATH_MAX + 1u);
    state->long_target = malloc(VFS_PATH_MAX + 1u);
    if (!state->output || !state->long_target)
    {
        free(state->output); free(state->long_target); free(state);
        serial_printf("VFS_IO_TEST: FAIL buffer allocation");
        return false;
    }
#define REQUIRE(test, label) do { if (!(test)) { state->failure = (label); goto failed; } } while (0)
    serial_printf("VFS_IO_TEST: start real protected VFS");
    REQUIRE(vfs_mkdir(vfs_root(), "/tmp") != NULL, "fixture temporary directory");
    REQUIRE(vfs_mkdir(vfs_root(), "/tmp/vfs-owned-test") != NULL, "fixture parent directory");
    REQUIRE(vfs_mkdir(vfs_root(), "/tmp/vfs-owned-test/dir") != NULL, "fixture directory");
    REQUIRE(vfs_boot_link(state, "/tmp/vfs-owned-test/link", "../zones/Area/City"), "fixture link");
    REQUIRE(vfs_boot_link(state, "/tmp/vfs-owned-test/alias", "dir"), "fixture alias");
    REQUIRE(vfs_boot_link(state, "/tmp/vfs-owned-test/loop", "loop"), "fixture loop");
    REQUIRE(vfs_boot_link(state, "/tmp/vfs-owned-test/dir/leaf", "../../zones/Area/City"), "fixture leaf");
    memset(state->output, 0x5a, VFS_PATH_MAX + 1u);
    REQUIRE(io_vfs_readlink_kernel("/tmp/vfs-owned-test/link", state->output, VFS_PATH_MAX) == 18 &&
            memcmp(state->output, "../zones/Area/City", 18) == 0 && state->output[18] == 0x5a, "raw snapshot");
    REQUIRE(io_vfs_readlink_kernel("/tmp/vfs-owned-test/alias/leaf", state->output, 4) == 4 &&
            memcmp(state->output, "../.", 4) == 0, "intermediate link");

    /* The target limit is enforced before mutation, including force-replace. */
    memset(state->long_target, 'x', VFS_PATH_MAX - 1u);
    state->long_target[VFS_PATH_MAX - 1u] = 0;
    REQUIRE(vfs_boot_link(state, "/tmp/vfs-owned-test/long", state->long_target), "4095 target accepted");
    memset(state->output, 0x5a, VFS_PATH_MAX + 1u);
    REQUIRE(io_vfs_readlink_kernel("/tmp/vfs-owned-test/long", state->output, VFS_PATH_MAX + 1u) == VFS_PATH_MAX - 1u &&
            state->output[VFS_PATH_MAX - 1u] == 0x5a, "large output full target");
    state->long_target[VFS_PATH_MAX - 1u] = 'x'; state->long_target[VFS_PATH_MAX] = 0;
    REQUIRE(!vfs_force_symlink(vfs_root(), state->long_target, "/tmp/vfs-owned-test/long"), "4096 replacement rejected");
    REQUIRE(io_vfs_readlink_kernel("/tmp/vfs-owned-test/long", state->output, VFS_PATH_MAX) == VFS_PATH_MAX - 1u,
            "failed replacement preserved target");

    spinlock_preempt_disable();
    state->saved_cwd = process_acquire_cwd_owner(process_current(), NULL, NULL);
    spinlock_preempt_enable();
    REQUIRE(state->saved_cwd != NULL, "save cwd owner");
    REQUIRE(io_vfs_change_cwd_kernel("/tmp/vfs-owned-test/dir", 0) == 0, "owned cwd apply");
    REQUIRE(io_vfs_readlink_kernel("leaf", state->output, VFS_PATH_MAX) == 21 &&
            memcmp(state->output, "../../zones/Area/City", 21) == 0, "relative owned cwd");
    spinlock_preempt_disable();
    int restored = process_set_cwd_description_owned(process_current(), state->saved_cwd);
    if (!restored) state->saved_cwd = NULL;
    spinlock_preempt_enable();
    REQUIRE(restored == 0, "restore cwd");

    memset(state->caller.output, 0x5a, sizeof(state->caller.output));
    state->caller_process = process_create_kernel("vfs-test-caller", vfs_boot_caller_entry, &state->caller, 0, -1);
    REQUIRE(state->caller_process != NULL, "create cancellable caller");
    /* Process creation registers procfs nodes, so acquire this real lock only
     * after the caller exists and is waiting on its heap-owned start gate. */
    vfs_selftest_lock_tree(); state->tree_locked = true;
    __atomic_store_n(&state->caller.start, true, __ATOMIC_RELEASE);
    uint64_t deadline = vfs_boot_deadline();
    while (!io_vfs_selftest_active_handlers() || !vfs_boot_caller_blocked(state->caller_process))
    {
        REQUIRE(timer_ticks() < deadline, "real VFS blocked-worker deadline");
        process_sleep_ms(1);
    }
    REQUIRE(!__atomic_load_n(&state->caller.returned, __ATOMIC_ACQUIRE), "caller blocked before kill");
    REQUIRE(process_kill(state->caller_process, 73), "kill blocked caller");
    REQUIRE(process_join(state->caller_process, NULL) == 73, "join killed caller");
    REQUIRE(!__atomic_load_n(&state->caller.returned, __ATOMIC_ACQUIRE), "killed caller did not resume");
    vfs_selftest_unlock_tree(); state->tree_locked = false;
    /* Destruction unregisters procfs and must happen after releasing tree. */
    process_destroy(state->caller_process); state->caller_process = NULL;
    deadline = vfs_boot_deadline();
    for (;;)
    {
        REQUIRE(io_vfs_service_snapshot(&state->service_status) == 0, "service snapshot");
        if (!state->service_status.queue.live && !io_vfs_selftest_active_handlers()) break;
        REQUIRE(timer_ticks() < deadline, "cancelled request cleanup deadline");
        process_sleep_ms(1);
    }
    REQUIRE(state->caller.output[0] == 0x5a, "worker did not write abandoned caller output");
    REQUIRE(io_vfs_readlink_kernel("/tmp/vfs-owned-test/link", state->output, VFS_PATH_MAX) == 18,
            "fresh call after cancellation");
    free(state->output); free(state->long_target); free(state);
    serial_printf("VFS_IO_TEST: PASS real_symlinks=1 cwd=1 target_limit=4095 killed_blocked_caller=1 fresh_call=1");
    return true;
failed:
    if (state->tree_locked) { vfs_selftest_unlock_tree(); state->tree_locked = false; }
    serial_printf("VFS_IO_TEST: FAIL %s", state->failure ? state->failure : "unknown");
    /* Failure halts in the boot hook. Keep heap state for diagnostics and any
     * still-running caller; do not free another thread's callback argument. */
    return false;
#undef REQUIRE
}
