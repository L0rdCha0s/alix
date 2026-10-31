#ifndef SYSCALL_DEFS_H
#define SYSCALL_DEFS_H

#include "types.h"
#include "timekeeping.h"

typedef enum
{
    SYSCALL_EXIT = 0,
    SYSCALL_WRITE = 1,
    SYSCALL_READ = 2,
    SYSCALL_OPEN = 3,
    SYSCALL_CLOSE = 4,
    SYSCALL_SBRK = 5,
    SYSCALL_UI_CREATE = 6,
    SYSCALL_UI_PRESENT = 7,
    SYSCALL_UI_POLL_EVENT = 8,
    SYSCALL_UI_CLOSE = 9,
    SYSCALL_YIELD = 10,
    SYSCALL_SERIAL_WRITE = 11,
    SYSCALL_SHELL_OPEN = 12,
    SYSCALL_SHELL_EXEC = 13,
    SYSCALL_SHELL_CLOSE = 14,
    SYSCALL_SHELL_POLL = 15,
    SYSCALL_SHELL_INTERRUPT = 16,
    SYSCALL_PROC_SNAPSHOT = 17,
    SYSCALL_NET_SNAPSHOT = 18,
    SYSCALL_TIME_MILLIS = 19,
    SYSCALL_FONT_CACHE = 20,
    SYSCALL_LSEEK = 21,
    SYSCALL_FSTAT = 22,
    SYSCALL_PREAD = 23,
    SYSCALL_CPU_SNAPSHOT = 24,
    SYSCALL_TIME_INFO = 25,
    SYSCALL_SOCKET_OPEN = 26,
    SYSCALL_SOCKET_CONNECT = 27,
    SYSCALL_LIST_DIR = 28,
    SYSCALL_SHELL_CWD = 29,
    SYSCALL_SOCKET_AVAILABLE = 30,
    SYSCALL_THREAD_CREATE = 31,
    SYSCALL_THREAD_JOIN = 32,
    SYSCALL_THREAD_EXIT = 33,
    SYSCALL_THREAD_SELF = 34,
    SYSCALL_UI_CAPTURE = 35,
    SYSCALL_SLEEP_MS = 36,
    SYSCALL_UI_POLL_EVENT_TIMEOUT = 37,
    SYSCALL_SHELL_PROMPT = 38,
    SYSCALL_GETUID = 39,
    SYSCALL_MKDIR = 40,
    SYSCALL_THREAD_SET_TLS = 41,
    SYSCALL_THREAD_GET_TLS = 42,
    SYSCALL_FUTEX_WAIT = 43,
    SYSCALL_FUTEX_WAKE = 44,
    SYSCALL_MONOTONIC_MILLIS = 45,
    SYSCALL_THREAD_SET_AFFINITY = 46,
    SYSCALL_THREAD_CPU = 47,
    SYSCALL_VM_MAP = 48,
    SYSCALL_VM_PROTECT = 49,
    SYSCALL_VM_UNMAP = 50,
    SYSCALL_THREAD_DETACH = 51,
    SYSCALL_GETRANDOM = 52,
    SYSCALL_THREAD_INFO = 53,
    SYSCALL_THREAD_SET_NAME = 54,
    SYSCALL_THREAD_PREPARE_EXIT = 55,
    SYSCALL_VM_ADVISE = 56,
    SYSCALL_GETPID = 57,
    SYSCALL_TIMEZONE_INFO = 58,
    SYSCALL_SIGACTION = 59,
    SYSCALL_SIGPROCMASK = 60,
    SYSCALL_SIGALTSTACK = 61,
    SYSCALL_SIGRETURN = 62,
    SYSCALL_RAISE = 63,
    SYSCALL_KILL = 64,
    SYSCALL_SLEEP_INTERRUPTIBLE = 65,
    SYSCALL_READLINK = 66,
    SYSCALL_SIGNAL_JUMP = 67,
    SYSCALL_PROCESS_UPTIME_NS = 68,
} syscall_id_t;

#define SYSCALL_TIMEZONE_VERSION 1u
#define SYSCALL_TIMEZONE_FIXED 0u
#define SYSCALL_TIMEZONE_RULE 1u
#define SYSCALL_TIMEZONE_IANA 2u
#define SYSCALL_TIMEZONE_CLOCK_WALL 0

typedef struct syscall_timezone_rule
{
    int32_t month, week, weekday, time_seconds, clock_basis;
} syscall_timezone_rule_t;

typedef struct syscall_timezone_info
{
    uint32_t version, size;
    uint64_t generation;
    uint32_t kind, flags;
    /* Offsets are seconds EAST of UTC, unlike POSIX's timezone variable. */
    int32_t standard_offset_seconds, dst_offset_seconds;
    syscall_timezone_rule_t start, end;
    char zone_id[128];
    char display_name[128];
} syscall_timezone_info_t;

#define SYSCALL_VM_PROT_NONE 0u
#define SYSCALL_VM_PROT_READ 1u
#define SYSCALL_VM_PROT_WRITE 2u
#define SYSCALL_VM_PROT_EXEC 4u
#define SYSCALL_VM_MAP_PRIVATE 0x02u
#define SYSCALL_VM_MAP_FIXED 0x10u
#define SYSCALL_VM_MAP_ANONYMOUS 0x20u
#define SYSCALL_VM_MAP_FIXED_NOREPLACE 0x100000u
#define SYSCALL_VM_ADVICE_DONTNEED 4u
#define SYSCALL_VM_ADVICE_POSIX 0x100u

#define SYSCALL_FUTEX_INTERRUPTED (-4)
#define SYSCALL_FUTEX_WAIT_FOREVER ((uint32_t)-1)
#define SYSCALL_FUTEX_OK 0
#define SYSCALL_FUTEX_AGAIN (-11)
#define SYSCALL_FUTEX_FAULT (-14)
#define SYSCALL_FUTEX_INVALID (-22)
#define SYSCALL_FUTEX_TIMED_OUT (-110)

#define SYSCALL_OPEN_READ     (1u << 0)
#define SYSCALL_OPEN_WRITE    (1u << 1)
#define SYSCALL_OPEN_CREATE   (1u << 2)
#define SYSCALL_OPEN_TRUNCATE (1u << 3)

#define SYSCALL_SEEK_SET 0
#define SYSCALL_SEEK_CUR 1
#define SYSCALL_SEEK_END 2

#define SYSCALL_PROCESS_NAME_MAX 32
#define SYSCALL_THREAD_INFO_MAIN 1u
#define SYSCALL_THREAD_INFO_DETACHED 2u

typedef struct syscall_thread_info
{
    uint64_t tid;
    uint64_t stack_base;
    uint64_t stack_size;
    uint64_t guard_size;
    uint32_t flags;
    uint32_t state;
    uint32_t cpu_index;
    uint32_t reserved;
    char name[SYSCALL_PROCESS_NAME_MAX];
} syscall_thread_info_t;
#define SYSCALL_NET_IF_NAME_MAX 8
#define SYSCALL_CPU_MAX 32
#define SYSCALL_DIR_NAME_MAX 64

typedef enum
{
    SYSCALL_PROCESS_STATE_READY = 0,
    SYSCALL_PROCESS_STATE_RUNNING = 1,
    SYSCALL_PROCESS_STATE_ZOMBIE = 2,
} syscall_process_state_t;

typedef enum
{
    SYSCALL_THREAD_STATE_READY = 0,
    SYSCALL_THREAD_STATE_RUNNING = 1,
    SYSCALL_THREAD_STATE_BLOCKED = 2,
    SYSCALL_THREAD_STATE_ZOMBIE = 3,
} syscall_thread_state_t;

typedef struct
{
    uint64_t pid;
    uint32_t process_state; /* syscall_process_state_t */
    uint32_t thread_state;  /* syscall_thread_state_t */
    uint32_t time_slice_remaining;
    int32_t stdout_fd;
    uint8_t is_idle;
    char process_name[SYSCALL_PROCESS_NAME_MAX];
    char thread_name[SYSCALL_PROCESS_NAME_MAX];
    uint64_t heap_used_bytes;
    uint64_t heap_committed_bytes;
    uint64_t runtime_ticks;
    uint32_t last_cpu_index;
} syscall_process_info_t;

typedef struct
{
    char name[SYSCALL_NET_IF_NAME_MAX];
    uint8_t present;
    uint8_t link_up;
    uint8_t mac[6];
    uint32_t ipv4_addr;
    uint32_t ipv4_netmask;
    uint32_t ipv4_gateway;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_errors;
    uint64_t tx_errors;
} syscall_net_stats_t;

typedef struct
{
    uint32_t cpu_index;
    uint32_t online;
    uint32_t run_queue_depth;
    uint32_t current_thread_state; /* thread_state_t */
    uint64_t total_ticks;
    uint64_t idle_ticks;
    uint64_t switch_count;
    uint64_t current_pid;
    char current_process_name[SYSCALL_PROCESS_NAME_MAX];
    char current_thread_name[SYSCALL_PROCESS_NAME_MAX];
} syscall_cpu_stats_t;

typedef struct
{
    uint64_t size_bytes;
    uint32_t type; /* vfs_node_type_t */
    uint32_t reserved;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
} syscall_stat_t;

typedef enum
{
    SYSCALL_NODE_TYPE_DIR = 0,
    SYSCALL_NODE_TYPE_FILE = 1,
    SYSCALL_NODE_TYPE_BLOCK = 2,
    SYSCALL_NODE_TYPE_SYMLINK = 3
} syscall_node_type_t;

typedef struct
{
    uint32_t type; /* syscall_node_type_t */
    uint32_t reserved;
    uint64_t size_bytes;
    char name[SYSCALL_DIR_NAME_MAX];
} syscall_dirent_t;

typedef struct
{
    int32_t offset_minutes;
    char timezone_name[TIMEKEEPING_TZ_NAME_MAX];
} syscall_time_info_t;

#endif
