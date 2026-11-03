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
    SYSCALL_RESOURCE_USAGE = 69,
    SYSCALL_DIRECTORY = 70,
    SYSCALL_FILE_IO = 71,
    SYSCALL_PROCESS = 72,
    SYSCALL_UI_CONTROL = 73,
    SYSCALL_MEMORY_PAGES = 74,
    SYSCALL_SIGWAIT = 75,
    SYSCALL_VM_FILE_MAP = 76,
    SYSCALL_VM_SYNC = 77,
    SYSCALL_NET_ROUTE = 78,
} syscall_id_t;

/* Physical RAM counts in 4096-byte pages. TOTAL is the boot E820 usable RAM
 * before kernel reservations; AVAILABLE is the current locked PMM free count.
 * No user pointer is retained or accessed. Unknown selectors return -EINVAL. */
#define SYSCALL_MEMORY_TOTAL_PAGES 0u
#define SYSCALL_MEMORY_AVAILABLE_PAGES 1u

#define SYSCALL_PROCESS_SPAWN 0u
#define SYSCALL_PROCESS_WAIT 1u
#define SYSCALL_PROCESS_NOHANG 1u
#define SYSCALL_PROCESS_SPAWN_EX 2u
#define SYSCALL_PROCESS_EXECUTABLE_PATH 3u
#define SYSCALL_PROCESS_GETGID 4u
#define SYSCALL_PROCESS_WAIT_INFO 5u
#define SYSCALL_PROCESS_UMASK 6u
#define SYSCALL_PROCESS_ALARM 7u
#define SYSCALL_PROCESS_ELF_INFO 8u
#define SYSCALL_ELF_INFO_VERSION 1u
#define SYSCALL_ELF_PHENT 56u
typedef struct
{
    uint32_t version, size, phent, phnum;
    uint64_t entry;
    uint32_t uid, gid;
    uint64_t reserved;
    /* phnum native ELF64 program headers follow this fixed prefix. */
} syscall_elf_info_t;
#define SYSCALL_PROCESS_WAIT_ALL 0u
#define SYSCALL_PROCESS_WAIT_PID 1u
#define SYSCALL_PROCESS_WAIT_PGID 2u
#define SYSCALL_PROCESS_WAIT_EXITED 4u
#define SYSCALL_PROCESS_WAIT_NOWAIT 0x01000000u
#define SYSCALL_EXECUTABLE_PATH_MAX 4096u
#define SYSCALL_SPAWN_VERSION 1u
#define SYSCALL_SPAWN_SETSIGMASK 1u
#define SYSCALL_SPAWN_SETSIGDEF 2u
#define SYSCALL_SPAWN_RESETIDS 4u
#define SYSCALL_SPAWN_CLOEXEC_DEFAULT 0x4000u
#define SYSCALL_SPAWN_SEARCH_PATH 0x10000u
#define SYSCALL_SPAWN_CLOSE 0u
#define SYSCALL_SPAWN_DUP2 1u
#define SYSCALL_SPAWN_OPEN 2u
#define SYSCALL_SPAWN_CHDIR 3u
typedef struct
{
    uint32_t operation;
    int32_t fd, destination;
    uint32_t flags;
    uint64_t path;
    uint32_t mode, reserved;
} syscall_spawn_action_t;
typedef struct
{
    uint32_t version, size;
    uint64_t path, argv, environment, actions;
    uint32_t action_count, flags;
    uint64_t signal_mask, signal_default, search_path;
} syscall_spawn_t;

/* Owned per-process namespace. Old IDs retain their legacy namespace for
 * installed binaries. This API never falls back to a matching global FD. */
typedef enum
{
    SYSCALL_FILE_OPEN, SYSCALL_FILE_READ, SYSCALL_FILE_WRITE, SYSCALL_FILE_CLOSE,
    SYSCALL_FILE_PREAD, SYSCALL_FILE_SEEK, SYSCALL_FILE_STAT,
    SYSCALL_FILE_GETFD, SYSCALL_FILE_SETFD, SYSCALL_FILE_DUP,
    SYSCALL_FILE_DUP2, SYSCALL_FILE_DUP3,
    SYSCALL_FILE_SOCKET_OPEN, SYSCALL_FILE_SOCKET_CONNECT, SYSCALL_FILE_SOCKET_AVAILABLE,
    SYSCALL_FILE_PIPE, SYSCALL_FILE_STAT_PATH, SYSCALL_FILE_CHDIR, SYSCALL_FILE_GETCWD,
    SYSCALL_FILE_REMOVE, SYSCALL_FILE_RENAME,
    SYSCALL_FILE_AUDIO_OPEN, SYSCALL_FILE_AUDIO_WRITE,
    SYSCALL_FILE_AUDIO_STATUS, SYSCALL_FILE_AUDIO_DRAIN,
    SYSCALL_FILE_POLL, SYSCALL_FILE_GETFL, SYSCALL_FILE_SETFL,
    SYSCALL_FILE_NET_OPEN, SYSCALL_FILE_NET_CONNECT, SYSCALL_FILE_NET_SEND, SYSCALL_FILE_NET_RECV,
    SYSCALL_FILE_NET_GETOPT, SYSCALL_FILE_NET_SETOPT, SYSCALL_FILE_NET_GETNAME,
    SYSCALL_FILE_DNS_RESOLVE, SYSCALL_FILE_SYNC, SYSCALL_FILE_SELECT,
    SYSCALL_FILE_TRUNCATE, SYSCALL_FILE_REALPATH, SYSCALL_FILE_MKDIR, SYSCALL_FILE_FLOCK,
    SYSCALL_FILE_IOCTL, SYSCALL_FILE_SYSTEM_INFO, SYSCALL_FILE_HOSTNAME,
    SYSCALL_FILE_GET_LIMIT, SYSCALL_FILE_SET_LIMIT, SYSCALL_FILE_WRITEV,
    SYSCALL_FILE_NET_SENDMSG, SYSCALL_FILE_NET_RECVMSG,
    SYSCALL_FILE_NET_BIND, SYSCALL_FILE_DATAGRAM,
    SYSCALL_FILE_STAT_INFO, SYSCALL_FILE_PATH_INFO, SYSCALL_FILE_CHOWN, SYSCALL_FILE_CHMOD,
    SYSCALL_FILE_RECORD_LOCK, SYSCALL_FILE_SET_TIMES,
    SYSCALL_FILE_SHM_OPEN, SYSCALL_FILE_SHM_UNLINK,
    SYSCALL_FILE_OPEN_MODE, SYSCALL_FILE_MKDIR_MODE, SYSCALL_FILE_CHMOD_PATH,
    SYSCALL_FILE_LOG, SYSCALL_FILE_SYMLINK, SYSCALL_FILE_ACCESS, SYSCALL_FILE_MKFIFO,
    SYSCALL_FILE_TRUNCATE_PATH, SYSCALL_FILE_STAT_TIMES, SYSCALL_FILE_PATH_TIMES
} syscall_file_operation_t;
#define SYSCALL_LOG_MAX_BYTES 4096u
#define SYSCALL_F_GETLK 5
#define SYSCALL_F_SETLK 6
#define SYSCALL_F_SETLKW 7
#define SYSCALL_F_RDLCK 0
#define SYSCALL_F_WRLCK 1
#define SYSCALL_F_UNLCK 2
typedef struct
{
    int64_t start, length;
    int32_t pid;
    int16_t type, whence;
} syscall_record_lock_t;
typedef struct { int64_t access_seconds, access_microseconds, modify_seconds, modify_microseconds; } syscall_file_times_t;
#define SYSCALL_IOV_MAX 1024u
typedef struct { uint64_t base, length; } syscall_iovec_t;
typedef struct
{
    uint64_t name;
    uint32_t name_length, reserved;
    uint64_t vectors, vector_count, control, control_length;
    int32_t flags;
    uint32_t padding;
} syscall_msghdr_t;
typedef struct
{
    uint64_t data, length, address, address_length, packet_info, address_length_pointer;
    uint32_t flags;
    int32_t tos;
    uint32_t source_ipv4, reserved;
} syscall_udp_request_t;
#define SYSCALL_RESOURCE_NOFILE 7u
#define SYSCALL_RESOURCE_AS 9u
#define SYSCALL_DUP_CHECK_MINIMUM 1u
typedef struct { uint64_t current, maximum; } syscall_rlimit_t;
#define SYSCALL_UTS_FIELD_LENGTH 65u
typedef struct {
    char sysname[SYSCALL_UTS_FIELD_LENGTH], nodename[SYSCALL_UTS_FIELD_LENGTH];
    char release[SYSCALL_UTS_FIELD_LENGTH], version[SYSCALL_UTS_FIELD_LENGTH];
    char machine[SYSCALL_UTS_FIELD_LENGTH];
} syscall_utsname_t;
#define SYSCALL_IOCTL_FIONREAD 0x541Bu
#define SYSCALL_IOCTL_FIONBIO 0x5421u
#define SYSCALL_IOCTL_FIONCLEX 0x5450u
#define SYSCALL_IOCTL_FIOCLEX 0x5451u
#define SYSCALL_FLOCK_SHARED 1u
#define SYSCALL_FLOCK_EXCLUSIVE 2u
#define SYSCALL_FLOCK_NONBLOCK 4u
#define SYSCALL_FLOCK_UNLOCK 8u
#define SYSCALL_REMOVE_ALLOW_DIRECTORY 1u
#define SYSCALL_REMOVE_DIRECTORY_ONLY 2u

#define SYSCALL_SELECT_VERSION 1u
#define SYSCALL_SELECT_FD_MAX 256u
typedef struct { uint64_t bits[SYSCALL_SELECT_FD_MAX / 64u]; } syscall_fd_set_t;
/* FILE_SELECT takes this query and its exact byte size. Timeout points to a
 * native pair of signed 64-bit seconds/microseconds; zero means indefinite.
 * Input sets/timeval are captured before queueing. Workers retain only owned
 * descriptions and readiness masks, never these user addresses. */
typedef struct
{
    uint32_t version, size;
    int32_t nfds;
    uint32_t flags;
    uint64_t readfds, writefds, exceptfds, timeout;
} syscall_select_t;
#define SYSCALL_DNS_VERSION 1u
#define SYSCALL_DNS_NAME_MAX 255u
#define SYSCALL_DNS_ADDR_MAX 8u
#define SYSCALL_DNS_OK 0u
#define SYSCALL_DNS_NOT_FOUND 1u
#define SYSCALL_DNS_AGAIN 2u
#define SYSCALL_DNS_FAILURE 3u
typedef struct
{
    uint32_t version, size, status, address_count;
    uint32_t addresses[SYSCALL_DNS_ADDR_MAX]; /* Native host-order IPv4 values. */
    uint32_t canonical_length, reserved;
    char canonical[SYSCALL_DNS_NAME_MAX + 1u];
} syscall_dns_reply_t;
#define SYSCALL_SOL_SOCKET 1u
#define SYSCALL_SO_REUSEADDR 2u
#define SYSCALL_SO_TYPE 3u
#define SYSCALL_SO_ERROR 4u
#define SYSCALL_SO_SNDBUF 7u
#define SYSCALL_SO_RCVBUF 8u
#define SYSCALL_SO_KEEPALIVE 9u
#define SYSCALL_SO_ACCEPTCONN 30u
#define SYSCALL_SO_PROTOCOL 38u
#define SYSCALL_SO_DOMAIN 39u
#define SYSCALL_TCP_NODELAY 1u
#define SYSCALL_TCP_MAXSEG 2u
#define SYSCALL_AF_INET 2u
#define SYSCALL_SOCK_STREAM 1u
#define SYSCALL_IPPROTO_TCP 6u
#define SYSCALL_MSG_PEEK 2u
#define SYSCALL_MSG_DONTWAIT 0x40u
#define SYSCALL_MSG_NOSIGNAL 0x4000u
typedef struct
{
    uint16_t family, port_be;
    uint32_t address_be;
    uint8_t reserved[8];
} syscall_sockaddr_in_t;
#define SYSCALL_FILE_CLOEXEC 1u
#define SYSCALL_OPEN_CLOEXEC (1u << 17)
#define SYSCALL_STAT_NOFOLLOW 1u

#define SYSCALL_POLL_IN 0x0001u
#define SYSCALL_POLL_PRI 0x0002u
#define SYSCALL_POLL_OUT 0x0004u
#define SYSCALL_POLL_ERR 0x0008u
#define SYSCALL_POLL_HUP 0x0010u
#define SYSCALL_POLL_NVAL 0x0020u
typedef struct
{
    int32_t fd;
    int16_t events, revents;
} syscall_pollfd_t;

#define SYSCALL_AUDIO_STATUS_VERSION 1u
#define SYSCALL_AUDIO_FAILED 1u
#define SYSCALL_AUDIO_RECOVERING 2u
typedef struct
{
    uint32_t version, size;
    uint32_t rate, channels, frame_bytes, flags;
    uint64_t submitted_frames, played_frames, dropped_frames;
    uint64_t queued_frames, latency_frames;
} syscall_audio_status_t;

#define SYSCALL_USAGE_VERSION 1u
#define SYSCALL_USAGE_SELF 0
#define SYSCALL_USAGE_CLOCK_PROCESS 0x100
#define SYSCALL_USAGE_CLOCK_THREAD 0x101
typedef struct { uint64_t ticks; uint32_t tick_frequency, reserved; } syscall_cpu_clock_t;
typedef struct
{
    uint32_t version, size;
    uint32_t tick_frequency, reserved;
    uint64_t user_ticks, system_ticks, minor_faults, major_faults;
} syscall_resource_usage_t;
#define SYSCALL_USAGE_VERSION_2 2u
typedef struct
{
    syscall_resource_usage_t usage;
    uint64_t resident_pages, peak_resident_pages;
} syscall_resource_usage_v2_t;

#define SYSCALL_DIRENT_VERSION 1u
#define SYSCALL_DIRENT_NAME_MAX 4095u
#define SYSCALL_DIRECTORY_OPEN 0u
#define SYSCALL_DIRECTORY_NEXT 1u
#define SYSCALL_DIRECTORY_CLOSE 2u
#define SYSCALL_DIRECTORY_REWIND 3u
typedef struct
{
    uint32_t version, size;
    uint64_t inode;
    uint32_t type, name_length;
    char name[SYSCALL_DIRENT_NAME_MAX + 1u];
} syscall_directory_entry_t;

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
#define SYSCALL_VM_MAP_SHARED 0x01u
#define SYSCALL_MS_ASYNC 1u
#define SYSCALL_MS_INVALIDATE 2u
#define SYSCALL_MS_SYNC 4u
#define SYSCALL_VM_MAP_FIXED 0x10u
#define SYSCALL_VM_MAP_ANONYMOUS 0x20u
#define SYSCALL_VM_MAP_NORESERVE 0x4000u
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
#define SYSCALL_OPEN_EXCLUSIVE (1u << 4)
#define SYSCALL_OPEN_APPEND (1u << 16)
#define SYSCALL_OPEN_NONBLOCK (1u << 18)
#define SYSCALL_OPEN_SYNC (1u << 19)
#define SYSCALL_OPEN_NOFOLLOW (1u << 20)
#define SYSCALL_ACCESS_NOFOLLOW 0x100u
#define SYSCALL_ACCESS_EFFECTIVE 0x200u

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

/* Versioned full metadata. The original syscall_stat_t and operation numbers
 * remain unchanged. This layout matches the new public struct stat exactly. */
typedef struct
{
    uint64_t size_bytes;
    uint32_t mode, type;
    uint64_t atime, mtime, ctime;
    uint64_t device, inode, links;
    uint32_t uid, gid;
    int64_t block_size, blocks;
} syscall_stat_info_t;
#define SYSCALL_STAT_TIME_FIELDS 2u
typedef struct { int64_t seconds, nanoseconds; } syscall_file_timestamp_t;
typedef struct
{
    syscall_stat_info_t info;
    syscall_file_timestamp_t accessed, modified, changed;
} syscall_stat_times_t;

typedef enum
{
    SYSCALL_NODE_TYPE_DIR = 0,
    SYSCALL_NODE_TYPE_FILE = 1,
    SYSCALL_NODE_TYPE_BLOCK = 2,
    SYSCALL_NODE_TYPE_SYMLINK = 3,
    SYSCALL_NODE_TYPE_SOCKET = 4,
    SYSCALL_NODE_TYPE_CHARACTER = 5,
    SYSCALL_NODE_TYPE_FIFO = 6
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
