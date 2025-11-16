#ifndef SYSCALL_DEFS_H
#define SYSCALL_DEFS_H

#include "types.h"

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
} syscall_id_t;

#define SYSCALL_OPEN_READ     (1u << 0)
#define SYSCALL_OPEN_WRITE    (1u << 1)
#define SYSCALL_OPEN_CREATE   (1u << 2)
#define SYSCALL_OPEN_TRUNCATE (1u << 3)

#define SYSCALL_PROCESS_NAME_MAX 32
#define SYSCALL_NET_IF_NAME_MAX 8

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

#endif
