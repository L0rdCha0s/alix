# Syscalls, FDs, and Sockets

This kernel exposes a small syscall surface for user programs. Syscalls are dispatched via vector 0x80.

## ABI / Entry (`src/arch/x86/syscall_entry.S`)

User code executes `int 0x80`. The IDT routes vector 0x80 to `syscall_entry`, which:

- Saves general-purpose registers onto the current stack.
- Calls `syscall_dispatch(syscall_frame_t *frame, uint64_t vector)` in C.
- Restores registers and returns with `iretq`.

## Dispatcher and IDs (`src/kernel/syscall.c`, `include/syscall_defs.h`)

`syscall_dispatch` reads:

- `RAX` = syscall number (`syscall_id_t`)
- Arguments from `RDI/RSI/RDX/R10/R8/...` depending on the syscall

Pointer safety:

- Most syscalls validate user pointers with `user_ptr_range_valid` and move data using `user_copy_*` helpers (`src/kernel/user_copy.c`).
- These helpers validate the address range against `g_mem_layout.user_pointer_base/limit` and canonicality, then use `memcpy`.

## File Descriptors (`src/kernel/fd.c`)

FDs are kernel-managed handles with an ops table:

- `fd_ops_t` contains `read/write/close/pread/lseek/fstat`.
- Each FD table entry stores `{ ops, context }`.
- Table size is currently fixed (`FD_MAX`).

This FD layer is shared by:

- VFS-backed files (`syscall.c` wraps a `vfs_node_t` + offset in a `file_handle_t`)
- TCP sockets (`src/net/tcp.c` registers a socket with FD ops)
- Shell service sessions (`src/kernel/shell_service.c` exposes a write-only FD capturing output)

## File Syscalls (VFS-backed)

Important behavior:

- `SYSCALL_OPEN` allocates a `file_handle_t`, retains the `vfs_node_t`, then installs an FD using `fd_allocate`.
- `SYSCALL_READ/WRITE` advance `file_handle_t.offset` after successful operations.
- `SYSCALL_PREAD` reads at an explicit offset without updating the shared offset.
- `SYSCALL_LSEEK` mutates the `file_handle_t.offset` according to `SEEK_SET/CUR/END`.
- `SYSCALL_LIST_DIR` enumerates children via VFS callbacks and returns `syscall_dirent_t[]`.

## Sockets (TCP)

Socket syscalls are TCP-only today:

- `SYSCALL_SOCKET_OPEN(iface_name?)`:
  - Chooses a NIC (optional name; otherwise “first present, prefer link_up”).
  - Calls `net_tcp_socket_open(iface)` and returns the socket’s FD.
- `SYSCALL_SOCKET_CONNECT(fd, ipv4_text, port)`:
  - Validates and parses IPv4 text.
  - Calls `net_tcp_socket_connect(...)` and waits for ESTABLISHED (poll/sleep loop).
- `SYSCALL_SOCKET_AVAILABLE(fd)`:
  - Returns readable byte count in the RX buffer.

Read/write/close on the returned FD are handled by `src/net/tcp.c`’s `fd_ops_t`.

## Other Syscalls

The syscall surface also includes:

- Process and CPU snapshots (`SYSCALL_PROC_SNAPSHOT`, `SYSCALL_CPU_SNAPSHOT`)
- Network interface snapshots (`SYSCALL_NET_SNAPSHOT`)
- Time queries (`SYSCALL_TIME_MILLIS`, `SYSCALL_TIME_INFO`)
- Shell service session control (`SYSCALL_SHELL_*`)
- UI syscalls for remote ATK windows (`SYSCALL_UI_*`)
- User thread lifecycle (`SYSCALL_THREAD_*`)

