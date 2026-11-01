# Terminal queries

The upstream runtime supplies native `termios.h` types/constants and libc
`isatty`, terminal-control and speed accessors. Its current descriptors are EOF
input, console/capture output, regular files, directories, pipes and sockets;
none has a TTY line discipline. Character-device metadata alone does not make a
stream a terminal.

Terminal operations validate the process-private FD slot. A valid non-TTY
returns `-1` with `ENOTTY`; a missing/closed slot reports `EBADF`. `isatty`
returns zero and preserves that distinction through errno. Queries leave the
caller's attribute buffer unchanged on failure. Unsupported actions and baud
codes report `EINVAL`, while local speed setters/getters operate on the supplied
native structure. These error meanings follow the
[terminal-mode contract](https://sourceware.org/glibc/manual/2.43/html_node/Mode-Functions.html).

`make zen-terminal-qemu-test` passes inside an eight-CPU Alix guest: stdio/file
classification, live aliases versus closed slots, invalid actions, preserved
attributes and input/output speed operations. Evidence is in
`build/test-out/terminal-qemu.log`.

This enables a hosted application to select its noninteractive stream path.
Interactive TTY input, canonical editing, terminal signals and process-group
job control still require a real terminal backend.
