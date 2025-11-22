# Agent Notes

- To run the OS in QEMU, use `bash -lc cd /Users/alex/Documents/Projects/alix && (make run-hdd > qemu-serial.log 2>&1 &) ; pid=$!; sleep 60; killall qemu-system-x86_64 || true; kill $pid || true`.
- Standard build remains `make` (produces `os.img` and `hdd.img`).
- We have our own libc implementation (src/kernel/libc.c), and memory/heap management (malloc, calloc, realloc, free) in src/kernel/heap.c.  Use heap operations rather than trying to use stack unless absolutely necessary.
- Remember that we're writing code for an SMP kernel, so considering stack usage and CPUs interacting with stacks is important.  Deeply understand process.c, paging.c and heap.c and smp.c
- Regarding SMP, pay particular attention to any scenario where we share something from a process stack with another thread - this will never work, and corrupt the stacks and crash the kernel
- If you need to modify memory layout, make sure you keep uefi.ld (kernel) and link.ld (user apps) up-to-date
- If you want to boot the kernel, the shell has a variety of commands (including shutdown) - which you can use to stop the kernel and return to your thinking
- Always run "make" to check your work before handing back to the user
- Use x86_64-elf-addr2line and x86_64-elf-objdump in order to look for lines in stacktraces in compiled code and analyse ELF binaries, like build/alix.elf (which is the main kernel binary)
- Use tcpdump to analyse qemu-net.pcap when looking at network traffic.
- We are still building our libc - if there's a function that should be either in the kernel or the user libc, add it in, rather than putting a function that should be in libc in a seperate place

Thanks!

