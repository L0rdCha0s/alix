# Agent Notes

- To run the OS in QEMU, use `bash -lc cd /Users/alex/Documents/Projects/alix && (make run-hdd > qemu-serial.log 2>&1 &) ; pid=$!; sleep 60; killall qemu-system-x86_64 || true; kill $pid || true`.
- Standard build remains `make` (produces `os.img` and `hdd.img`).
- We have our own libc implementation (src/kernel/libc.c), and memory/heap management (malloc, calloc, realloc, free) in src/kernel/heap.c.  Use heap operations rather than trying to use stack unless absolutely necessary.
- Remember that we're writing code for an SMP kernel, so considering stack usage and CPUs interacting with stacks is important.  Deeply understand process.c, paging.c and heap.c and smp.c
- If you need to modify memory layout, make sure you keep STAGE2_BASE and STACK_TOP up-to-date to avoid smashing memory through overlaps in stage2.asm
- If you want to boot the kernel, the shell has a variety of commands (including shutdown) - which you can use to stop the kernel and return to your thinking
- Always run "make" to check your work before handing back to the user
- Use x86_64-elf-addr2line and x86_64-elf-objdump in order to look for lines in stacktraces in compiled code and analyse ELF binaries.
- Use tcpdump to analyse qemu-net.pcap when looking at network traffic.

Thanks!

