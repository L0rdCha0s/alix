# Agent Notes

- To run the OS in QEMU, use `make run-hdd`.
  - Prefer this over `make run`; the HDD target is the intended path for interactive runs.
- If you run `make run-hdd`, you won't be able to continue, because the process won't finish.  If you want to run it then kill it to get serial output, run `killall qemu-system-x86_64`
- Standard build remains `make` (produces `os.img` and `hdd.img`).
- We have our own libc implementation (src/kernel/libc.c), and memory/heap management (malloc, calloc, realloc, free) in src/kernel/heap.c.  Use heap operations rather than trying to use fixed memory assigned in stage2.asm unless absolutely necessary.
- If you need to modify memory layout, make sure you keep STAGE2_BASE and STACK_TOP up-to-date to avoid smashing memory through overlaps in stage2.asm

Thanks!

