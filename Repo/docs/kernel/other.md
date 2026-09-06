# Other Kernel Subsystems (Grab Bag)

This file covers important kernel subsystems not captured in the main boot/process/memory/vfs/syscall/network docs.

## Console and Serial

- `src/kernel/console.c`: VGA text console with optional framebuffer-backed rendering.
- `src/drivers/serial.c`: `serial_printf` adds a log prefix and *auto-appends* CRLF unless the format ends with `\\n`.

## Hardware Discovery

- `src/kernel/acpi.c`: ACPI table discovery; also supports extracting power-management registers (used by shutdown).
- `src/kernel/hwinfo.c`: lightweight CPU/memory summary used at boot and by procfs endpoints.
- `src/drivers/pci.c`: PCI enumeration (consumed by NIC/storage drivers and `/proc/devices/pci`).

## Timekeeping

- `src/drivers/timer.c`: tick source (`timer_ticks()` and `timer_frequency()`).
- `src/kernel/timekeeping.c`: wall clock built on ticks + timezone config under `/etc/timezone/current`.
- `src/kernel/tzdb.c`: timezone database support used by `timekeeping`.

## Logging to Files

- `src/kernel/logger.c`: appends logs under `/var/log` using VFS files (depends on VFS being initialised/mounted).

## Shell Integration

- `src/kernel/shell_service.c`: background shell sessions exposed through syscalls (`SYSCALL_SHELL_*`), used by userland apps.
- `src/kernel/startup.c`: optional startup script runner that uses the shell to execute `/etc/startup.rc`.

## UI Hosting (ATK)

- `src/kernel/user_atk.c`: implements remote “user ATK windows” that user programs present into via `SYSCALL_UI_*`.

## Audio

- `src/kernel/audio.c` and `src/drivers/hda.c`: audio device initialisation and control surfaces; HDA init may be deferred to a kernel thread.
- See [Audio streaming and playback diagnostics](audio.md) for the PCM contract, ATK MP3 worker, queue ownership, runtime counters and QEMU capture workflow.

## Fonts

- `src/kernel/font.c`, `src/kernel/ttf.c`, `src/kernel/font_cache.c`: font loading/raster and caching (used by console/UI).
