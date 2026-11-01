# Physical x86-64 hardware and boot validation

Alix uses 64-bit UEFI. The kernel and drivers run natively; passing the QEMU
acceptance tests is not evidence of a successful physical-machine boot.

## Disk safety

Boot still attempts the existing `/dev/ahci1` to `/root` mount. If that mount
fails, it logs the failure and leaves the disk unchanged. It creates the
fallback system layout in RAM. There is no format-on-mount-failure path.

USB disks are registered as `/dev/usb0`, `/dev/usb1`, etc. They are not mounted
or formatted automatically. `mkfs <device>` remains an explicit, destructive
shell command; `mount <device> <directory>` mounts an existing AlixFS volume.
These names currently identify whole devices, not GPT/MBR partitions. FAT on
the UEFI boot volume is read by firmware to load the kernel; the kernel does
not gain a FAT filesystem implementation through the USB block driver.

## USB host controllers

`src/drivers/xhci.c` discovers PCI xHCI controllers across all 256 buses and
uses mapped MMIO, firmware ownership handoff, controller reset, scratchpads,
32/64-byte contexts, command/transfer rings and a polled event ring. Its DMA
allocations are aligned, below 4 GiB, and owned for the controller's lifetime.
This also supports controllers without 64-bit DMA addressing. Data buffers do
not cross a 64 KiB boundary. Callers' stack/user pointers are never programmed
into this controller.

Boot enumeration supports standard low/full/high/SuperSpeed IDs, root ports,
and USB hubs with route strings and transaction-translator context. Hub depth
is limited to the representable five tiers. Boot-protocol HID keyboards and
mice use the existing input layer. A pending interrupt IN TD retains its own
DMA buffer between nonblocking polls. The input threads sleep between polls,
so a single-CPU machine can wake other sleeping threads.

Bulk/control timeouts stop the endpoint before advancing its dequeue pointer;
stalls reset the halted endpoint. Failed recovery stops the controller and
retains its allocations instead of returning live DMA memory to the heap.
The controller gate and BOT device gate suppress cancellation/preemption while
owned, keep IRQs enabled, and have bounded hardware waits. No IRQ routing or
MSI support is needed by this initial xHCI polling backend.

UHCI remains supported. Control requests use heap bounce buffers; cancelled
or empty transfers halt the controller before TD/buffer reclamation. If USB
input is unavailable and ACPI declares an i8042 controller, the PS/2 fallback
is enabled.

QEMU now uses xHCI by default. Use `USB_HOST=uhci` for the old controller, or
`USB_STORAGE_IMG=/absolute/path/to/disposable.img` to attach a USB disk.

## USB mass storage

`src/drivers/usb_storage.c` supports the SCSI transparent subclass with
Bulk-Only Transport (class 08/subclass 06/protocol 50). It implements GET_MAX_LUN,
INQUIRY, TEST UNIT READY, REQUEST SENSE, READ CAPACITY (10/16), READ/WRITE (10/16)
and SYNCHRONIZE CACHE. Up to 16 LUNs share a device-wide command gate. The block
layer receives sector size/capacity, read/write and flush callbacks.

CBW/CSW signatures, tags, lengths, status and residue are checked. Transport
errors perform BOT reset/clear-halt recovery. Failed writes are never replayed;
DATA PROTECT sense marks the LUN read-only. Supported sector sizes are powers
of two from 512 to 4096 bytes. Larger I/O is split into 16 KiB transfers.

This is BOT support, not USB Attached SCSI (UAS). Only a supported alternate-zero
interface is selected; arbitrary composite devices and every HID report layout
are not implemented. Enumeration is at boot. Full hotplug discovery, removal
notification/block-device unregister, vendor-specific xHCI quirks, custom
protocol speed-ID tables, IOMMU DMA mapping and physical-device compatibility
testing remain separate work. Unplugged devices can return I/O failures, but
there is no general hotplug lifecycle yet.

## Generic graphics

Use UEFI Graphics Output Protocol's linear framebuffer as the baseline for
real hardware. Firmware has already configured the monitor and GPU. This
provides a software-rendered desktop without requiring separate Intel, AMD or
Nvidia drivers or legacy VGA register mode-setting.

The loader records mode dimensions, pixel pitch and RGB masks. The console and
ATK map the physical framebuffer through `ioremap`, including addresses above
4 GiB. ATK uses a heap backbuffer, runtime dimensions, hardware row pitch and
pixel conversion for RGB/BGR/contiguous bitmask modes. Small modes reflow the
desktop shortcuts. The GOP backend does not touch legacy VGA registers, alter
MTRRs, attempt unsupported page flips, or change firmware's display mode.

The Bochs backend remains for the existing QEMU desktop. Its exit restores the
firmware framebuffer geometry before returning to the console. Blit-only GOP
modes, accelerated graphics, monitor hotplug and runtime display-mode switching
are not supported by the generic framebuffer backend. Conventional BIOS-only
boot would require an additional loader/VBE path.

## Boot robustness

`bootinfo_t` version 3 carries firmware-allocated bootstrap stack/page-table
addresses. The loader reserves these and bootinfo below 4 GiB as reserved
memory, and the kernel/PMM use those actual addresses. The fixed real-mode AP
mailbox, trampoline and temporary stack pages are reserved explicitly. If
firmware owns them, boot falls back to one CPU instead of overwriting them.
The linked kernel address remains fixed; failed allocation is a diagnosed
loader failure, not an attempted overwrite or unsupported relocation.

The loader validates ELF program-header bounds, segment ranges/sizes and the
executable entry, rejects a truncated/malformed memory map, and supports up to
512 descriptors. Five-level firmware paging is rejected explicitly. A missing
usable low-memory kernel heap produces a diagnostic halt.

Loader and kernel serial output probe the UART and bound transmit waits.
Booting without COM1 is supported. BSS is cleared before kernel serial state
is initialized. ACPI MADT I/O APIC source overrides route the timer and legacy
input, with the PIC fallback retained. General PCI INTx routing still uses the
existing PIC path; full ACPI `_PRT`/interrupt-remapping support is not added.
The PIT remains the time source. Hardware without a PIT needs another timer
backend. LAPIC spurious interrupts have an IDT handler; IPIs support xAPIC and
x2APIC, preserve full CPU IDs, and bound delivery waits.

AP startup uses PIT channel-2 durations rather than CPU-speed-dependent delay
loops. A timed-out AP keeps its mailbox/stack assignment and prevents reuse by
the next AP. PCI CF8/CFC configuration transactions are serialized across CPUs.

## Validation

Run:

```sh
make
python3 tests/hardware_contract_test.py
python3 tests/hardware_qemu_test.py
python3 tests/hardware_qemu_test.py --hub
python3 tests/hardware_qemu_test.py --no-uart
python3 tests/hardware_qemu_test.py --host uhci --graphics std
python3 tests/hardware_qemu_test.py --usb-boot --memory 8G --cpus 1
```

The guest runner uses `run-via-agent.sh`, private firmware variables, a private
boot directory and disposable AHCI/USB images. Its signature-marked test
disk is the only write-test target. It verifies read/write/flush, repeated
bulk/event/control ring wraps, EP0 stall/short-packet recovery on xHCI, bounds,
USB keyboard login/command execution, desktop rendering and mouse movement.
The unrelated AHCI fixture must retain its full SHA-256 hash. Guest failures
retain stopped CPU/GDB evidence against the exact booted ELF. Acceptance
kernels are linked to isolated output paths; the normal kernel contains no
test hook.

Host tests execute production descriptor parsing, GOP pitch/size/mask validation
and BOT code under AddressSanitizer/UndefinedBehaviorSanitizer, covering corrupt
CSWs, short data, reset recovery, write protection, no write replay, overflow
bounds and 64-bit LBAs. They also exercise heap selection around firmware
framebuffer apertures and reserved memory. Results and screenshots are under
`build/test-out/hardware-*`.

For a physical trial, disable Secure Boot for the unsigned EFI binary and use
a supported UEFI framebuffer and boot-attached USB HID/BOT devices. Physical
boot, chipset timing, firmware handoff, DMA/IOMMU configuration and real USB
media behaviour still require testing on the actual machine. NVMe, Wi-Fi and
native GPU acceleration are outside this change.

Protocol references:

- [Intel xHCI specification](https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/extensible-host-controler-interface-usb-xhci.pdf)
- [USB-IF Bulk-Only Transport](https://www.usb.org/sites/default/files/usbmassbulk_10.pdf)
- [UEFI specification](https://uefi.org/specifications)
