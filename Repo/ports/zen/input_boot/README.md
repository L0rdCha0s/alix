# USB boot input starvation fix

The two input driver changes and production host contract test were applied on
2026-10-31; their outputs matched the reviewed hashes. No public header changed.
`input-boot.pending.patch` retains the reviewed patch relative to the parent
Git root; `pending.json` records its input/output hashes and acceptance.

The captured `thread-pthread-qemu` timeout happened before the test ELF started.
The shell had printed `login:` but never consumed its submitted username. UART
LSR was `0x61` (RX pending); CPU2 was in `mouse_process_byte`, with a captured byte
of `0xff`. Other CPUs were idle and scheduler/sleep locks were free.

Default preprocessing independently confirmed `ENABLE_USB` was undefined in
both input drivers. Their PS/2 booleans therefore initialized true even though
the normal QEMU command disables i8042. `mouse_poll` checked enable only once and
then drained AUX forever; an absent controller reading `0xff` satisfies both
status tests. USB binding later disabled the flag, but an already entered loop
never re-read it. This explains the timing-dependent serial-login starvation.

The applied change:

- Explicitly includes `build_features.h` in both drivers. Default USB and
  explicit `-DENABLE_USB=0` now agree with the rest of the kernel.
- Keeps keyboard software reset, repeat defaults and `/proc/keyboard` settings
  common to USB/PS2. Only the controller initialization remains conditional.
- Publishes/reads PS/2 enable flags atomically, including each mouse-poll iteration.
- Stops mouse polling on absent-controller `0xff`, leaves keyboard bytes for
  the keyboard driver, and processes at most 32 AUX bytes per call.
- Preserves the caller's interrupt state on every exit path. One in-flight byte
  may complete while another CPU disables the backend; the next iteration exits.

Validation completed: both full driver translation units compile with native
kernel flags and `-Wall -Wextra -Werror`, for default USB and explicit PS/2.
Production host tests pass plain and ASan/UBSan in both modes. They cover absent,
empty, keyboard-owned, continuously producing and mixed controller streams;
live disable; initially enabled/disabled IRQ state; USB-injected buffered
scancodes; and common keyboard initialization. The patch passes `git apply
--check`. The full normal build and active host tests passed after application.
Seven consecutive native guests then passed pthread main/initial-thread exit,
upstream libc++, upstream Rust std and write/no-access/execute protection tests.
Every guest passed serial login and recovered the shell. The combined result
is recorded in `build/ports/zen/input-runtime-guests.log`; the original failure
and debugger evidence are retained as `build/ports/zen/usb-ps2-login-failure.*`.

The completed pre-application host check was:

```sh
PYTHONPATH=tests python3 ports/zen/input_boot/pending/tests/input_poll_contract_test.py --source-tree ports/zen/input_boot/pending
```

For subsequent checks run the normal `make`, then
`python3 tests/input_poll_contract_test.py`. Native tests use the existing
bounded disposable harness. Do not regenerate or reapply the retained patch.
