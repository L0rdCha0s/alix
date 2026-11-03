# Source preparation is opt-in; normal Alix builds never download upstream code.
# The upstream runtime uses owned descriptors. Keep the original syscall object
# for existing Alix C targets/binaries; never mix the two FD namespaces in one ELF.
ZEN_OWNED_SYSCALL := $(USER_OBJDIR)/lib/syscall-owned.o
ZEN_UPSTREAM_LIBC := $(USER_OBJDIR)/lib/libc-upstream.o
ZEN_FCNTL_OBJECT := $(USER_OBJDIR)/lib/fcntl.o
ZEN_TERMIOS_OBJECT := $(USER_OBJDIR)/lib/termios.o
ZEN_POLL_OBJECT := $(USER_OBJDIR)/lib/poll.o
ZEN_SOCKET_OBJECT := $(USER_OBJDIR)/lib/socket-owned.o
ZEN_SELECT_OBJECT := $(USER_OBJDIR)/lib/select-owned.o
ZEN_IOCTL_OBJECT := $(USER_OBJDIR)/lib/ioctl-owned.o
ZEN_RESOURCE_OBJECT := $(USER_OBJDIR)/lib/resource-owned.o
ZEN_DSO_START := $(USER_OBJDIR)/lib/dso_start.o
ZEN_USER_RUNTIME_OBJECTS := $(filter-out $(USER_OBJDIR)/lib/syscall.o $(USER_OBJDIR)/lib/libc.o $(USER_OBJDIR)/lib/socket.o $(USER_OBJDIR)/lib/select.o $(USER_OBJDIR)/lib/ioctl.o $(USER_OBJDIR)/lib/resource.o,$(USER_COMMON_OBJECTS)) $(ZEN_UPSTREAM_LIBC) $(ZEN_OWNED_SYSCALL) $(ZEN_FCNTL_OBJECT) $(ZEN_TERMIOS_OBJECT) $(ZEN_POLL_OBJECT) $(ZEN_SOCKET_OBJECT) $(ZEN_SELECT_OBJECT) $(ZEN_IOCTL_OBJECT) $(ZEN_RESOURCE_OBJECT)

$(ZEN_UPSTREAM_LIBC): user/lib/libc.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -DALIX_UPSTREAM_ABORT_HOOK=1 -DALIX_OWNED_FDS=1 -c -o $@ $<

$(ZEN_OWNED_SYSCALL): user/lib/syscall.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -DALIX_OWNED_FDS=1 -c -o $@ $<

$(ZEN_SOCKET_OBJECT): user/lib/socket.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -DALIX_OWNED_FDS=1 -c -o $@ $<

$(ZEN_SELECT_OBJECT): user/lib/select.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -DALIX_OWNED_FDS=1 -c -o $@ $<

$(ZEN_IOCTL_OBJECT): user/lib/ioctl.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -DALIX_OWNED_FDS=1 -c -o $@ $<

$(ZEN_RESOURCE_OBJECT): user/lib/resource.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -DALIX_OWNED_FDS=1 -c -o $@ $<

$(ZEN_DSO_START): user/lib/dso_start.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -fPIC -mcmodel=small -ftls-model=global-dynamic -c -o $@ $<

.PHONY: zen-dso-runtime
zen-dso-runtime: $(ZEN_DSO_START)

.PHONY: zen-dynamic-loader-qemu-test
zen-dynamic-loader-qemu-test: all zen-dso-runtime $(ZEN_USER_RUNTIME_OBJECTS) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 tests/zen_toolchain_test.py
	python3 ports/zen/build_dynamic_loader_test.py
	python3 tests/zen_static_elf_validator_test.py
	python3 tests/dynamic_loader_qemu_test.py

.PHONY: zen-rlbox-runtime-qemu-test
zen-rlbox-runtime-qemu-test: all $(ZEN_USER_RUNTIME_OBJECTS) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 tests/zen_toolchain_test.py
	python3 ports/zen/build_rlbox_runtime_test.py
	python3 tests/rlbox_runtime_qemu_test.py

.PHONY: zen-udp-core-qemu-test
zen-udp-core-qemu-test:
	python3 tests/udp_owned_qemu_test.py

$(ZEN_FCNTL_OBJECT): user/lib/fcntl.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

-include $(ZEN_UPSTREAM_LIBC:.o=.d) $(ZEN_OWNED_SYSCALL:.o=.d) $(ZEN_FCNTL_OBJECT:.o=.d) $(ZEN_TERMIOS_OBJECT:.o=.d) $(ZEN_POLL_OBJECT:.o=.d) $(ZEN_SOCKET_OBJECT:.o=.d) $(ZEN_SELECT_OBJECT:.o=.d) $(ZEN_IOCTL_OBJECT:.o=.d) $(ZEN_RESOURCE_OBJECT:.o=.d)

$(USER_OBJDIR)/tests/terminal_test.o: tests/terminal_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/terminal_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/terminal_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/terminal_test.o

.PHONY: zen-terminal-qemu-test
zen-terminal-qemu-test:
	python3 tests/terminal_qemu_test.py

$(USER_OBJDIR)/tests/pipe_test.o: tests/pipe_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/pipe_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/pipe_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/pipe_test.o

.PHONY: pipe-contract-test zen-pipe-qemu-test
pipe-contract-test:
	python3 tests/pipe_contract_test.py
zen-pipe-qemu-test:
	python3 tests/pipe_qemu_test.py

$(USER_OBJDIR)/tests/stat_clock_test.o: tests/stat_clock_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/stat_clock_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/stat_clock_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/stat_clock_test.o

.PHONY: zen-stat-clock-qemu-test
zen-stat-clock-qemu-test:
	python3 tests/stat_clock_qemu_test.py

$(USER_OBJDIR)/tests/file_identity_test.o: tests/file_identity_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/file_identity_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/file_identity_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/file_identity_test.o

.PHONY: zen-file-identity-qemu-test
zen-file-identity-qemu-test: all $(USER_OBJDIR)/file_identity_test.elf
	python3 tests/file_identity_qemu_test.py

$(USER_OBJDIR)/tests/record_lock_test.o: tests/record_lock_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/record_lock_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/record_lock_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/record_lock_test.o

.PHONY: zen-record-lock-qemu-test
zen-record-lock-qemu-test: all $(USER_OBJDIR)/record_lock_test.elf
	python3 tests/record_lock_qemu_test.py

.PHONY: zen-sqlite-runtime-qemu-test
zen-sqlite-runtime-qemu-test: all $(ZEN_USER_RUNTIME_OBJECTS)
	python3 ports/zen/build_sqlite_runtime_test.py
	python3 tests/sqlite_runtime_qemu_test.py

.PHONY: zen-version-loader-qemu-test
zen-version-loader-qemu-test: all $(ZEN_USER_RUNTIME_OBJECTS)
	python3 ports/zen/build_version_loader_test.py
	python3 tests/version_loader_qemu_test.py

$(USER_OBJDIR)/tests/process_wait_status_test.o: tests/process_wait_status_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/process_wait_status_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/process_wait_status_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/process_wait_status_test.o

.PHONY: zen-wait-status-qemu-test
zen-wait-status-qemu-test:
	python3 tests/process_wait_status_qemu_test.py

$(USER_OBJDIR)/tests/process_spawn_test.o: tests/process_spawn_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<
$(USER_OBJDIR)/process_spawn_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/process_spawn_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/process_spawn_test.o
.PHONY: zen-process-spawn-qemu-test
zen-process-spawn-qemu-test:
	python3 tests/process_spawn_qemu_test.py

$(USER_OBJDIR)/tests/waitid_test.o: tests/waitid_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<
$(USER_OBJDIR)/waitid_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/waitid_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/waitid_test.o
.PHONY: zen-waitid-qemu-test
zen-waitid-qemu-test: all $(USER_OBJDIR)/waitid_test.elf
	python3 tests/waitid_qemu_test.py

$(USER_OBJDIR)/tests/random_test.o: tests/random_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<
$(USER_OBJDIR)/random_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/random_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/random_test.o
.PHONY: zen-random-qemu-test
zen-random-qemu-test: all $(USER_OBJDIR)/random_test.elf
	python3 tests/random_qemu_test.py

$(USER_OBJDIR)/tests/creation_modes_test.o: tests/creation_modes_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<
$(USER_OBJDIR)/creation_modes_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/creation_modes_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/creation_modes_test.o
.PHONY: zen-creation-modes-qemu-test
zen-creation-modes-qemu-test: all $(USER_OBJDIR)/creation_modes_test.elf
	python3 tests/creation_modes_qemu_test.py

.PHONY: zen-libevent-qemu-test
zen-libevent-qemu-test: all $(ZEN_USER_RUNTIME_OBJECTS) zen-ssp-runtime
	python3 ports/zen/build_libevent_runtime_test.py
	python3 tests/libevent_runtime_qemu_test.py

$(USER_OBJDIR)/tests/posix_spawn_test.o: tests/posix_spawn_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<
$(USER_OBJDIR)/posix_spawn_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/posix_spawn_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/posix_spawn_test.o
.PHONY: zen-posix-spawn-qemu-test
zen-posix-spawn-qemu-test:
	python3 tests/posix_spawn_qemu_test.py

$(USER_OBJDIR)/tests/audio_owned_test.o: tests/audio_owned_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/audio_owned_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/audio_owned_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/audio_owned_test.o

$(USER_OBJDIR)/tests/poll_test.o: tests/poll_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/poll_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/poll_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/poll_test.o

.PHONY: zen-poll-qemu-test
zen-poll-qemu-test: all $(USER_OBJDIR)/poll_test.elf
	python3 tests/poll_qemu_test.py

$(USER_OBJDIR)/tests/window_control_test.o: tests/window_control_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/window_control_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/window_control_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/window_control_test.o

.PHONY: zen-window-control-qemu-test
zen-window-control-qemu-test: $(USER_OBJDIR)/window_control_test.elf $(USER_OBJDIR)/atk_shell.elf
	python3 tests/window_control_qemu_test.py

$(USER_OBJDIR)/tests/posix_runtime_test.o: tests/posix_runtime_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/posix_runtime_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/posix_runtime_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/posix_runtime_test.o

.PHONY: zen-posix-runtime-qemu-test
zen-posix-runtime-qemu-test: all $(USER_OBJDIR)/posix_runtime_test.elf
	python3 tests/posix_runtime_qemu_test.py

$(USER_OBJDIR)/tests/sleep_test.o: tests/sleep_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/sleep_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/sleep_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/sleep_test.o

.PHONY: zen-sleep-qemu-test
zen-sleep-qemu-test: all $(USER_OBJDIR)/sleep_test.elf
	python3 tests/sleep_qemu_test.py

$(USER_OBJDIR)/tests/shared_memory_test.o: tests/shared_memory_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/shared_memory_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/shared_memory_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/shared_memory_test.o

.PHONY: zen-shared-memory-qemu-test
zen-shared-memory-qemu-test: all $(USER_OBJDIR)/shared_memory_test.elf
	python3 tests/shared_memory_qemu_test.py

$(USER_OBJDIR)/tests/fd_stream_test.o: tests/fd_stream_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/fd_stream_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/fd_stream_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/fd_stream_test.o

.PHONY: zen-fd-stream-qemu-test
zen-fd-stream-qemu-test: all $(USER_OBJDIR)/fd_stream_test.elf
	python3 tests/fd_stream_qemu_test.py

ZEN_RUST_LIBC_SOURCE := ports/zen/upstream/firefox-159.0/third_party/rust/libc/src
ZEN_RUST_LIBC_FFI_DIR := build/ports/zen/rust-libc-ffi
$(ZEN_RUST_LIBC_FFI_DIR)/liblibc.rlib: $(ZEN_RUST_LIBC_SOURCE)/lib.rs $(ZEN_RUST_LIBC_SOURCE)/alix/mod.rs $(ZEN_RUST_LIBC_SOURCE)/alix/sdk.rs ports/zen/patches/series.json ports/zen/rust/rustc.py ports/zen/rust/x86_64-unknown-alix.json
	@mkdir -p $(@D)
	python3 ports/zen/rust/rustc.py --crate-name libc --crate-type rlib --edition 2021 --target x86_64-unknown-alix -C panic=abort -C opt-level=2 $(ZEN_RUST_LIBC_SOURCE)/lib.rs -o $@

$(ZEN_RUST_LIBC_FFI_DIR)/libffi.a: tests/rust_libc_ffi_test.rs $(ZEN_RUST_LIBC_FFI_DIR)/liblibc.rlib
	python3 ports/zen/rust/rustc.py --crate-name alix_rust_libc_ffi --crate-type staticlib --edition 2021 --target x86_64-unknown-alix -C panic=abort -C opt-level=2 --extern libc=$(ZEN_RUST_LIBC_FFI_DIR)/liblibc.rlib $< -o $@

$(USER_OBJDIR)/tests/rust_libc_ffi_test.o: tests/rust_libc_ffi_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/rust_libc_ffi_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/rust_libc_ffi_test.o $(ZEN_RUST_LIBC_FFI_DIR)/libffi.a $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/rust_libc_ffi_test.o $(ZEN_RUST_LIBC_FFI_DIR)/libffi.a

.PHONY: zen-rust-libc-ffi-qemu-test
zen-rust-libc-ffi-qemu-test: all $(USER_OBJDIR)/rust_libc_ffi_test.elf
	python3 tests/rust_libc_ffi_qemu_test.py

$(USER_OBJDIR)/tests/flock_test.o: tests/flock_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/flock_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/flock_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/flock_test.o

.PHONY: zen-flock-qemu-test flock-contract-test
zen-flock-qemu-test: all $(USER_OBJDIR)/flock_test.elf
	python3 tests/flock_qemu_test.py
flock-contract-test:
	python3 tests/flock_contract_test.py

$(USER_OBJDIR)/tests/ioctl_test.o: tests/ioctl_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<
$(USER_OBJDIR)/tests/ioctl_legacy_test.o: tests/ioctl_legacy_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<
$(USER_OBJDIR)/ioctl_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/ioctl_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/ioctl_test.o
$(USER_OBJDIR)/ioctl_legacy_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/ioctl_legacy_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/ioctl_legacy_test.o
.PHONY: zen-ioctl-qemu-test
zen-ioctl-qemu-test: all $(USER_OBJDIR)/ioctl_test.elf $(USER_OBJDIR)/ioctl_legacy_test.elf
	python3 tests/ioctl_qemu_test.py

$(USER_OBJDIR)/tests/system_identity_test.o: tests/system_identity_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<
$(USER_OBJDIR)/system_identity_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/system_identity_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/system_identity_test.o
.PHONY: zen-system-identity-qemu-test
zen-system-identity-qemu-test: all $(USER_OBJDIR)/system_identity_test.elf
	python3 tests/system_identity_qemu_test.py
.PHONY: zen-nspr-file-abi-qemu-test
zen-nspr-file-abi-qemu-test: all $(ZEN_USER_RUNTIME_OBJECTS) $(ZEN_SSP_ARCHIVE)
	python3 ports/zen/build_nspr_file_abi_test.py
	python3 tests/nspr_file_abi_qemu_test.py

.PHONY: zen-nspr-resources-qemu-test
zen-nspr-resources-qemu-test: all $(ZEN_USER_RUNTIME_OBJECTS) $(ZEN_SSP_ARCHIVE)
	python3 ports/zen/build_nspr_resources_test.py
	python3 tests/nspr_resources_qemu_test.py

$(USER_OBJDIR)/tests/synchronous_file_test.o: tests/synchronous_file_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/tests/synchronous_file_legacy_test.o: tests/synchronous_file_legacy_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/synchronous_file_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/synchronous_file_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/synchronous_file_test.o

$(USER_OBJDIR)/synchronous_file_legacy_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/synchronous_file_legacy_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/synchronous_file_legacy_test.o

.PHONY: zen-synchronous-file-qemu-test
zen-synchronous-file-qemu-test: all $(USER_OBJDIR)/synchronous_file_test.elf $(USER_OBJDIR)/synchronous_file_legacy_test.elf
	python3 tests/synchronous_file_qemu_test.py

$(USER_OBJDIR)/tests/fd_limits_test.o: tests/fd_limits_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/tests/fd_limits_legacy_test.o: tests/fd_limits_legacy_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/fd_limits_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/fd_limits_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/fd_limits_test.o

$(USER_OBJDIR)/fd_limits_legacy_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/fd_limits_legacy_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/fd_limits_legacy_test.o

.PHONY: zen-fd-limits-qemu-test
zen-fd-limits-qemu-test: all $(USER_OBJDIR)/fd_limits_test.elf $(USER_OBJDIR)/fd_limits_legacy_test.elf
	python3 tests/fd_limits_qemu_test.py

$(USER_OBJDIR)/tests/spawn_cwd_test.o: tests/spawn_cwd_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/spawn_cwd_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/spawn_cwd_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/spawn_cwd_test.o

.PHONY: zen-spawn-cwd-qemu-test
zen-spawn-cwd-qemu-test: all $(USER_OBJDIR)/spawn_cwd_test.elf
	python3 tests/spawn_cwd_qemu_test.py

.PHONY: zen-nspr-spawn-qemu-test
zen-nspr-spawn-qemu-test: all $(ZEN_USER_RUNTIME_OBJECTS) $(ZEN_SSP_ARCHIVE)
	python3 ports/zen/build_nspr_spawn_test.py
	python3 tests/nspr_spawn_qemu_test.py

$(USER_OBJDIR)/tests/sigwait_test.o: tests/sigwait_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/sigwait_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/sigwait_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/sigwait_test.o

.PHONY: zen-sigwait-qemu-test
zen-sigwait-qemu-test: all $(USER_OBJDIR)/sigwait_test.elf
	python3 tests/sigwait_qemu_test.py

$(USER_OBJDIR)/tests/file_mapping_test.o: tests/file_mapping_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<
$(USER_OBJDIR)/file_mapping_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/file_mapping_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/file_mapping_test.o
.PHONY: zen-file-mapping-qemu-test
$(USER_OBJDIR)/tests/file_mapping_legacy_test.o: tests/file_mapping_legacy_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<
$(USER_OBJDIR)/file_mapping_legacy_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/file_mapping_legacy_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/file_mapping_legacy_test.o
zen-file-mapping-qemu-test: all $(USER_OBJDIR)/file_mapping_test.elf $(USER_OBJDIR)/file_mapping_legacy_test.elf
	python3 tests/file_mapping_qemu_test.py

$(USER_OBJDIR)/tests/writev_test.o: tests/writev_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<
$(USER_OBJDIR)/writev_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/writev_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/writev_test.o
.PHONY: zen-writev-qemu-test
zen-writev-qemu-test: all $(USER_OBJDIR)/writev_test.elf
	python3 tests/writev_qemu_test.py

.PHONY: zen-nspr-library-build zen-nspr-runtime-qemu-test
zen-nspr-library-build: zen-dso-runtime
	python3 ports/zen/build_nspr_library.py --make "$(MAKE)" --jobs 2

zen-nspr-runtime-qemu-test: all zen-dso-runtime zen-toolchain-test
	python3 ports/zen/build_nspr_library.py --make "$(MAKE)" --jobs 2
	python3 ports/zen/build_nspr_runtime_test.py
	python3 tests/nspr_runtime_qemu_test.py

.PHONY: zen-rust-dynamic-loading-qemu-test
zen-rust-dynamic-loading-qemu-test: all zen-dso-runtime zen-toolchain-test
	python3 ports/zen/rust/build_dynamic_loading_test.py
	python3 tests/rust_dynamic_loading_qemu_test.py

$(USER_OBJDIR)/tests/executable_path_test.o: tests/executable_path_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/executable_path_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/executable_path_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/executable_path_test.o

.PHONY: zen-executable-path-qemu-test
zen-executable-path-qemu-test: all $(USER_OBJDIR)/executable_path_test.elf
	python3 tests/executable_path_qemu_test.py

$(USER_OBJDIR)/tests/socket_test.o: tests/socket_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/socket_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/socket_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/socket_test.o

.PHONY: zen-socket-qemu-test
zen-socket-qemu-test: all $(USER_OBJDIR)/socket_test.elf
	python3 tests/socket_qemu_test.py

$(USER_OBJDIR)/tests/netdb_test.o: tests/netdb_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/netdb_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/netdb_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/netdb_test.o

.PHONY: zen-netdb-qemu-test
zen-netdb-qemu-test: all $(USER_OBJDIR)/netdb_test.elf
	python3 tests/netdb_qemu_test.py

$(USER_OBJDIR)/tests/gecko_os_interfaces_test.o: tests/gecko_os_interfaces_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/gecko_os_interfaces_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/gecko_os_interfaces_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/gecko_os_interfaces_test.o

.PHONY: zen-gecko-os-interfaces-qemu-test
zen-gecko-os-interfaces-qemu-test: all $(USER_OBJDIR)/gecko_os_interfaces_test.elf
	python3 tests/gecko_os_interfaces_qemu_test.py

$(USER_OBJDIR)/tests/select_test.o: tests/select_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/select_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/select_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/select_test.o

.PHONY: zen-select-qemu-test
zen-select-qemu-test: all $(USER_OBJDIR)/select_test.elf
	python3 tests/select_qemu_test.py

$(USER_OBJDIR)/tests/filesystem_primitives_test.o: tests/filesystem_primitives_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/filesystem_primitives_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/filesystem_primitives_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/filesystem_primitives_test.o

.PHONY: zen-filesystem-primitives-qemu-test
zen-filesystem-primitives-qemu-test: all $(USER_OBJDIR)/filesystem_primitives_test.elf
	python3 tests/filesystem_primitives_qemu_test.py
# Keep upstream source trees separate from generated build artifacts. QEMU's
# boot volume now exposes only the staged loader and kernel in build/boot/.
ZEN_SOURCE_DIR ?= $(abspath ports/zen/upstream/desktop)
ZEN_ENGINE_DIR ?= $(abspath ports/zen/upstream/firefox-159.0)
ZEN_ENGINE_ARCHIVE ?= $(abspath ports/zen/upstream/firefox-159.0.source.tar.xz)
ZEN_JS_KEEP_GOING ?= 0
ZEN_GECKO_KEEP_GOING ?= 0
ZEN_GECKO_JOBS ?= 2

.PHONY: zen-fetch zen-fetch-engine zen-preflight zen-source-test
zen-fetch:
	python3 ports/zen/prepare.py fetch --source-dir "$(ZEN_SOURCE_DIR)"

zen-fetch-engine:
	python3 ports/zen/prepare.py fetch-engine --engine-dir "$(ZEN_ENGINE_DIR)" --engine-archive "$(ZEN_ENGINE_ARCHIVE)"

zen-preflight:
	python3 ports/zen/prepare.py preflight --source-dir "$(ZEN_SOURCE_DIR)"

zen-source-test:
	python3 tests/zen_source_test.py

include ports/zen/libcxx/runtime.mk
include ports/zen/libm/runtime.mk
include ports/zen/rust/runtime.mk

.PHONY: zen-patch-engine zen-js-configure zen-js-build zen-gecko-configure zen-gecko-build zen-patch-test zen-toolchain-test zen-host-tools zen-ssp-runtime zen-ssp-test zen-cxx-stream-test zen-cxx-wide-test zen-wchar-float-test
ZEN_SSP_ARCHIVE := $(USER_OBJDIR)/lib/libalix-ssp.a

$(ZEN_SSP_ARCHIVE): $(USER_OBJDIR)/lib/stack_protector.o
	x86_64-elf-ar rcs $@ $<

zen-ssp-runtime: $(ZEN_SSP_ARCHIVE)

zen-ssp-test: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 tests/stack_protector_toolchain_test.py

.PHONY: zen-ssp-loader-qemu-test
zen-ssp-loader-qemu-test: all zen-dso-runtime zen-ssp-test
	python3 ports/zen/build_ssp_loader_test.py
	python3 tests/ssp_loader_qemu_test.py

zen-cxx-stream-test: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 tests/cxx_stream_toolchain_test.py

.PHONY: zen-cxx-random-test zen-cxx-random-qemu-test
zen-cxx-random-test: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 tests/cxx_stream_toolchain_test.py --random-device
zen-cxx-random-qemu-test: all zen-cxx-random-test
	python3 tests/random_device_qemu_test.py

zen-cxx-wide-test: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 tests/cxx_stream_toolchain_test.py --wide

zen-wchar-float-test: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 tests/cxx_stream_toolchain_test.py --wide-float

.PHONY: zen-nearbyint-test zen-math-support-test
zen-nearbyint-test: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 tests/cxx_stream_toolchain_test.py --nearbyint

zen-math-support-test: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 tests/cxx_stream_toolchain_test.py --math-support

$(USER_OBJDIR)/tests/stdio_buffer_test.o: tests/stdio_buffer_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/stdio_buffer_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/stdio_buffer_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/stdio_buffer_test.o

$(USER_OBJDIR)/tests/resource_usage_test.o: tests/resource_usage_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/resource_usage_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/resource_usage_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/resource_usage_test.o

$(USER_OBJDIR)/tests/readlink_test.o: tests/readlink_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/readlink_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/readlink_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/readlink_test.o

$(USER_OBJDIR)/tests/posix_entrypoints_test.o: tests/posix_entrypoints_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/posix_entrypoints_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/posix_entrypoints_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/posix_entrypoints_test.o

$(USER_OBJDIR)/tests/math_atan2_test.o: tests/math_atan2_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/math_atan2_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/math_atan2_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/math_atan2_test.o

$(USER_OBJDIR)/tests/signal_test.o: tests/signal_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/signal_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/signal_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/signal_test.o

$(USER_OBJDIR)/tests/inttypes_test.o: tests/inttypes_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/inttypes_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/inttypes_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/inttypes_test.o

$(USER_OBJDIR)/tests/calendar_locale_test.o: tests/calendar_locale_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/calendar_locale_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/calendar_locale_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/calendar_locale_test.o

$(USER_OBJDIR)/tests/timezone_test.o: tests/timezone_test.c tests/timezone_fixtures.h
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/timezone_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/timezone_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/timezone_test.o

$(USER_OBJDIR)/tests/stdio_stream_test.o: tests/stdio_stream_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/stdio_stream_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/stdio_stream_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/stdio_stream_test.o

$(USER_OBJDIR)/tests/printf_locale_test.o: tests/printf_locale_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -frounding-math -c -o $@ $<

$(USER_OBJDIR)/printf_locale_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/printf_locale_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/printf_locale_test.o

$(USER_OBJDIR)/tests/wchar_test.o: tests/wchar_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/wchar_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/wchar_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/wchar_test.o

$(USER_OBJDIR)/tests/wide_stdio_test.o: tests/wide_stdio_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -frounding-math -c -o $@ $<

$(USER_OBJDIR)/wide_stdio_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/wide_stdio_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/wide_stdio_test.o

$(USER_OBJDIR)/tests/exception_context_test.o: tests/exception_context_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -frounding-math -c -o $@ $<

$(USER_OBJDIR)/tests/exception_context_probe.o: tests/exception_context_probe.S
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/exception_context_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/exception_context_test.o $(USER_OBJDIR)/tests/exception_context_probe.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/exception_context_test.o $(USER_OBJDIR)/tests/exception_context_probe.o

$(USER_OBJDIR)/tests/kernel_preempt_test.o: tests/kernel_preempt_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/tests/kernel_preempt_probe.o: tests/kernel_preempt_probe.S
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/tests/kernel_preempt_model.o: src/arch/x86/process_preempt.S
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) '-DALIX_PREEMPT_RESUME_SLOT=[rip+test_resume_rip]' -c -o $@ $<

$(USER_OBJDIR)/kernel_preempt_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/kernel_preempt_test.o $(USER_OBJDIR)/tests/kernel_preempt_probe.o $(USER_OBJDIR)/tests/kernel_preempt_model.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/kernel_preempt_test.o $(USER_OBJDIR)/tests/kernel_preempt_probe.o $(USER_OBJDIR)/tests/kernel_preempt_model.o

.PHONY: calendar-locale-qemu-test zen-ssp-qemu-test signal-qemu-test timezone-qemu-test
calendar-locale-qemu-test: all $(USER_OBJDIR)/calendar_locale_test.elf
	python3 tests/calendar_locale_qemu_test.py

zen-ssp-qemu-test: all zen-ssp-test
	python3 tests/stack_protector_qemu_test.py

signal-qemu-test: all $(USER_OBJDIR)/signal_test.elf
	python3 tests/signal_qemu_test.py

timezone-qemu-test: all $(USER_OBJDIR)/timezone_test.elf
	python3 tests/timezone_qemu_test.py

$(USER_OBJDIR)/tests/directory_stream_test.o: tests/directory_stream_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/directory_stream_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/directory_stream_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/directory_stream_test.o

.PHONY: directory-contract-test zen-directory-qemu-test
directory-contract-test:
	python3 -B tests/directory_snapshot_contract_test.py
	python3 -B tests/directory_cursor_contract_test.py
	python3 -B tests/directory_retirement_contract_test.py

zen-directory-qemu-test: all $(USER_OBJDIR)/directory_stream_test.elf
	python3 -B tests/directory_stream_qemu_test.py

.PHONY: tcp-owned-contract-test tcp-owned-qemu-test
tcp-owned-contract-test:
	python3 -B tests/tcp_owned_contract_test.py

tcp-owned-qemu-test:
	python3 -B tests/tcp_owned_qemu_test.py

.PHONY: io-event-service-test event-tcp-qemu-test shell-lifetime-test
io-event-service-test:
	python3 -B tests/io_event_service_contract_test.py

event-tcp-qemu-test:
	python3 -B tests/tcp_owned_qemu_test.py

shell-lifetime-test:
	python3 -B tests/shell_actor_lifetime_test.py
	python3 -B tests/shell_cwd_contract_test.py

$(USER_OBJDIR)/tests/private_fd_test.o: tests/private_fd_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/private_fd_test.elf: $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/private_fd_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(USER_COMMON_OBJECTS) $(USER_OBJDIR)/tests/private_fd_test.o

$(USER_OBJDIR)/tests/owned_fd_libc_test.o: tests/owned_fd_libc_test.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

$(USER_OBJDIR)/owned_fd_libc_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/owned_fd_libc_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/owned_fd_libc_test.o

zen-patch-engine:
	python3 ports/zen/patch_engine.py --engine-dir "$(ZEN_ENGINE_DIR)"

zen-js-configure: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 ports/zen/configure_engine.py --engine-dir "$(ZEN_ENGINE_DIR)"

zen-js-build: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 ports/zen/configure_engine.py --engine-dir "$(ZEN_ENGINE_DIR)" --build $(if $(filter 1,$(ZEN_JS_KEEP_GOING)),--keep-going,)

zen-gecko-configure: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 ports/zen/configure_engine.py --engine-dir "$(ZEN_ENGINE_DIR)" --project browser

zen-gecko-build: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 ports/zen/configure_engine.py --engine-dir "$(ZEN_ENGINE_DIR)" --project browser --build --jobs "$(ZEN_GECKO_JOBS)" $(if $(filter 1,$(ZEN_GECKO_KEEP_GOING)),--keep-going,)

zen-patch-test:
	python3 tests/zen_patch_test.py

zen-toolchain-test: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 tests/zen_toolchain_test.py

.PHONY: zen-cubeb-test zen-cubeb-profiler-test
zen-cubeb-test: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 ports/zen/cubeb/build_test.py

zen-cubeb-profiler-test: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 ports/zen/cubeb/build_test.py --profiler-provider

.PHONY: zen-wasi-sdk
zen-wasi-sdk:
	python3 ports/zen/wasi_sdk.py

.PHONY: zen-toolchain-qemu-test
zen-toolchain-qemu-test:
	python3 tests/zen_toolchain_qemu_test.py

zen-host-tools:
	python3 ports/zen/build_host_tools.py

# Full C11 acceptance also exercises the process-owned descriptor namespace.
$(USER_OBJDIR)/libc_complete_owned_test.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/libc_complete_test.o $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_OBJDIR)/tests/libc_complete_test.o
