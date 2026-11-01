# Source preparation is opt-in; normal Alix builds never download upstream code.
# The upstream runtime uses owned descriptors. Keep the original syscall object
# for existing Alix C targets/binaries; never mix the two FD namespaces in one ELF.
ZEN_OWNED_SYSCALL := $(USER_OBJDIR)/lib/syscall-owned.o
ZEN_FCNTL_OBJECT := $(USER_OBJDIR)/lib/fcntl.o
ZEN_USER_RUNTIME_OBJECTS := $(filter-out $(USER_OBJDIR)/lib/syscall.o,$(USER_COMMON_OBJECTS)) $(ZEN_OWNED_SYSCALL) $(ZEN_FCNTL_OBJECT)

$(ZEN_OWNED_SYSCALL): user/lib/syscall.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -DALIX_OWNED_FDS=1 -c -o $@ $<

$(ZEN_FCNTL_OBJECT): user/lib/fcntl.c
	@mkdir -p $(@D)
	$(CC) $(USER_CFLAGS) -c -o $@ $<

-include $(ZEN_OWNED_SYSCALL:.o=.d) $(ZEN_FCNTL_OBJECT:.o=.d)
# QEMU exposes build/ as a FAT disk; never put Mozilla/Zen source trees there.
ZEN_SOURCE_DIR ?= $(abspath ports/zen/upstream/desktop)
ZEN_ENGINE_DIR ?= $(abspath ports/zen/upstream/firefox-159.0)
ZEN_ENGINE_ARCHIVE ?= $(abspath ports/zen/upstream/firefox-159.0.source.tar.xz)
ZEN_JS_KEEP_GOING ?= 0

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

.PHONY: zen-patch-engine zen-js-configure zen-js-build zen-patch-test zen-toolchain-test zen-host-tools zen-ssp-runtime zen-ssp-test zen-cxx-stream-test zen-cxx-wide-test zen-wchar-float-test
ZEN_SSP_ARCHIVE := $(USER_OBJDIR)/lib/libalix-ssp.a

$(ZEN_SSP_ARCHIVE): $(USER_OBJDIR)/lib/stack_protector.o
	x86_64-elf-ar rcs $@ $<

zen-ssp-runtime: $(ZEN_SSP_ARCHIVE)

zen-ssp-test: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 tests/stack_protector_toolchain_test.py

zen-cxx-stream-test: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 tests/cxx_stream_toolchain_test.py

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

zen-patch-test:
	python3 tests/zen_patch_test.py

zen-toolchain-test: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 tests/zen_toolchain_test.py

zen-host-tools:
	python3 ports/zen/build_host_tools.py
