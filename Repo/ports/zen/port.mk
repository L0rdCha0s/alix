# Source preparation is opt-in; normal Alix builds never download upstream code.
# QEMU exposes build/ as a FAT disk; never put Mozilla/Zen source trees there.
ZEN_SOURCE_DIR ?= $(abspath ports/zen/upstream/desktop)
ZEN_ENGINE_DIR ?= $(abspath ports/zen/upstream/firefox-159.0)
ZEN_ENGINE_ARCHIVE ?= $(abspath ports/zen/upstream/firefox-159.0.source.tar.xz)

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
include ports/zen/rust/runtime.mk

.PHONY: zen-patch-engine zen-js-configure zen-js-build zen-patch-test zen-toolchain-test zen-host-tools zen-ssp-runtime zen-ssp-test zen-cxx-stream-test zen-cxx-wide-test zen-wchar-float-test
ZEN_SSP_ARCHIVE := $(USER_OBJDIR)/lib/libalix-ssp.a

$(ZEN_SSP_ARCHIVE): $(USER_OBJDIR)/lib/stack_protector.o
	x86_64-elf-ar rcs $@ $<

zen-ssp-runtime: $(ZEN_SSP_ARCHIVE)

zen-ssp-test: $(USER_COMMON_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(USER_COMMON_OBJECTS)" python3 tests/stack_protector_toolchain_test.py

zen-cxx-stream-test: $(USER_COMMON_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(USER_COMMON_OBJECTS)" python3 tests/cxx_stream_toolchain_test.py

zen-cxx-wide-test: $(USER_COMMON_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(USER_COMMON_OBJECTS)" python3 tests/cxx_stream_toolchain_test.py --wide

zen-wchar-float-test: $(USER_COMMON_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(USER_COMMON_OBJECTS)" python3 tests/cxx_stream_toolchain_test.py --wide-float

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

.PHONY: calendar-locale-qemu-test zen-ssp-qemu-test signal-qemu-test timezone-qemu-test
calendar-locale-qemu-test: all $(USER_OBJDIR)/calendar_locale_test.elf
	python3 tests/calendar_locale_qemu_test.py

zen-ssp-qemu-test: all zen-ssp-test
	python3 tests/stack_protector_qemu_test.py

signal-qemu-test: all $(USER_OBJDIR)/signal_test.elf
	python3 tests/signal_qemu_test.py

timezone-qemu-test: all $(USER_OBJDIR)/timezone_test.elf
	python3 tests/timezone_qemu_test.py

zen-patch-engine:
	python3 ports/zen/patch_engine.py --engine-dir "$(ZEN_ENGINE_DIR)"

zen-js-configure: $(USER_COMMON_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(USER_COMMON_OBJECTS)" python3 ports/zen/configure_engine.py --engine-dir "$(ZEN_ENGINE_DIR)"

zen-js-build: $(USER_COMMON_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(USER_COMMON_OBJECTS)" python3 ports/zen/configure_engine.py --engine-dir "$(ZEN_ENGINE_DIR)" --build

zen-patch-test:
	python3 tests/zen_patch_test.py

zen-toolchain-test: $(USER_COMMON_OBJECTS) $(USER_LD_SCRIPT) $(ZEN_SSP_ARCHIVE)
	ALIX_RUNTIME_OBJECTS="$(USER_COMMON_OBJECTS)" python3 tests/zen_toolchain_test.py

zen-host-tools:
	python3 ports/zen/build_host_tools.py
