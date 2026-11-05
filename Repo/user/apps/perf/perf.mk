# Use the process-owned FD runtime for every benchmark and GUI path.
PERF_OBJECTS := $(USER_OBJDIR)/apps/perf/perf.o $(USER_OBJDIR)/apps/perf/gui.o
$(USER_OBJDIR)/perf.elf: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_ATK_OBJECTS) $(PERF_OBJECTS) $(USER_LD_SCRIPT)
	$(LD) -nostdlib -T $(USER_LD_SCRIPT) -o $@ $(ZEN_USER_RUNTIME_OBJECTS) $(USER_ATK_OBJECTS) $(PERF_OBJECTS)
$(USER_BIN_DIR)/perf: $(USER_OBJDIR)/perf.elf
	@mkdir -p $(@D)
	cp $< $@
.PHONY: perf perf-qemu perf-cli-qemu
perf: $(USER_OBJDIR)/perf.elf $(USER_BIN_DIR)/perf
perf-qemu: all
	python3 tools/perf.py run --gui --quick
perf-cli-qemu: all
	python3 tools/perf.py run --quick
