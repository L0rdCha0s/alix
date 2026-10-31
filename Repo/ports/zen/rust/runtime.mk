.PHONY: zen-rust-runtime
zen-rust-runtime: $(USER_COMMON_OBJECTS) $(USER_LD_SCRIPT)
	ALIX_RUNTIME_OBJECTS="$(USER_COMMON_OBJECTS)" python3 ports/zen/rust/build.py

.PHONY: zen-rust-runtime-qemu-test
zen-rust-runtime-qemu-test: all zen-rust-runtime
	python3 tests/rust_std_qemu_test.py
