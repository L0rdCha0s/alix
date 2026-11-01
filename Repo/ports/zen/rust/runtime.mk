.PHONY: zen-rust-runtime
zen-rust-runtime: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 ports/zen/rust/build.py

.PHONY: zen-rust-runtime-qemu-test
zen-rust-runtime-qemu-test: all zen-rust-runtime
	python3 tests/rust_std_qemu_test.py
