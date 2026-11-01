.PHONY: zen-rust-runtime
zen-rust-runtime: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 ports/zen/rust/build.py

.PHONY: zen-rust-runtime-qemu-test
zen-rust-runtime-qemu-test: all zen-rust-runtime
	python3 tests/rust_std_qemu_test.py

.PHONY: zen-rust-file-urls-test zen-rust-file-urls-qemu-test
# Keep std publication and configure sequential even when the caller uses -j.
zen-rust-file-urls-test:
	$(MAKE) zen-rust-runtime
	$(MAKE) zen-gecko-configure
	python3 ports/zen/rust/build_file_urls_test.py

zen-rust-file-urls-qemu-test: all zen-rust-file-urls-test
	python3 tests/rust_file_urls_qemu_test.py

.PHONY: zen-rust-os-consumers-test zen-rust-os-consumers-qemu-test
zen-rust-os-consumers-test:
	$(MAKE) zen-rust-runtime
	$(MAKE) zen-gecko-configure
	python3 ports/zen/rust/build_os_consumers_test.py

zen-rust-os-consumers-qemu-test: all zen-rust-os-consumers-test
	python3 tests/rust_os_consumers_qemu_test.py

.PHONY: zen-rust-directories-test zen-rust-directories-qemu-test
zen-rust-directories-test:
	$(MAKE) zen-rust-runtime
	$(MAKE) zen-gecko-configure
	python3 ports/zen/rust/build_directories_test.py

zen-rust-directories-qemu-test: all zen-rust-directories-test
	python3 tests/rust_directories_qemu_test.py
