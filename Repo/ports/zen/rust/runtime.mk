.PHONY: zen-rust-runtime
zen-rust-runtime: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 ports/zen/rust/build.py

.PHONY: zen-rust-pic-runtime
zen-rust-pic-runtime: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 ports/zen/rust/build.py --pic --no-publish-smoke

.PHONY: zen-rust-runtime-qemu-test
zen-rust-runtime-qemu-test: all zen-rust-runtime
	python3 tests/rust_std_qemu_test.py

.PHONY: zen-rust-std-net-qemu-test
zen-rust-std-net-qemu-test: all zen-rust-runtime
	python3 ports/zen/rust/build_std_net_test.py
	python3 tests/rust_std_net_qemu_test.py

.PHONY: zen-rust-glyph-rasterizer-qemu-test
zen-rust-glyph-rasterizer-qemu-test: all
	$(MAKE) zen-rust-runtime
	$(MAKE) zen-gecko-configure
	python3 ports/zen/rust/build_glyph_rasterizer_test.py
	python3 ports/zen/rust/check_glyph_gecko.py
	python3 tests/rust_glyph_rasterizer_qemu_test.py

.PHONY: zen-rust-mtu-qemu-test
zen-rust-mtu-qemu-test: all
	$(MAKE) zen-rust-runtime
	$(MAKE) zen-gecko-configure
	python3 ports/zen/rust/build_mtu_test.py
	python3 tests/rust_mtu_qemu_test.py

.PHONY: zen-rust-socket2-qemu-test
zen-rust-socket2-qemu-test: all
	$(MAKE) zen-rust-runtime
	$(MAKE) zen-gecko-configure
	python3 ports/zen/rust/build_socket2_test.py
	python3 tests/rust_socket2_qemu_test.py

.PHONY: zen-rust-quinn-udp-qemu-test
zen-rust-quinn-udp-qemu-test: all
	$(MAKE) zen-rust-runtime
	$(MAKE) zen-gecko-configure
	python3 ports/zen/rust/build_quinn_udp_test.py
	python3 tests/rust_quinn_udp_qemu_test.py

.PHONY: zen-rust-neqo-udp-qemu-test
zen-rust-neqo-udp-qemu-test: all
	$(MAKE) zen-rust-runtime
	$(MAKE) zen-gecko-configure
	python3 ports/zen/rust/build_neqo_udp_test.py
	python3 tests/rust_neqo_udp_qemu_test.py

.PHONY: zen-rust-file-urls-test zen-rust-file-urls-qemu-test
# Keep std publication and configure sequential even when the caller uses -j.
zen-rust-file-urls-test:
	$(MAKE) zen-rust-runtime
	$(MAKE) zen-gecko-configure
	python3 ports/zen/rust/build_file_urls_test.py

zen-rust-file-urls-qemu-test: all
	$(MAKE) zen-rust-file-urls-test
	python3 tests/rust_file_urls_qemu_test.py

.PHONY: zen-rust-os-consumers-test zen-rust-os-consumers-qemu-test
zen-rust-os-consumers-test:
	$(MAKE) zen-rust-runtime
	$(MAKE) zen-gecko-configure
	python3 ports/zen/rust/build_os_consumers_test.py

zen-rust-os-consumers-qemu-test: all
	$(MAKE) zen-rust-os-consumers-test
	python3 tests/rust_os_consumers_qemu_test.py

.PHONY: zen-rust-directories-test zen-rust-directories-qemu-test
zen-rust-directories-test:
	$(MAKE) zen-rust-runtime
	$(MAKE) zen-gecko-configure
	python3 ports/zen/rust/build_directories_test.py

zen-rust-directories-qemu-test: all
	$(MAKE) zen-rust-directories-test
	python3 tests/rust_directories_qemu_test.py
