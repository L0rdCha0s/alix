.PHONY: zen-fetch-cxx zen-cxx-runtime
zen-fetch-cxx:
	python3 ports/zen/libcxx/fetch.py

zen-cxx-runtime: $(ZEN_USER_RUNTIME_OBJECTS) $(USER_LD_SCRIPT)
	ALIX_RUNTIME_OBJECTS="$(ZEN_USER_RUNTIME_OBJECTS)" python3 ports/zen/libcxx/build.py --smoke

.PHONY: zen-cxx-runtime-qemu-test
zen-cxx-runtime-qemu-test: all zen-cxx-runtime
	python3 tests/libcxx_runtime_qemu_test.py

.PHONY: libc-support-host-test
libc-support-host-test:
	python3 tests/libc_support_host_test.py
