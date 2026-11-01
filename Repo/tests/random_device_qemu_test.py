#!/usr/bin/env python3
"""Verify real libc++ randomness and its native failure paths in Alix."""
import hashlib
import json

from cpp_runtime_qemu_test import ROOT, run_native_elf


def verify_receipts():
    paths = [ROOT / ("build/test-out/" + name) for name in (
        "cxx-random-native-qemu.log", "cxx-random-unsupported-qemu.log", "cxx-random-invalid-token-qemu.log")]
    if 'error 38 and message "random_device getentropy failed"' not in paths[1].read_text():
        raise RuntimeError("libc++ did not report the native ENOSYS entropy failure")
    if 'error 2 and message "random device not supported alix-invalid-random-token"' not in paths[2].read_text():
        raise RuntimeError("libc++ did not reject the unsupported token with ENOENT")
    binary = ROOT / "build/user/random_device_test.elf"
    binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
    images = [json.loads(path.with_suffix(".boot-image.json").read_text()) for path in paths]
    if any(item["user_sha256"] != binary_hash for item in images):
        raise RuntimeError("random-device guest receipts do not match the current native executable")
    receipt = {
        "scope": "Upstream libc++ random_device in Alix; complete Gecko and Zen remain unverified",
        "cpus": 8, "samples": 4096, "minimum_unique_samples": 4090,
        "descriptor_exhaustion": True, "entropy_backend": "native getentropy",
        "unavailable_entropy_errno": 38, "invalid_token_errno": 2,
        "failure_policy": "existing no-exceptions libc++ abort, caught only by the QA fixture",
        "user_sha256": binary_hash, "boot_images": images,
        "logs": [str(path.relative_to(ROOT)) for path in paths],
    }
    paths[0].with_suffix(".acceptance.json").write_text(json.dumps(receipt, indent=2) + "\n")


def main():
    run_native_elf("random_device_test.elf",
        ("CPP_RANDOM_TEST: PASS cpus=8 samples=4096 fd_pressure=1",),
        ROOT / "build/test-out/cxx-random-native-qemu.log", "native libc++ random_device", 65,
        tcg_cpu="qemu64,+rdrand", expected_wait_status=0, fail_on_missing_markers_at_exit=True)
    run_native_elf("random_device_test.elf",
        ("random_device getentropy failed", "CPP_RANDOM_TEST: unsupported PASS"),
        ROOT / "build/test-out/cxx-random-unsupported-qemu.log", "libc++ unavailable entropy", 60,
        arguments=("unsupported",), tcg_cpu="qemu64,-rdrand", expected_wait_status=0,
        fail_on_missing_markers_at_exit=True)
    run_native_elf("random_device_test.elf",
        ("random device not supported alix-invalid-random-token", "CPP_RANDOM_TEST: invalid_token PASS"),
        ROOT / "build/test-out/cxx-random-invalid-token-qemu.log", "libc++ invalid entropy token", 60,
        arguments=("invalid",), tcg_cpu="qemu64,+rdrand", expected_wait_status=0,
        fail_on_missing_markers_at_exit=True)
    verify_receipts()


if __name__ == "__main__":
    main()
