#!/usr/bin/env python3
"""Exercise WebRender's actual FreeType rasterizer in eight-CPU Alix."""
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    run_native_elf("rust_glyph_rasterizer_test.elf", (
        "RUST_GLYPH_RASTERIZER_TEST: PASS cpus=8 glyphs=512 freetype=1 mono=1 alpha=1 subpixel=1 variable=1 file_bytes=1 shared_faces=1",
    ), ROOT / "build/test-out/rust-glyph-rasterizer-qemu.log",
        "Native WebRender FreeType glyph rasterizer", 140,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
