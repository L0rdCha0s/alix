#!/usr/bin/env python3
from cpp_runtime_qemu_test import ROOT, run_native_elf

if __name__ == "__main__":
    source = ROOT / "ports/zen/upstream/firefox-159.0"
    run_native_elf("alix_font_files_test.elf",
        ("ALIX_FONT_FILES_TEST: PASS cpus=8 depth=32 candidates=32 valid_faces=24 invalid=8 freetype=1 harfbuzz_ligatures=1 byte_paths=1",),
        ROOT / "build/test-out/alix-font-files-qemu.log", "Native Alix font discovery and shaping", 160,
        input_files=(("font-sans.ttf", source / "layout/reftests/fonts/dejavu-sans/DejaVuSans.ttf"),
                     ("font-serif.ttf", source / "mobile/android/fonts/CharisSILCompact-R.ttf"),
                     ("font-mono.ttf", source / "gfx/wr/wrshell/res/FiraCode-Regular.ttf")),
        expected_wait_status=0, fail_on_missing_markers_at_exit=True)
