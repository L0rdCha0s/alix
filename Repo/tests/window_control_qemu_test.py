#!/usr/bin/env python3
"""Exercise actual native window controls and inspect real compositor output."""
import json
import hashlib
import subprocess
from cpp_runtime_qemu_test import ROOT, run_native_elf
from quake_gui_liveness_test import ppm_pixels


if __name__ == "__main__":
    binary = ROOT / "build/user/window_control_test.elf"
    screenshot = ROOT / "build/test-out/window-control-native.ppm"
    screenshot.unlink(missing_ok=True)
    run_native_elf(binary.name,
        ("UI_CONTROL_TEST: SMP PASS cpus=8 presents=128 resize=12", "UI_CONTROL_TEST: OWNERSHIP PASS",
         "UI_CONTROL_TEST: RAW_KEYS PASS arrow_down=1 arrow_up=1 ansi=0",
         "UI_CONTROL_TEST: PASS bounds=1 visibility=1 focus=1 title=1 chrome=1 cpus=8 ownership=1 close_race=1"),
        ROOT / "build/test-out/window-control-native-qemu.log", "native window controls", 90,
        expected_wait_status=0, fail_on_missing_markers_at_exit=True, gui_launch=True,
        user_breakpoint=("window_control_visual_checkpoint", binary,
            ("monitor screendump " + str(screenshot),)),
        after_breakpoint_commands=("sendkey left 80",))
    width, height, pixels = ppm_pixels(screenshot)
    probes = ((80, 120, (208, 48, 32)), (440, 300, (32, 64, 192)), (640, 160, (32, 176, 64)))
    for x, y, expected in probes:
        offset = (y * width + x) * 3
        actual = tuple(pixels[offset:offset + 3])
        if actual != expected:
            raise RuntimeError(f"native compositor pixel {(x, y)} was {actual}, expected {expected}")
    boot = json.loads((ROOT / "build/test-out/window-control-native-qemu.boot-image.json").read_text())
    if boot["user_sha256"] != hashlib.sha256(binary.read_bytes()).hexdigest():
        raise RuntimeError("window fixture changed during acceptance")
    screenshot.with_suffix(".analysis.json").write_text(json.dumps({"width": width, "height": height,
        "verified_pixels": probes, "boot_images": boot, "wait_status": 0, "cpus": 8,
        "capture_sha256": hashlib.sha256(screenshot.read_bytes()).hexdigest(),
        "scope": "Native Alix UI controls and surfaces; Gecko and Zen remain unverified"}, indent=2) + "\n")
    subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-i", str(screenshot),
                    "-frames:v", "1", str(screenshot.with_suffix(".png"))], check=True)
    print("Real compositor contains both native window surfaces: PASS")
