#!/usr/bin/env python3
"""Build the native WebRender FreeType rasterizer with Gecko's toolchain."""
from gecko_fixture import run
import subprocess
import sys
from pathlib import Path

if __name__ == "__main__":
    if sys.argv[1:] != ["--configured"]:
        subprocess.run([sys.executable, str(Path(__file__).resolve().parents[1] /
                                            "build_freetype_library.py")], check=True)
    run("glyphs")
