#!/usr/bin/env python3
"""Create a new dedicated Alix swap image; existing paths are never overwritten."""
import argparse
from pathlib import Path
import struct

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("path", type=Path)
parser.add_argument("--size-mib", type=int, default=256)
args = parser.parse_args()
if not 16 <= args.size_mib <= 65536:
    parser.error("size must be between 16 and 65536 MiB")
size = args.size_mib * 1024 * 1024
with args.path.open("xb") as image:
    image.truncate(size)
    image.write(struct.pack("<8sQ", b"ALIXSWP1", size // 4096 - 1))
print(f"Created {args.path}: {args.size_mib} MiB dedicated Alix swap")
