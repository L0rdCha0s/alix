#!/usr/bin/env python3
"""Exercise the production scanner with real directories, symlinks and a FIFO."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "ports/zen/upstream/firefox-159.0/gfx/thebes"

with tempfile.TemporaryDirectory(prefix="alix-font-files-") as directory:
    directory = Path(directory)
    fonts = directory / "fonts"
    fonts.mkdir()
    nested = fonts / "folder.ttf"
    nested.mkdir()
    deepest = nested
    for _ in range(64):
        deepest = deepest / "d"
        deepest.mkdir()
    native_name = "résumé.ttc" if os.uname().sysname == "Darwin" else "bytes-\udcff.ttc"
    files = [fonts / "normal.ttf", nested / "upper.OTF", deepest / native_name]
    for path in files:
        path.write_bytes(b"font candidate")
    alias = fonts / "alias.woff"
    alias.symlink_to(files[0])
    (fonts / "cycle.ttf").symlink_to(fonts, target_is_directory=True)
    (fonts / "missing.ttf").symlink_to(fonts / "absent")
    os.mkfifo(fonts / "pipe.ttf")
    (fonts / "notes.txt").write_text("ignore")
    fixture = directory / "main.cpp"
    fixture.write_text(r'''
#include "AlixFontFiles.h"
#include <sys/resource.h>
#include <algorithm>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>
using Paths = std::vector<std::string>;
static void collect(const char* path, void* context) {
  static_cast<Paths*>(context)->push_back(path);
}
int main(int argc, char** argv) {
  if (argc != 2) return 1;
  auto limit = std::make_unique<rlimit>();
  if (getrlimit(RLIMIT_NOFILE, limit.get())) return 2;
  limit->rlim_cur = 16;
  if (setrlimit(RLIMIT_NOFILE, limit.get())) return 3;
  auto paths = std::make_unique<Paths>();
  for (unsigned round = 0; round < 64; ++round) {
    paths->clear();
    if (mozilla::gfx::EnumerateAlixFontFiles(argv[1], collect, paths.get()) != 4) return 4;
  }
  std::sort(paths->begin(), paths->end());
  for (const auto& path : *paths) std::puts(path.c_str());
  return 0;
}
''')
    binary = directory / "font-files"
    subprocess.run([*shlex.split(os.environ.get("HOST_CXX", "clang++")), "-std=c++20", "-Wall", "-Wextra", "-Werror",
                    "-I" + str(SOURCE), str(SOURCE / "AlixFontFiles.cpp"), str(fixture), "-o", str(binary)], check=True)
    output = subprocess.check_output([str(binary), str(fonts)], timeout=20)
    expected = sorted(os.fsencode(path) for path in [*files, alias])
    assert output.splitlines() == expected, "scanner lost native bytes, followed a directory cycle, or included a special file"
print("Production font scanner contracts PASS: depth=64 limited_fds=16 byte_paths=1 symlinks=1 fifo_skip=1")
