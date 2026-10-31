#!/usr/bin/env python3
"""Fetch the pinned upstream C++ runtime sources without executing their code."""
import json
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
DESTINATION = HERE.parent / "upstream/llvm-project-22.1.8"

def git(*args, cwd=None):
    return subprocess.check_output(["git", *map(str, args)], cwd=cwd, text=True).strip()

def verify(directory, manifest):
    if not (directory / ".git").is_dir() or Path(git("rev-parse", "--show-toplevel", cwd=directory)).resolve() != directory.resolve():
        raise RuntimeError("LLVM source path is not its own checkout; left untouched")
    if git("remote", "get-url", "origin", cwd=directory) != manifest["repository"]:
        raise RuntimeError("LLVM source origin differs from the pin; left untouched")
    if git("rev-parse", "HEAD", cwd=directory) != manifest["revision"]:
        raise RuntimeError("LLVM source revision differs from the pin; left untouched")
    for path in manifest["sparse_paths"]:
        if not (directory / path).is_dir():
            raise RuntimeError(f"LLVM source lacks required directory {path}; left untouched")

def main():
    manifest = json.loads((HERE / "upstream.json").read_text())
    if DESTINATION.exists() or DESTINATION.is_symlink():
        verify(DESTINATION, manifest)
        print(f"LLVM base revision verified: {DESTINATION}")
        print("Existing port patches and local source modifications were preserved.")
        return
    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".llvm-fetch-", dir=DESTINATION.parent) as temp:
        checkout = Path(temp) / "llvm-project"
        git("clone", "--filter=blob:none", "--depth=1", "--branch", manifest["tag"],
            "--sparse", manifest["repository"], checkout)
        git("sparse-checkout", "set", *manifest["sparse_paths"], cwd=checkout)
        verify(checkout, manifest)
        if DESTINATION.exists() or DESTINATION.is_symlink():
            raise RuntimeError("LLVM destination appeared during fetch; left untouched")
        checkout.rename(DESTINATION)
    print(f"Pinned LLVM runtime source ready: {DESTINATION}")

if __name__ == "__main__":
    main()
