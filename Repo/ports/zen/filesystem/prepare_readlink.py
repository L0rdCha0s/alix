#!/usr/bin/env python3
"""Stage public readlink atop the separately owned native syscall 66 bridge."""
from pathlib import Path
import difflib
import hashlib
import json
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OUTPUT = ROOT / "build/ports/zen/readlink-posix"

def change(text, old, new):
    if text.count(old) != 1: raise RuntimeError("source context changed: " + old)
    return text.replace(old, new, 1)

def main():
    changes = {}
    name = "include/unistd.h"; before = (ROOT / name).read_text()
    changes[name] = (before, change(before, "int unlink(const char *path);",
        "int unlink(const char *path);\nssize_t readlink(const char *path, char *buffer, size_t capacity);"))
    name = "Makefile"; before = (ROOT / name).read_text()
    changes[name] = (before, change(before, "\t$(USER_DIR)/lib/process_posix.c \\\n",
        "\t$(USER_DIR)/lib/process_posix.c \\\n\t$(USER_DIR)/lib/filesystem_posix.c \\\n"))
    name = "user/lib/filesystem_posix.c"
    if (ROOT / name).exists(): raise RuntimeError("filesystem wrapper is already integrated")
    changes[name] = (None, (HERE / "filesystem_posix.c").read_text())
    patches = []; entries = []
    digest = lambda text: hashlib.sha256(text.encode()).hexdigest() if text is not None else None
    for name, (before, after) in changes.items():
        path = OUTPUT / "pending" / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(after)
        patches.append(f"diff --git a/{name} b/{name}\n")
        if before is None: patches.append("new file mode 100644\n")
        patches.extend(difflib.unified_diff((before or "").splitlines(True), after.splitlines(True),
                       fromfile=f"a/{name}" if before is not None else "/dev/null", tofile=f"b/{name}"))
        entries.append({"path": name, "before": digest(before), "after": digest(after)})
    (OUTPUT / "readlink-posix.patch").write_text("".join(patches))
    (OUTPUT / "manifest.json").write_text(json.dumps({"applied": False, "requires_syscall": 66, "files": entries}, indent=2) + "\n")
    repository = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=ROOT, text=True).strip())
    prefix = str(ROOT.relative_to(repository))
    subprocess.run(["git", "apply", "--check", "--directory=" + prefix,
                    str(OUTPUT / "readlink-posix.patch")], cwd=repository, check=True)
    print(f"Staged public readlink declaration, wrapper and build registration: {OUTPUT}")

if __name__ == "__main__": main()
