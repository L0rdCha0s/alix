#!/usr/bin/env python3
"""Link real configured NSPR resource functions into a native component fixture."""
import hashlib
import json
from pathlib import Path
import shlex
import subprocess

ROOT = Path(__file__).resolve().parents[2]

def main():
    commands = json.loads((ROOT / "ports/zen/upstream/obj-gecko-alix/clangd/compile_commands.json").read_text())
    sources = ["md/unix/uxrng.c", "md/unix/unix_errors.c", "misc/prrng.c", "misc/prsystem.c"]
    output = ROOT / "build/ports/zen/nspr-resources"
    output.mkdir(parents=True, exist_ok=True)
    objects, receipts = [], []
    for relative in sources + ["fixture"]:
        match = "misc/prrng.c" if relative == "fixture" else relative
        entry = next(item for item in commands if item["file"].endswith("/nsprpub/pr/src/" + match))
        argv = list(entry.get("arguments") or shlex.split(entry["command"]))
        source = ROOT / "tests/nspr_resources_test.c" if relative == "fixture" else Path(entry["file"])
        obj = output / (Path(relative).stem + ".o")
        argv[argv.index("-o") + 1] = str(obj)
        argv[argv.index(entry["file"])] = str(source)
        # This component fixture must reach unavailable-entropy handling on a
        # CPU without RDRAND. Production SSP aborts before main on that CPU.
        # Production flags remain unchanged and are covered by the source audit.
        argv.append("-fno-stack-protector")
        subprocess.run(argv, cwd=entry["directory"], check=True)
        objects.append(str(obj))
        receipts.append({"source": str(source.relative_to(ROOT)),
                         "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                         "command": argv})
    elf = ROOT / "build/user/nspr_resources_test.elf"
    subprocess.run([str(ROOT / "ports/zen/toolchain/alix-clang"), *objects,
                    "-Wl,--gc-sections", "-o", str(elf)], cwd=ROOT, check=True)
    symbols = subprocess.check_output(["x86_64-elf-nm", str(elf)], text=True)
    if "__stack_chk_guard" in symbols:
        raise RuntimeError("unavailable-entropy fixture unexpectedly links SSP preinit")
    if subprocess.check_output(["x86_64-elf-nm", "-u", str(elf)], text=True).strip():
        raise RuntimeError("native NSPR resource fixture has unresolved symbols")
    (output / "link.json").write_text(json.dumps({
        "scope": "Whole upstream resource objects; instrumented per-thread PR_SetError sink; no full NSPR startup",
        "test_override": "-fno-stack-protector to reach unavailable-entropy handling; production flags unchanged",
        "objects": receipts, "elf_sha256": hashlib.sha256(elf.read_bytes()).hexdigest(),
    }, indent=2) + "\n")
    print("Native NSPR resource functions compiled and linked:", elf)

if __name__ == "__main__":
    main()
