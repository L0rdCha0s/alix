#!/usr/bin/env python3
"""Stage the native process-uptime ABI without overwriting active integration."""
from pathlib import Path
import difflib
import hashlib
import json
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
OUTPUT = ROOT / "build/ports/zen/process-uptime"

def replace(text, old, new):
    if text.count(old) != 1: raise RuntimeError("source context changed: " + old[:100])
    return text.replace(old, new, 1)

def main():
    edits = {}
    def update(name, old, new):
        before = (ROOT / name).read_text()
        edits[name] = (before, replace(before, old, new))
    update("include/process_internal.h", "struct process\n{\n    uint64_t pid;",
           "struct process\n{\n    uint64_t pid;\n    uint64_t started_monotonic_ticks; /* Immutable creation timestamp. */")
    update("src/kernel/process/process_memory.c", "    proc->state = PROCESS_STATE_READY;",
           "    proc->started_monotonic_ticks = timer_ticks();\n    proc->state = PROCESS_STATE_READY;")
    update("include/process.h", "uint64_t process_current_pid(void);",
           "uint64_t process_current_pid(void);\nuint64_t process_current_uptime_ns(void);")
    update("include/syscall_defs.h", "} syscall_id_t;",
           "    SYSCALL_PROCESS_UPTIME_NS = 68,\n} syscall_id_t;")
    update("user/lib/usyscall.h", "uint64_t sys_monotonic_millis(void);",
           "uint64_t sys_monotonic_millis(void);\nuint64_t sys_process_uptime_ns(void);")
    update("user/lib/syscall.c", "uint64_t sys_monotonic_millis(void)",
           "uint64_t sys_process_uptime_ns(void)\n{\n    return (uint64_t)syscall0(SYSCALL_PROCESS_UPTIME_NS);\n}\n\nuint64_t sys_monotonic_millis(void)")
    update("src/kernel/syscall.c", "        case SYSCALL_GETPID:",
           "        case SYSCALL_PROCESS_UPTIME_NS:\n            result = (int64_t)process_current_uptime_ns();\n            break;\n        case SYSCALL_GETPID:")
    module = "src/kernel/process/process_uptime.c"
    if (ROOT / module).exists(): raise RuntimeError("uptime module already integrated")
    edits[module] = (None, (HERE / "process_uptime.c").read_text())
    name = "tests/process_pid_test.py"
    before = (ROOT / name).read_text()
    after = replace(before,
        "typedef struct { uint64_t pid; unsigned state, lifetime_state; } process_t;",
        "typedef struct { uint64_t pid, started_monotonic_ticks; unsigned state, lifetime_state; } process_t;\nstatic uint64_t timer_ticks(void) { return 123456; }")
    after = replace(after, "    CHECK(process && process->pid == PID_MAXIMUM);",
        "    CHECK(process && process->pid == PID_MAXIMUM);\n    CHECK(process->started_monotonic_ticks == 123456);")
    edits[name] = (before, after)
    patch = []; manifest = []
    for name, (before, after) in edits.items():
        destination = OUTPUT / "pending" / name
        destination.parent.mkdir(parents=True, exist_ok=True); destination.write_text(after)
        patch += ["diff --git a/" + name + " b/" + name + "\n"]
        if before is None: patch += ["new file mode 100644\n"]
        patch += difflib.unified_diff((before or "").splitlines(True), after.splitlines(True),
                                     fromfile="a/" + name if before is not None else "/dev/null", tofile="b/" + name)
        sha = lambda text: hashlib.sha256(text.encode()).hexdigest() if text is not None else None
        manifest.append({"path": name, "before": sha(before), "after": sha(after)})
    (OUTPUT / "process-uptime.patch").write_text("".join(patch))
    (OUTPUT / "manifest.json").write_text(json.dumps({"applied": False, "files": manifest}, indent=2) + "\n")
    repository = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=ROOT, text=True).strip())
    prefix = str(ROOT.relative_to(repository))
    subprocess.run(["git", "apply", "--check", "--directory=" + prefix,
                    str(OUTPUT / "process-uptime.patch")], cwd=repository, check=True)
    print(f"Staged {len(edits)} native uptime files: {OUTPUT}")

if __name__ == "__main__": main()
