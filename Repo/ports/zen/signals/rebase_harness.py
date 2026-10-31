#!/usr/bin/env python3
"""Preserve the current active harness and add exact pending signal evidence."""
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
text=(ROOT/'tests/cpp_runtime_qemu_test.py').read_text()
old='forbidden_markers=(), download_timeout_seconds=10, boot_markers=()):'
assert text.count(old)==1
text=text.replace(old,'forbidden_markers=(), download_timeout_seconds=10, boot_markers=(),\n                   expected_exception=None, expected_signal_termination=None):')
helpers=(HERE/'harness_support.py').read_text()
helpers=helpers[helpers.index('def native_elf_symbol('):]
anchor='def capture_guest_failure('
assert text.count(anchor)==1;text=text.replace(anchor,helpers+'\n\n'+anchor)
old='            if expected_fault is None:\n'
new='''            if expected_signal_termination is not None:
                verify_signal_termination(phase, binary, expected_signal_termination)
            if expected_exception is not None:
                verify_expected_user_exception(phase, binary, expected_exception)
                recovered = len(harness.read_log())
                command("echo fault_recovered")
                harness.wait_for(runner, "shell responds after expected user exception",
                    lambda text: re.search(r"(?:^|\\n)fault_recovered\\r?\\n", text[recovered:]), 5)
            elif expected_fault is None:
'''
assert text.count(old)==1;text=text.replace(old,new)
(HERE/'pending/tests/cpp_runtime_qemu_test.py').write_text(text)
print('Pending signal harness rebased onto current active boot/failure diagnostics')
