#!/usr/bin/env python3
"""Check that configure's custom target is the exact spec passed to rustc."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "ports/zen/rust/rustc.py"
DEFAULT_SPEC = WRAPPER.with_name("x86_64-unknown-alix.json")


class RustWrapperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="alix rust wrapper ")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve()
        self.compiler = self.directory / "record compiler.py"
        self.compiler.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "print(json.dumps({'args': sys.argv[1:], "
            "'target_path': os.environ.get('RUST_TARGET_PATH')}))\n"
        )
        self.compiler.chmod(0o755)
        self.specification = self.directory / DEFAULT_SPEC.name
        self.specification.write_bytes(DEFAULT_SPEC.read_bytes())
        self.environment = os.environ.copy()
        self.environment.pop("RUST_TARGET_SPEC", None)
        self.environment["ALIX_REAL_RUSTC"] = str(self.compiler)
        self.environment["RUST_TARGET_PATH"] = "/unrelated/target/path"

    def run_wrapper(self, *arguments, specification=None):
        environment = self.environment.copy()
        if specification is not None:
            environment["RUST_TARGET_SPEC"] = str(specification)
        return subprocess.run([sys.executable, str(WRAPPER), *arguments],
                              cwd=self.directory, env=environment, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def result(self, *arguments, specification=None):
        process = self.run_wrapper(*arguments, specification=specification)
        self.assertEqual(process.returncode, 0, process.stderr)
        return json.loads(process.stdout)

    def test_default_alias_and_both_argument_spellings(self):
        for arguments in (("--target", "x86_64-unknown-alix"),
                          ("--target=x86_64-unknown-alix",)):
            with self.subTest(arguments=arguments):
                result = self.result(*arguments)
                self.assertTrue(any(str(DEFAULT_SPEC) in arg for arg in result["args"]))
                self.assertIn("-Zunstable-options", result["args"])

    def test_override_uses_the_validated_file_not_default_with_same_name(self):
        for arguments in (("--target", "x86_64-unknown-alix"),
                          ("--target=x86_64-unknown-alix",)):
            with self.subTest(arguments=arguments):
                result = self.result(*arguments, specification=self.specification)
                self.assertTrue(any(str(self.specification) in arg for arg in result["args"]))
                self.assertFalse(any(str(DEFAULT_SPEC) in arg for arg in result["args"]))
                self.assertEqual(result["target_path"], str(self.directory))

    def test_relative_override_is_canonicalized(self):
        result = self.result("--target=x86_64-unknown-alix", specification=DEFAULT_SPEC.name)
        self.assertIn("--target=" + str(self.specification), result["args"])

    def test_explicit_json_argument_is_not_replaced(self):
        for specification in (DEFAULT_SPEC, self.specification):
            with self.subTest(specification=specification):
                target = "--target=" + str(specification)
                result = self.result(target, specification=self.specification)
                self.assertIn(target, result["args"])
                self.assertIn("-Zunstable-options", result["args"])

    def test_missing_or_differently_named_specification_fails(self):
        wrong_name = self.directory / "different-alix.json"
        wrong_name.write_bytes(DEFAULT_SPEC.read_bytes())
        for specification in (self.directory / "missing" / DEFAULT_SPEC.name, wrong_name):
            with self.subTest(specification=specification):
                process = self.run_wrapper("--target=x86_64-unknown-alix",
                                           specification=specification)
                self.assertNotEqual(process.returncode, 0)
                self.assertEqual(process.stdout, "")
                self.assertIn("RUST_TARGET_SPEC must name an existing", process.stderr)

    def test_host_and_builtin_target_list_are_not_rewritten(self):
        for arguments in (("--print", "target-list"),
                          ("--target=aarch64-apple-darwin", "--print=cfg")):
            with self.subTest(arguments=arguments):
                result = self.result(*arguments, specification=self.specification)
                self.assertEqual(result["args"][2:], list(arguments))
                self.assertEqual(result["target_path"], "/unrelated/target/path")


if __name__ == "__main__":
    unittest.main()
