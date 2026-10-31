#!/usr/bin/env python3
"""Exercise checked Gecko patching on throwaway source subsets."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("patch_engine", ROOT / "ports/zen/patch_engine.py")
patcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patcher)


class PatchTests(unittest.TestCase):
    def setUp(self):
        parent = ROOT / "ports/zen/upstream"
        self.temp = tempfile.TemporaryDirectory(prefix=".patch-test-", dir=parent)
        self.addCleanup(self.temp.cleanup)
        self.engine = Path(self.temp.name) / "engine"
        self.engine.mkdir()
        self.package = ROOT / "ports/zen/patches"
        self.series = json.loads((self.package / "series.json").read_text())
        original = parent / "firefox-159.0"
        self.entry = self.series["patches"][0]
        for entry in self.series["patches"]:
            for item in entry["files"]:
                dest = self.engine / item["path"]
                dest.parent.mkdir(parents=True, exist_ok=True)
                if patcher.digest(original / item["path"]) is not None:
                    shutil.copyfile(original / item["path"], dest)
        version = self.engine / "browser/config/version.txt"
        version.parent.mkdir(parents=True, exist_ok=True)
        version.write_text(self.series["firefox_version"] + "\n")
        self.repository = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=ROOT, text=True).strip())
        self.prefix = str(self.engine.relative_to(self.repository))
        for entry in reversed(self.series["patches"]):
            if all(patcher.digest(self.engine / item["path"]) == item["after"] for item in entry["files"]):
                self.reverse_entry(entry)
            self.assertTrue(all(patcher.digest(self.engine / item["path"]) == item["before"]
                                for item in entry["files"]))

    def reverse_entry(self, entry):
        command = ["git", "apply", "--reverse", "--directory=" + self.prefix]
        patch = str(self.package / entry["file"])
        subprocess.run(command + ["--check", patch], cwd=self.repository, check=True)
        subprocess.run(command + [patch], cwd=self.repository, check=True)

    def snapshot(self):
        return {p.relative_to(self.engine): ("symlink", os.readlink(p)) if p.is_symlink() else p.read_bytes()
                for p in self.engine.rglob("*") if p.is_symlink() or p.is_file()}

    def added_source(self):
        for entry in self.series["patches"]:
            for item in entry["files"]:
                if item["before"] is None:
                    return entry, item
        self.fail("tracked series has no source-file addition fixture")

    def test_apply_and_repeat_preserve_unrelated_work(self):
        sentinel = self.engine / "local-work.txt"
        sentinel.write_text("keep this change\n")
        patcher.apply_patches(self.engine)
        after = self.snapshot()
        patcher.apply_patches(self.engine)
        self.assertEqual(after, self.snapshot())
        self.assertEqual(sentinel.read_text(), "keep this change\n")
        for entry in self.series["patches"]:
            for item in entry["files"]:
                self.assertEqual(patcher.digest(self.engine / item["path"]), item["after"])

    def test_added_file_absent_base_repeat_and_reverse(self):
        entry, item = self.added_source()
        target = self.engine / item["path"]
        self.assertFalse(target.exists())
        self.assertIsNone(patcher.digest(target))
        patcher.apply_patches(self.engine)
        self.assertEqual(patcher.digest(target), item["after"])
        after = self.snapshot()
        patcher.apply_patches(self.engine)
        self.assertEqual(after, self.snapshot())
        self.reverse_entry(entry)
        self.assertFalse(target.exists())
        for affected in entry["files"]:
            self.assertEqual(patcher.digest(self.engine / affected["path"]), affected["before"])
        patcher.apply_patches(self.engine)
        self.assertEqual(after, self.snapshot())

    def test_existing_content_at_added_path_is_preserved(self):
        _, item = self.added_source()
        target = self.engine / item["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("local implementation: preserve me\n")
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "unrecognized edits"):
            patcher.apply_patches(self.engine)
        self.assertEqual(before, self.snapshot())

    def test_symlink_at_added_path_is_rejected(self):
        _, item = self.added_source()
        target = self.engine / item["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        external = Path(self.temp.name) / "outside-source"
        external.write_text("external work\n")
        target.symlink_to(external)
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "symlink patch input"):
            patcher.apply_patches(self.engine)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(external.read_text(), "external work\n")
        external.unlink()
        # A dangling symlink must not be confused with a legitimately absent file.
        with self.assertRaisesRegex(RuntimeError, "symlink patch input"):
            patcher.apply_patches(self.engine)
        self.assertTrue(target.is_symlink())

    def test_nonregular_added_path_is_rejected(self):
        _, item = self.added_source()
        target = self.engine / item["path"]
        target.mkdir(parents=True)
        (target / "keep.txt").write_text("local directory\n")
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "non-regular patch input"):
            patcher.apply_patches(self.engine)
        self.assertEqual(before, self.snapshot())

    def test_unknown_file_edits_are_not_overwritten(self):
        target = self.engine / self.entry["files"][0]["path"]
        target.write_text(target.read_text() + "\n# local edit\n")
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "unrecognized edits"):
            patcher.apply_patches(self.engine)
        self.assertEqual(before, self.snapshot())

    def test_partial_patch_is_not_silently_completed(self):
        before = self.snapshot()
        patcher.apply_patches(self.engine)
        after = self.snapshot()
        # Restore the exact fixture bytes, then introduce one patched file.
        for path in after.keys() - before.keys():
            (self.engine / path).unlink()
        for path, data in before.items():
            (self.engine / path).write_bytes(data)
        item = self.entry["files"][0]
        (self.engine / item["path"]).write_bytes(after[Path(item["path"])])
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "partially applied"):
            patcher.apply_patches(self.engine)
        self.assertEqual(before, self.snapshot())

    def test_wrong_release_is_rejected(self):
        (self.engine / "browser/config/version.txt").write_text("0.0\n")
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "release does not match"):
            patcher.apply_patches(self.engine)
        self.assertEqual(before, self.snapshot())

    def test_changed_patch_is_rejected(self):
        package = Path(self.temp.name) / "patches"
        shutil.copytree(self.package, package)
        patch = package / self.entry["file"]
        patch.write_bytes(patch.read_bytes() + b"\n# altered\n")
        before = self.snapshot()
        with self.assertRaisesRegex(RuntimeError, "patch digest changed"):
            patcher.apply_patches(self.engine, package)
        self.assertEqual(before, self.snapshot())


if __name__ == "__main__":
    unittest.main()
