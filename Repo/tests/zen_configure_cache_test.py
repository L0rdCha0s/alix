#!/usr/bin/env python3
"""Verify native SDK changes invalidate real probes while preserving history."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("configure_cache", ROOT / "ports/zen/configure_cache.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="alix-configure-cache-")
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.objects = root / "objects"
        self.objects.mkdir()
        self.state = root / "state"
        self.header = root / "native.h"
        self.object = root / "native.o"
        self.header.write_bytes(b"header v1")
        self.object.write_bytes(b"object v1")
        self.cache = self.objects / "configure.cache"
        self.cache.write_bytes(b"real previous compiler results")

    def refresh(self, inputs=None):
        return module.refresh_compiler_cache(self.objects, self.state,
                                             inputs if inputs is not None else [self.header, self.object])

    def test_first_refresh_archives_and_repeat_preserves_cache(self):
        revision = self.refresh()
        self.assertFalse(self.cache.exists())
        history = list((self.state / "configure-cache-history").iterdir())
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].read_bytes(), b"real previous compiler results")
        self.cache.write_bytes(b"fresh real probes")
        self.assertEqual(self.refresh([self.object, self.header, self.object]), revision)
        self.assertEqual(self.cache.read_bytes(), b"fresh real probes")
        self.assertEqual(list((self.state / "configure-cache-history").iterdir()), history)

    def test_same_size_same_timestamp_content_change_invalidates(self):
        original = self.refresh()
        for path in (self.header, self.object):
            before = path.stat()
            path.write_bytes(path.read_bytes().replace(b"v1", b"v2"))
            os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
            self.cache.write_bytes(b"old probes remain preserved")
            updated = self.refresh()
            self.assertNotEqual(updated, original)
            self.assertFalse(self.cache.exists())
            original = updated
        self.assertEqual(len(list((self.state / "configure-cache-history").iterdir())), 3)

    def test_missing_input_changes_nothing(self):
        with self.assertRaises(FileNotFoundError):
            self.refresh([self.header, self.object.with_name("missing.o")])
        self.assertEqual(self.cache.read_bytes(), b"real previous compiler results")
        self.assertFalse(self.state.exists())

    def test_absent_cache_and_resolved_input_symlink(self):
        self.cache.unlink()
        alias = self.header.with_name("alias.h")
        alias.symlink_to(self.header)
        self.assertEqual(self.refresh([alias, self.object]), self.refresh())
        self.assertFalse((self.state / "configure-cache-history").exists())

    def test_nonregular_cache_is_not_replaced(self):
        self.cache.unlink()
        self.cache.mkdir()
        with self.assertRaisesRegex(RuntimeError, "not a regular file"):
            self.refresh()
        self.assertTrue(self.cache.is_dir())
        self.assertFalse(self.state.exists())


if __name__ == "__main__":
    unittest.main()
