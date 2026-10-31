#!/usr/bin/env python3
"""Exercise pinned source acquisition against a tiny, offline Git repository."""

import importlib.util
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("zen_prepare", ROOT / "ports/zen/prepare.py")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class ZenSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="alix-zen-source-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.upstream = self.root / "upstream"
        self.upstream.mkdir()
        prepare.run("git", "init", "--quiet", str(self.upstream))
        (self.upstream / "LICENSE").write_text("test fixture license\n")
        (self.upstream / "surfer.json").write_text(json.dumps({
            "version": {"version": "159.0"},
            "brands": {"release": {"release": {"displayVersion": "1.24b"}}},
        }))
        prepare.run("git", "add", ".", cwd=self.upstream)
        prepare.run("git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                    "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture", cwd=self.upstream)
        self.manifest = {
            "repository": str(self.upstream),
            "revision": prepare.run("git", "rev-parse", "HEAD", cwd=self.upstream),
            "release": "1.24b", "firefox_version": "159.0",
        }
        self.destination = self.root / "destination"

    def test_fetch_pin_and_idempotence(self):
        prepare.fetch_source(self.destination, self.manifest)
        prepare.verify_source(self.destination, self.manifest)
        head = (self.destination / ".git/HEAD").read_bytes()
        prepare.fetch_source(self.destination, self.manifest)
        self.assertEqual(head, (self.destination / ".git/HEAD").read_bytes())

    def test_dirty_checkout_is_preserved(self):
        prepare.fetch_source(self.destination, self.manifest)
        changed = self.destination / "LICENSE"
        changed.write_text("local work\n")
        with self.assertRaisesRegex(RuntimeError, "local changes"):
            prepare.fetch_source(self.destination, self.manifest)
        self.assertEqual(changed.read_text(), "local work\n")

    def test_existing_nonrepo_is_preserved(self):
        self.destination.mkdir()
        sentinel = self.destination / "keep"
        sentinel.write_text("existing data\n")
        with self.assertRaisesRegex(RuntimeError, "dedicated Zen Git checkout"):
            prepare.fetch_source(self.destination, self.manifest)
        self.assertEqual(sentinel.read_text(), "existing data\n")

    def test_wrong_release_is_not_published(self):
        self.manifest["firefox_version"] = "0.0"
        with self.assertRaisesRegex(RuntimeError, "Firefox version"):
            prepare.fetch_source(self.destination, self.manifest)
        self.assertFalse(self.destination.exists())

    def test_wrong_revision_is_preserved(self):
        prepare.fetch_source(self.destination, self.manifest)
        head = prepare.run("git", "rev-parse", "HEAD", cwd=self.destination)
        self.manifest["revision"] = "0" * 40
        with self.assertRaisesRegex(RuntimeError, "revision does not match"):
            prepare.fetch_source(self.destination, self.manifest)
        self.assertEqual(head, prepare.run("git", "rev-parse", "HEAD", cwd=self.destination))


class FirefoxSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="alix-firefox-source-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.original = self.root / "original"
        self.original.mkdir()
        for name, content in {
            "LICENSE": "fixture license\n", "mach": "#!/usr/bin/env python3\n",
            "browser/config/version.txt": "159.0\n",
            "build/moz.configure/init.configure": "# fixture\n",
        }.items():
            path = self.original / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        (self.original / "mach").chmod(0o755)
        (self.original / "license-link").symlink_to("LICENSE")
        self.archive = self.root / "firefox-159.0.source.tar.xz"
        self.destination = self.root / "engine"
        self.manifest = {"firefox_version": "159.0", "firefox_revision": "a" * 40,
                         "firefox_source_url": "https://example.invalid/never-download"}
        self.write_archive()

    def write_archive(self, additional=None, container_root=False):
        with tarfile.open(self.archive, "w:xz") as package:
            if container_root:
                root = tarfile.TarInfo(".")
                root.type = tarfile.DIRTYPE
                package.addfile(root)
            package.add(self.original, arcname="firefox-159.0")
            if additional:
                package.addfile(additional, io.BytesIO(b"x") if additional.isfile() else None)
        self.manifest["firefox_source_sha512"] = hashlib.sha512(self.archive.read_bytes()).hexdigest()

    def fetch(self):
        prepare.fetch_engine(self.destination, self.archive, self.manifest)

    def test_extract_and_verify_cached_source(self):
        self.fetch()
        self.assertEqual((self.destination / "LICENSE").read_text(), "fixture license\n")
        self.assertTrue((self.destination / "license-link").is_symlink())
        self.fetch()

    def test_mozilla_archive_container_root(self):
        self.write_archive(container_root=True)
        self.fetch()
        self.fetch()
        self.assertEqual((self.destination / "LICENSE").read_text(), "fixture license\n")

    def test_corrupt_cache_is_rejected_without_touching_source(self):
        self.destination.mkdir()
        keep = self.destination / "keep"
        keep.write_text("local work\n")
        self.archive.write_bytes(b"corrupt")
        with self.assertRaisesRegex(RuntimeError, "SHA-512 mismatch"):
            self.fetch()
        self.assertEqual(keep.read_text(), "local work\n")
        self.assertEqual(self.archive.read_bytes(), b"corrupt")

    def test_changed_source_is_preserved(self):
        self.fetch()
        path = self.destination / "LICENSE"
        path.write_text("modified\n")
        with self.assertRaisesRegex(RuntimeError, "differs from verified archive"):
            self.fetch()
        self.assertEqual(path.read_text(), "modified\n")

    def test_added_source_file_is_reported(self):
        self.fetch()
        path = self.destination / "local-patch"
        path.write_text("local work\n")
        with self.assertRaisesRegex(RuntimeError, "added/missing paths"):
            self.fetch()
        self.assertEqual(path.read_text(), "local work\n")

    def test_partial_download_is_preserved(self):
        self.archive.unlink()
        partial = self.archive.with_suffix(".xz.partial")
        partial.write_bytes(b"unfinished download")
        with self.assertRaisesRegex(RuntimeError, "existing .partial"):
            self.fetch()
        self.assertEqual(partial.read_bytes(), b"unfinished download")
        self.assertFalse(self.destination.exists())

    def test_archive_path_escape_is_rejected(self):
        escape = tarfile.TarInfo("firefox-159.0/../../escape")
        escape.size = 1
        self.write_archive(escape)
        with self.assertRaisesRegex(RuntimeError, "unsafe Firefox archive member"):
            self.fetch()
        self.assertFalse((self.root / "escape").exists())
        self.assertFalse(self.destination.exists())

    def test_archive_symlink_escape_is_rejected(self):
        escape = tarfile.TarInfo("firefox-159.0/escape")
        escape.type = tarfile.SYMTYPE
        escape.linkname = "../../escape"
        self.write_archive(escape)
        with self.assertRaisesRegex(RuntimeError, "unsafe Firefox archive link"):
            self.fetch()
        self.assertFalse(self.destination.exists())

    def test_wrong_release_is_not_published(self):
        (self.original / "browser/config/version.txt").write_text("0.0\n")
        self.write_archive()
        with self.assertRaisesRegex(RuntimeError, "release metadata differs"):
            self.fetch()
        self.assertFalse(self.destination.exists())

    def test_existing_unverified_directory_is_preserved(self):
        self.destination.mkdir()
        keep = self.destination / "keep"
        keep.write_text("existing work\n")
        with self.assertRaisesRegex(RuntimeError, "differs from verified archive"):
            self.fetch()
        self.assertEqual(keep.read_text(), "existing work\n")

    def test_normalized_internal_symlink_verifies(self):
        (self.original / "normalized-link").symlink_to("build/../LICENSE")
        self.write_archive()
        self.fetch()
        self.fetch()
        self.assertEqual((self.destination / "normalized-link").read_text(), "fixture license\n")


if __name__ == "__main__":
    unittest.main()
