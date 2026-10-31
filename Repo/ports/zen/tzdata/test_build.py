#!/usr/bin/env python3
"""Offline identity and preservation checks for the pinned IANA builder."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest
import sys

sys.dont_write_bytecode=True

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location("alix_tz_builder",HERE/"build.py")
builder=importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

class SourceContracts(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(prefix="alix-tz-source-")
        self.cache=Path(self.directory.name).resolve()
        (self.cache/"downloads").mkdir()
        for archive in builder.PIN["archives"]:
            shutil.copyfile(builder.DEFAULT_CACHE/"downloads"/archive["file"],self.cache/"downloads"/archive["file"])

    def tearDown(self): self.directory.cleanup()

    def test_pristine_repeat(self):
        source,expected=builder.sources(self.cache,False)
        builder.sources(self.cache,False)
        self.assertEqual((source/"version").read_text().strip(),builder.PIN["release"])
        self.assertTrue(all((source/name).read_bytes()==data for name,data in expected.items()))

    def test_modified_source_preserved(self):
        source,_=builder.sources(self.cache,False)
        path=source/"zic.c";path.write_bytes(b"local change")
        with self.assertRaises(RuntimeError): builder.sources(self.cache,False)
        self.assertEqual(path.read_bytes(),b"local change")

    def test_unknown_file_preserved(self):
        source,_=builder.sources(self.cache,False)
        path=source/"local-note";path.write_text("keep")
        with self.assertRaises(RuntimeError): builder.sources(self.cache,False)
        self.assertEqual(path.read_text(),"keep")

    def test_wrong_archive_rejected(self):
        path=self.cache/"downloads"/builder.PIN["archives"][0]["file"]
        data=bytearray(path.read_bytes());data[-1]^=1;path.write_bytes(data)
        with self.assertRaises(RuntimeError): builder.sources(self.cache,False)
        self.assertFalse((self.cache/"source").exists())

    def test_missing_source_never_substituted(self):
        (self.cache/"downloads"/builder.PIN["archives"][0]["file"]).unlink()
        with self.assertRaisesRegex(RuntimeError,"missing pinned source"): builder.sources(self.cache,False)

    def test_path_and_symlink_preservation(self):
        for path in ("../x","/x","x//y","x/../y","x/./y","x/","x\\y"):
            self.assertFalse(builder.safe_name(path))
        outside=self.cache/"keep";outside.write_text("keep")
        link=self.cache/"link";link.symlink_to(outside)
        with self.assertRaises(RuntimeError): builder.write_preserving(link,b"replace")
        self.assertEqual(outside.read_text(),"keep")

if __name__=="__main__": unittest.main()
