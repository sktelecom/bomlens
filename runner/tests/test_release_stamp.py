# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""tools/stamp_release.py: the values the release workflow writes into _release.py."""

import contextlib
import importlib.util
import io
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

RUNNER = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(RUNNER / "src"))
SPEC = importlib.util.spec_from_file_location("stamp_release", RUNNER / "tools" / "stamp_release.py")
stamp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(stamp)

DIGEST = "sha256:" + "a" * 64
ENGINE = f"ghcr.io/sktelecom/bomlens:1.16.0@{DIGEST}"
LICENSE = f"ghcr.io/sktelecom/bomlens-deep-license:1.16.0@{DIGEST}"
CVE = f"ghcr.io/sktelecom/bomlens-deep-cve:1.16.0@{DIGEST}"


class StampRelease(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.file = self.dir / "_release.py"
        shutil.copy(RUNNER / "src" / "bomlens_runner" / "_release.py", self.file)

    def run_stamp(self, *argv):
        with contextlib.redirect_stderr(io.StringIO()):
            return stamp.main([*argv, "--file", str(self.file)])

    def load(self):
        spec = importlib.util.spec_from_file_location("stamped", self.file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_writes_the_version_and_images(self):
        self.assertEqual(self.run_stamp("1.16.0", ENGINE, LICENSE, CVE), 0)
        stamped = self.load()
        self.assertEqual(stamped.VERSION, "1.16.0")
        self.assertEqual((stamped.ENGINE_IMAGE, stamped.DEEP_LICENSE_IMAGE, stamped.DEEP_CVE_IMAGE),
                         (ENGINE, LICENSE, CVE))
        self.assertTrue(self.file.read_text().startswith("# Copyright"))

    def test_optional_images_may_be_left_out(self):
        self.assertEqual(self.run_stamp("1.16.0", ENGINE), 0)
        self.assertEqual(self.load().DEEP_CVE_IMAGE, "")

    def test_refuses_bad_values(self):
        for argv in (("1.16.0-rc.1", ENGINE), ("1.16.0", "ghcr.io/sktelecom/bomlens:1.16.0"),
                     ("1.16.0", f"ghcr.io/sktelecom/bomlens:latest@{DIGEST}"),
                     ("1.16.0", f"ghcr.io/sktelecom/bomlens:1.15.0@{DIGEST}"),
                     ("1.16.0", ENGINE, f'x:1.16.0@{DIGEST}"\nimport os')):
            with self.subTest(argv=argv), self.assertRaises(SystemExit):
                self.run_stamp(*argv)
        self.assertEqual(self.load().VERSION, "0.0.0.dev0")


if __name__ == "__main__":
    unittest.main()
