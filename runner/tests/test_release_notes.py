# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""tools/release_notes.py: the PyPI check and the release notes section."""

import contextlib
import hashlib
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
import urllib.error
import zipfile
from pathlib import Path
from unittest import mock

RUNNER = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("release_notes", RUNNER / "tools" / "release_notes.py")
notes = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(notes)

DIGEST = "sha256:" + "b" * 64
ENGINE = f"ghcr.io/sktelecom/bomlens:1.16.0@{DIGEST}"
LICENSE = f"ghcr.io/sktelecom/bomlens-deep-license:1.16.0@{DIGEST}"
CVE = f"ghcr.io/sktelecom/bomlens-deep-cve:1.16.0@{DIGEST}"
WHEEL = "bomlens_runner-1.16.0-py3-none-any.whl"
SDIST = "bomlens_runner-1.16.0.tar.gz"


def wheel_bytes(engine=ENGINE):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("bomlens_runner/_release.py",
                    f'"""doc"""\nVERSION = "1.16.0"\nENGINE_IMAGE = "{engine}"\n'
                    f'DEEP_LICENSE_IMAGE = "{LICENSE}"\nDEEP_CVE_IMAGE = "{CVE}"\n')
    return buf.getvalue()


class FakePyPI:
    def __init__(self, wheel=None, files=(WHEEL, SDIST)):
        self.wheel = wheel
        self.files = files

    def __call__(self, url, timeout=60):
        if url.startswith("https://pypi.org/"):
            if self.wheel is None:
                raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)
            urls = [{"filename": f, "url": f"https://files.pythonhosted.org/x/{f}",
                     "digests": {"sha256": hashlib.sha256(self.wheel if f.endswith(".whl") else b"sdist").hexdigest()}}
                    for f in self.files]
            return json.dumps({"urls": urls}).encode()
        if url.endswith(".whl"):
            return self.wheel
        raise AssertionError(url)


class ReleaseNotes(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.dist = self.dir / "dist"
        self.dist.mkdir()
        (self.dist / WHEEL).write_bytes(wheel_bytes())
        (self.dist / SDIST).write_bytes(b"sdist")
        self.body = self.dir / "body.md"

    def run_notes(self, pypi, *argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(notes, "fetch", pypi), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = notes.main(list(argv))
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue() + err.getvalue()

    def test_check_passes_a_new_version(self):
        self.assertEqual(self.run_notes(FakePyPI(), "check", "1.16.0", ENGINE, LICENSE, CVE)[0], 0)

    def test_check_passes_the_same_images(self):
        self.assertEqual(self.run_notes(FakePyPI(wheel_bytes()), "check", "1.16.0", ENGINE, LICENSE, CVE)[0], 0)

    def test_check_refuses_other_images_on_pypi(self):
        other = f"ghcr.io/sktelecom/bomlens:1.16.0@sha256:{'c' * 64}"
        code, out = self.run_notes(FakePyPI(wheel_bytes(other)), "check", "1.16.0", ENGINE, LICENSE, CVE)
        self.assertEqual(code, 1)
        self.assertIn(other, out)

    def test_notes_add_the_section_with_images_from_pypi(self):
        self.body.write_text("Release notes\r\n\r\n- a change\r\n")
        code, _ = self.run_notes(FakePyPI(wheel_bytes()), "notes", "1.16.0", "--dist", str(self.dist),
                                 "--body", str(self.body))
        self.assertEqual(code, 0)
        text = self.body.read_text()
        self.assertNotIn("\r", text)
        self.assertTrue(text.startswith("Release notes\n\n- a change\n\n" + notes.START))
        self.assertIn(f"| `{WHEEL}` | `{hashlib.sha256(wheel_bytes()).hexdigest()}` |", text)
        self.assertIn(f"- `{ENGINE}`", text)
        self.assertTrue(text.endswith(notes.END + "\n"))

    def test_notes_replace_an_earlier_section_and_keep_what_follows(self):
        self.body.write_text(f"Intro\n\n{notes.START}\nold\n{notes.END}\n\nAdded by hand\n")
        self.run_notes(FakePyPI(wheel_bytes()), "notes", "1.16.0", "--dist", str(self.dist), "--body", str(self.body))
        once = self.body.read_text()
        self.run_notes(FakePyPI(wheel_bytes()), "notes", "1.16.0", "--dist", str(self.dist), "--body", str(self.body))
        self.assertEqual(self.body.read_text(), once)
        self.assertNotIn("old", once)
        self.assertEqual(once.count(notes.START), 1)
        self.assertTrue(once.endswith("Added by hand\n"))

    def test_notes_wait_until_pypi_lists_every_file(self):
        self.body.write_text("Notes\n")
        code, out = self.run_notes(FakePyPI(wheel_bytes(), files=(SDIST,)), "notes", "1.16.0", "--dist",
                                   str(self.dist), "--body", str(self.body), "--tries", "2", "--delay", "0")
        self.assertNotEqual(code, 0)
        self.assertIn(WHEEL, str(code) + out)
        self.assertEqual(self.body.read_text(), "Notes\n")

    def test_notes_warn_when_a_local_file_differs(self):
        self.body.write_text("Notes\n")
        (self.dist / SDIST).write_bytes(b"rebuilt")
        _, out = self.run_notes(FakePyPI(wheel_bytes()), "notes", "1.16.0", "--dist", str(self.dist),
                                "--body", str(self.body))
        self.assertIn(f"::warning::{SDIST} differs", out)


if __name__ == "__main__":
    unittest.main()
