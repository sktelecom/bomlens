# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
"""Write a release's version and image references into _release.py.

Usage: stamp_release.py VERSION ENGINE [DEEP_LICENSE] [DEEP_CVE] [--file PATH]

Each image is repository:tag@sha256:<digest>. The values are checked the way
the runner checks them, so a package that would refuse its own images is
never built.
"""

import argparse
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from bomlens_runner.errors import PolicyError  # noqa: E402
from bomlens_runner.images import PinnedImage  # noqa: E402

VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(\.post[0-9]+)?")
DEFAULT_FILE = HERE.parent / "src" / "bomlens_runner" / "_release.py"


def render(version: str, engine: str, deep_license: str, deep_cve: str, header: str) -> str:
    return (f'{header}VERSION = "{version}"\nENGINE_IMAGE = "{engine}"\n'
            f'DEEP_LICENSE_IMAGE = "{deep_license}"\nDEEP_CVE_IMAGE = "{deep_cve}"\n')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("version")
    parser.add_argument("engine")
    parser.add_argument("deep_license", nargs="?", default="")
    parser.add_argument("deep_cve", nargs="?", default="")
    parser.add_argument("--file", type=Path, default=DEFAULT_FILE)
    args = parser.parse_args(argv)

    if not VERSION_RE.fullmatch(args.version):
        parser.error("version must be MAJOR.MINOR.PATCH, or that with .postN")
    for ref in (args.engine, args.deep_license, args.deep_cve):
        if not ref:
            continue
        try:
            image = PinnedImage.parse(ref)
        except PolicyError as exc:
            parser.error(str(exc))
        # A .postN package is a re-publication of the release: its images keep the release's tag.
        if image.ref.rsplit(":", 1)[1] != args.version.split(".post")[0]:
            parser.error(f"{image.repository} is not tagged {args.version.split('.post')[0]}")
    if not args.engine:
        parser.error("the engine image is required")

    text = args.file.read_text(encoding="utf-8")
    header = text[:text.index("VERSION = ")]
    args.file.write_text(render(args.version, args.engine, args.deep_license, args.deep_cve, header),
                         encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
