# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Publish a copy of the sitemap under each language folder.

The theme's language switcher looks for `sitemap.xml` next to the page it is
on, so on the Korean site it requests /ko/sitemap.xml to find the matching
English page. The i18n plugin writes one sitemap at the root only, so that
request returned 404 and the switcher fell back to the other language's home
page. The root sitemap already lists every page with its language alternates,
so the same file serves both folders.
"""

import shutil
from pathlib import Path


def on_post_build(config, **kwargs):
    site = Path(config["site_dir"])
    source = site / "sitemap.xml"
    if not source.is_file():
        return
    for language in config["plugins"]["i18n"].config.languages:
        locale = language.locale
        if language.default or not language.build:
            continue
        target = site / locale
        if target.is_dir():
            shutil.copyfile(source, target / "sitemap.xml")
