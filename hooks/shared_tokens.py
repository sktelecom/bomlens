# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Publish the shared design tokens as a site stylesheet.

docker/shared/bomlens-tokens.css is generated from the web UI's index.css
(`npm run tokens:build`, checked in CI by `npm run tokens:check`). The site
reads that file at build time instead of keeping a second copy under docs/, so
it cannot drift from the app.

The token file puts dark values under `.dark`. Material marks its dark scheme
with `data-md-color-scheme="slate"` on <body> instead, so the same block is
also attached to that selector. Nothing else in the file is changed.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE = Path("docker") / "shared" / "bomlens-tokens.css"
TARGET = Path("stylesheets") / "bomlens-tokens.css"
DARK_SELECTOR = ".dark {"
DARK_SELECTOR_WITH_SLATE = '.dark,\n[data-md-color-scheme="slate"] {'


def on_post_build(config, **kwargs):
    # Written after the build rather than registered as a generated page file:
    # the i18n plugin rejects files that have no source path. Both language
    # folders link to the same stylesheet at the site root.
    css = (REPO_ROOT / SOURCE).read_text(encoding="utf-8")
    if css.count(DARK_SELECTOR) != 1:
        raise RuntimeError(f"{SOURCE}: expected exactly one '{DARK_SELECTOR}' block")
    css = css.replace(DARK_SELECTOR, DARK_SELECTOR_WITH_SLATE)
    target = Path(config["site_dir"]) / TARGET
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(css, encoding="utf-8")
