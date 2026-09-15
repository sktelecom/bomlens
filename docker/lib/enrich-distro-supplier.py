#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# enrich-distro-supplier.py: fill in a distro package's `supplier` with the
# distro project that supplied it.
#
# Usage: enrich-distro-supplier.py <sbom.json>   (CycloneDX JSON, edited in place)
#
# Why: a syft-generated rpm/deb/apk component carries `publisher`, but never
# `supplier` (verified across all three ecosystems). deb and apk put an
# individual maintainer's name and email there, different per package; rpm
# already puts the distro project there, from the rpm database's own Vendor
# field, the same value across every package. `publisher` and `supplier` are
# different CycloneDX fields (who published it, versus who supplied it to
# the consumer), so rpm's own publisher value is not treated as already
# answering the question: this script fills `supplier` for rpm too.
#
# Distro identification reuses enrich-os-context.py's own work rather than
# reclassifying each PURL: that script already infers the dominant distro
# from the SBOM's rpm/deb/apk PURLs and appends one `operating-system`
# component, or records why it could not (see below for what that means
# here). This script only reads that component's `name`.
#
# Only three distros have a supplier name confirmed from a source in this
# repository; no guessed names are hardcoded:
#   - debian -> "Debian" (docker/lib/notices/THIRD_PARTY_LICENSES.md)
#   - alpine -> "Alpine" (docker/lib/notices/THIRD_PARTY_LICENSES.md)
#   - rocky  -> "Rocky Enterprise Software Foundation" (a real scan's own
#     syft output: the rpm `publisher` field and the `cpe` vendor slug agree)
# enrich-os-context.py's own vocabulary has six more distro names (ubuntu,
# fedora, centos, redhat, alma, amazon) with no such source found yet; an SBOM
# with one of those as its distro is left untouched, same as an unrecognized
# distro would be.
#
# Safe by construction, matching the Maven/Cargo/npm workspace-member filters
# and enrich-os-context.py's own contract:
#   - No operating-system component, more than one, or `bomlens:os-context-
#     ambiguous` set (the SBOM mixes distros and the OS component names only
#     the majority one) -> nothing filled, no guessing which package belongs
#     to which distro.
#   - A distro name not in the table above -> nothing filled.
#   - A component that already carries a non-empty `supplier` -> left alone.
# Best-effort: any read/parse failure leaves the SBOM unchanged. Idempotent:
# a second run finds every target component already carries a supplier and
# changes nothing.
#
# Toggle: ENRICH_DISTRO_SUPPLIER (default on); the entrypoint skips it for AI
# SBOMs, same as the other enrich steps.
import json
import sys

# os-context `name` -> the supplier org name, confirmed from a source in this
# repository (see the module docstring). A name with no confirmed source is
# deliberately absent rather than guessed.
DISTRO_SUPPLIER = {
    "debian": "Debian",
    "alpine": "Alpine",
    "rocky": "Rocky Enterprise Software Foundation",
}

DISTRO_PKG_PREFIXES = ("pkg:deb/", "pkg:rpm/", "pkg:apk/")


def enrich(path):
    try:
        with open(path) as f:
            doc = json.load(f)
    except (OSError, ValueError) as exc:
        print(f"[distro-supplier] WARN: could not read SBOM ({exc}); skipping", file=sys.stderr)
        return
    if doc.get("bomFormat") != "CycloneDX":
        return

    components = doc.get("components")
    if not isinstance(components, list):
        return

    meta = doc.get("metadata")
    props = meta.get("properties") if isinstance(meta, dict) else None
    if isinstance(props, list) and any(
        isinstance(p, dict) and p.get("name") == "bomlens:os-context-ambiguous" for p in props
    ):
        return  # more than one distro voted on; the majority-only OS name is not trustworthy per-package

    os_components = [c for c in components if c.get("type") == "operating-system"]
    if len(os_components) != 1:
        return  # none synthesized (no distro packages, or os-context-unmatched), or an unexpected second one

    supplier_name = DISTRO_SUPPLIER.get(os_components[0].get("name"))
    if not supplier_name:
        return  # a real distro os-context does not have a confirmed supplier name yet

    changed = 0
    for c in components:
        purl = c.get("purl") or ""
        if not purl.startswith(DISTRO_PKG_PREFIXES):
            continue
        if c.get("supplier"):
            continue
        c["supplier"] = {"name": supplier_name}
        changed += 1

    if changed:
        _write(path, doc)
        print(f"[distro-supplier] filled supplier ({supplier_name}) on {changed} component(s).")


def _write(path, doc):
    with open(path, "w") as f:
        json.dump(doc, f, ensure_ascii=False)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: enrich-distro-supplier.py <sbom.json>", file=sys.stderr)
        sys.exit(2)
    enrich(sys.argv[1])
