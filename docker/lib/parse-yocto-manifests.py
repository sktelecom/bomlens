#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# parse-yocto-manifests.py — read what a Yocto build wrote about its image when
# it produced no SPDX SBOM, and emit the same CycloneDX + sidecars the SPDX path
# does.
#
# Usage: parse-yocto-manifests.py <build-dir> <out.cdx.json> [out_prefix]
#   writes <out.cdx.json>                   (CycloneDX 1.6, installed packages)
#   writes <out_prefix>_security_yocto.json (Trivy-shaped, unpatched CVEs only)
#   writes <out_prefix>_yocto_vex.json      (patched / ignored / unpatched counts)
#
# Turning create-spdx on is a build-configuration change, and someone holding a
# finished build directory cannot always make one. But a build records what it
# shipped anyway, in three files this reads (formats from openembedded-core):
#
#   tmp*/deploy/images/<machine>/<image>.manifest
#       every installed package, one per line, "<name> <arch> <version>"
#       (rootfs-postcommands.bbclass write_image_manifest -> format_pkg_list "ver")
#   tmp*/deploy/licenses/**/license.manifest
#       per installed package: PACKAGE NAME / PACKAGE VERSION / RECIPE NAME /
#       LICENSE, blank-line separated (license_image.bbclass write_license_files).
#       The image_license.manifest beside it describes the image recipe rather
#       than its contents and is deliberately not read.
#   tmp*/log/cve/cve-summary.json
#       cve-check's report, keyed by RECIPE: {"package": [{"name", "version",
#       "issue": [{"id", "status": Patched|Ignored|Unpatched, "scorev3", ...}]}]}
#       (cve-check.bbclass). license.manifest is what ties a package back to the
#       recipe those verdicts belong to.
#
# Measured against a published Yocto artifact (docs/maintainers/yocto-validation.md):
# Kirkstone 4.0.28 publishes an image manifest and no SPDX at all — 31 packages,
# exactly the set the manifest lists, and no CVE verdicts because that build ran
# no cve-check, which the log says rather than implying there are none to find.
#
# What this is not: the SPDX path. There are no CPEs here, so vulnerability
# matching downstream has only names and versions to work with, and the CVE
# verdicts are only as complete as the build's own cve-check run. When a build
# publishes SPDX, that is read instead — see parse-yocto-spdx.py.
import glob
import json
import os
import re
import sys

CDX_VERSION = "1.6"

# Files that are not the image package manifest, though they end in .manifest.
_NOT_IMAGE_MANIFEST = ("image_license.manifest",)

# cve-check states, in our terms. "Ignored" is the build saying the CVE does not
# apply to how it configured or patched the recipe, which is a judgement, not a
# gap — the same distinction the SPDX 3.0 VEX path draws.
_STATUS_BUCKET = {"Patched": "fixed", "Ignored": "notAffected", "Unpatched": "affected"}


def _newest(paths):
    best, best_mtime = None, None
    for path in paths:
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        if best_mtime is None or mtime > best_mtime:
            best, best_mtime = path, mtime
    return best


def find_image_manifest(build_dir):
    """The newest installed-package manifest a build published."""
    esc = glob.escape(build_dir)
    for pattern in (
        "tmp*/deploy/images/*/*.manifest",
        "deploy/images/*/*.manifest",
        "images/*/*.manifest",
        "*.manifest",
    ):
        hits = [
            p
            for p in glob.glob(os.path.join(esc, pattern))
            if os.path.isfile(p) and os.path.basename(p) not in _NOT_IMAGE_MANIFEST
        ]
        # A symlink and the timestamped file it points at are one manifest.
        seen, unique = set(), []
        for path in sorted(hits):
            real = os.path.realpath(path)
            if real in seen:
                continue
            seen.add(real)
            unique.append(path)
        if unique:
            return _newest(unique)
    return None


def parse_image_manifest(path):
    """[(name, arch, version)] — the installed set, as the build listed it."""
    rows = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                rows.append((parts[0], parts[1], parts[2]))
    except OSError:
        return []
    return rows


def find_license_manifest(build_dir, image_stem):
    """The license manifest belonging to this image, if the build wrote one.

    LICENSE_DIRECTORY has moved between releases (with and without the package
    architecture level), so both shapes are searched. The image name is in the
    directory, which is how the right one is picked when a build directory holds
    several images; failing that, the newest.
    """
    esc = glob.escape(build_dir)
    hits = []
    for pattern in (
        "tmp*/deploy/licenses/*/license.manifest",
        "tmp*/deploy/licenses/*/*/license.manifest",
        "deploy/licenses/*/license.manifest",
        "deploy/licenses/*/*/license.manifest",
        "licenses/*/license.manifest",
    ):
        hits.extend(p for p in glob.glob(os.path.join(esc, pattern)) if os.path.isfile(p))
    if not hits:
        return None
    if image_stem:
        named = [p for p in hits if image_stem in os.path.basename(os.path.dirname(p))]
        if named:
            return _newest(named)
    return _newest(hits)


def parse_license_manifest(path):
    """{package name: {"version", "recipe", "license"}} from the blank-line
    separated blocks license_image.bbclass writes."""
    out, block = {}, {}

    def flush():
        name = block.get("PACKAGE NAME")
        if name:
            out[name] = {
                "version": block.get("PACKAGE VERSION", ""),
                "recipe": block.get("RECIPE NAME", ""),
                "license": block.get("LICENSE", ""),
            }
        block.clear()

    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    flush()
                    continue
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                block[key.strip()] = value.strip()
    except OSError:
        return {}
    flush()
    return out


def find_cve_summary(build_dir):
    esc = glob.escape(build_dir)
    for pattern in ("tmp*/log/cve/cve-summary.json", "log/cve/cve-summary.json",
                    "cve-summary.json"):
        hits = [p for p in glob.glob(os.path.join(esc, pattern)) if os.path.isfile(p)]
        if hits:
            return _newest(hits)
    return None


def _severity(issue):
    """CVSS v3 base score to its qualitative rating (the standard bands). The
    build records the score, not the rating, and the report groups by rating."""
    for key in ("scorev4", "scorev3", "scorev2"):
        try:
            score = float(issue.get(key) or 0)
        except (TypeError, ValueError):
            continue
        if score <= 0:
            continue
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        return "LOW"
    return "UNKNOWN"


def parse_cve_summary(path, recipe_of):
    """(rows, counts) from cve-check's report.

    The report is keyed by recipe; recipe_of maps an installed package back to
    the recipe it came from, so only CVEs belonging to something in the image are
    counted. A recipe that built nothing installed — the native and cross tools —
    is skipped for the same reason the SPDX path skips them.
    """
    counts = {"fixed": 0, "notAffected": 0, "affected": 0}
    rows, seen = [], set()
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return rows, counts
    packages_of_recipe = {}
    for pkg, recipe in recipe_of.items():
        packages_of_recipe.setdefault(recipe, []).append(pkg)

    for entry in data.get("package") or []:
        if not isinstance(entry, dict):
            continue
        installed = packages_of_recipe.get(entry.get("name") or "")
        if not installed:
            continue
        version = entry.get("version") or ""
        for issue in entry.get("issue") or []:
            if not isinstance(issue, dict):
                continue
            bucket = _STATUS_BUCKET.get(issue.get("status") or "")
            if bucket is None:
                continue
            cve = issue.get("id")
            if not cve:
                continue
            # Counted per (CVE, installed package), which is how the findings are
            # counted too: a recipe that produced three packages carries its
            # verdict into all three, and the tally beside the report has to
            # measure the same things the report lists.
            for pkg in sorted(installed):
                key = (cve, pkg)
                if key in seen:
                    continue
                seen.add(key)
                counts[bucket] += 1
                if bucket != "affected":
                    continue
                rows.append(
                    {
                        "VulnerabilityID": cve,
                        "PkgName": pkg,
                        "InstalledVersion": version,
                        "Severity": _severity(issue),
                        "Title": (issue.get("summary") or "")[:200],
                        "PrimaryURL": issue.get("link")
                        or ("https://nvd.nist.gov/vuln/detail/" + cve),
                        "source": "yocto-cve-check",
                    }
                )
    return rows, counts


def image_identity(manifest_path):
    """(name, version) for the root component, from the manifest filename.

    bitbake names it <image>-<machine>.rootfs.manifest (or <image>-<machine>-
    <timestamp>.rootfs.manifest); there is no version in a build directory, so
    the machine stays part of the name rather than being invented into one.
    """
    base = os.path.basename(manifest_path)
    for suffix in (".rootfs.manifest", ".manifest"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    base = re.sub(r"-\d{8}\d*$", "", base)
    return base or "yocto-image"


def build(build_dir):
    """(components, vuln_rows, counts, image_name) or (None, ...) when the build
    left nothing to read."""
    manifest = find_image_manifest(build_dir)
    if not manifest:
        return None, [], {}, ""
    installed = parse_image_manifest(manifest)
    if not installed:
        return None, [], {}, ""

    image_name = image_identity(manifest)
    licenses = parse_license_manifest(find_license_manifest(build_dir, image_name) or "")

    components, recipe_of = [], {}
    for name, arch, version in sorted(installed):
        info = licenses.get(name) or {}
        recipe = info.get("recipe") or ""
        if recipe:
            recipe_of[name] = recipe
        comp = {
            "bom-ref": "yocto-pkg-%s" % name,
            "type": "library",
            "name": name,
            "version": version or info.get("version") or "",
            "properties": [
                {"name": "bomlens:layer", "value": "yocto"},
                {"name": "bomlens:identifiedBy", "value": "yocto-manifest"},
            ],
        }
        if arch:
            comp["properties"].append({"name": "bomlens:yocto:arch", "value": arch})
        if recipe and recipe != name:
            comp["properties"].append({"name": "bomlens:yocto:recipe", "value": recipe})
        expression = (info.get("license") or "").strip()
        if expression and expression not in ("NOASSERTION", "NONE", "CLOSED"):
            if any(op in expression for op in (" AND ", " OR ", " WITH ", "&", "|")):
                # license.manifest carries Yocto's own operators, not SPDX's.
                normalized = expression.replace("&", "AND").replace("|", "OR")
                normalized = " ".join(normalized.split())
                comp["licenses"] = [{"expression": normalized}]
            else:
                comp["licenses"] = [{"license": {"id": expression}}]
        components.append(comp)

    summary = find_cve_summary(build_dir)
    rows, counts = parse_cve_summary(summary, recipe_of) if summary else ([], {})
    return components, rows, counts, image_name


def write_cyclonedx(path, components, image_name):
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_VERSION,
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "bomlens-yocto-manifest"}]},
            "component": {"type": "operating-system", "name": image_name},
        },
        "components": components,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=False)
        fh.write("\n")


def write_sidecars(out_prefix, rows, counts):
    if rows:
        with open(out_prefix + "_security_yocto.json", "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "Results": [
                        {
                            "Target": "yocto image (cve-check)",
                            "Class": "os-pkgs",
                            "Vulnerabilities": rows,
                        }
                    ]
                },
                fh,
                indent=2,
            )
            fh.write("\n")
    if counts:
        with open(out_prefix + "_yocto_vex.json", "w", encoding="utf-8") as fh:
            json.dump(
                {
                    "source": "yocto-cve-check",
                    "judgements": counts,
                    "unresolved": len(rows),
                    "note": (
                        "Counts come from the cve-check report the build wrote. "
                        "'fixed' means a recipe patched that CVE; 'notAffected' "
                        "means the build recorded it as not applying."
                    ),
                },
                fh,
                indent=2,
            )
            fh.write("\n")


def main():
    if len(sys.argv) < 3:
        print(
            "usage: parse-yocto-manifests.py <build-dir> <out.cdx.json> [out_prefix]",
            file=sys.stderr,
        )
        return 2
    build_dir, out = sys.argv[1], sys.argv[2]
    out_prefix = sys.argv[3] if len(sys.argv) > 3 else ""

    if not os.path.isdir(build_dir):
        print("[yocto-manifest] not a directory: %s" % build_dir, file=sys.stderr)
        return 1

    components, rows, counts, image_name = build(build_dir)
    if not components:
        print(
            "[yocto-manifest] no image package manifest in this build directory.",
            file=sys.stderr,
        )
        return 3

    write_cyclonedx(out, components, image_name)
    if out_prefix:
        write_sidecars(out_prefix, rows, counts)

    if counts:
        print(
            "[yocto-manifest] %d installed package(s); cve-check: %d patched, "
            "%d not applicable, %d unpatched."
            % (len(components), counts["fixed"], counts["notAffected"], counts["affected"]),
            file=sys.stderr,
        )
    else:
        print(
            "[yocto-manifest] %d installed package(s); this build ran no cve-check, "
            "so vulnerabilities are matched from the package names and versions alone."
            % len(components),
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
