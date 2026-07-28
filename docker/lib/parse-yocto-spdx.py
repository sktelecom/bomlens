#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# parse-yocto-spdx.py — read a Yocto SPDX 3.0 image SBOM and emit CycloneDX plus
# the vulnerability judgement Yocto already made during the build.
#
# Usage: parse-yocto-spdx.py <image.spdx.json> <out.cdx.json> [out_prefix]
#   writes <out.cdx.json>                      (CycloneDX 1.6, installed packages)
#   writes <out_prefix>_security_yocto.json    (Trivy-shaped sidecar, AFFECTED only)
#   writes <out_prefix>_yocto_vex.json         (judgement counts for the UI)
#
# Why not syft: syft converts this document, but it drops the two things that make
# a Yocto SBOM worth having. Measured on a real core-image-minimal (Scarthgap,
# SPDX 3.0.1): syft emits 1000 components of which 872 are source FILES and only 35
# are packages actually installed in the image, and it discards every vulnerability
# (`vulnerabilities: 0`) even though the document carries 3188 of them.
#
# What this reads instead (all verified against that sample):
#   - software_Package with software_primaryPurpose == "install"  -> the shipped set.
#     The other 92 packages are upstream source tarballs consumed by the build.
#   - hasConcludedLicense edges                                   -> licenses.
#     All 35 installed packages carry one directly; no need to walk build edges.
#   - externalIdentifier[cpe23]                                   -> component.cpe.
#     Yocto writes these from CVE_PRODUCT with a wildcard vendor.
#   - hasAssociatedVulnerability edges + the two VEX relationship types.
#
# The VEX split is the point. Yocto knows whether it applied the patch, so a CVE it
# reports as `fixedIn` is genuinely closed on this image — an outside scanner keyed
# on version alone would report it as open. On the reference image every one of the
# 12318 vulnerability links resolves to fixed (12255) or not-affected (63), leaving
# zero unresolved. Only unresolved ones reach the security sidecar; the rest are
# counted separately so the UI can show the work the build already did without
# inflating the risk numbers.
#
# Vulnerabilities that hang off build-host recipes (`-native`, `-cross`, ...) never
# link to an installed package, so filtering by recipe name is unnecessary: reading
# only the hasAssociatedVulnerability edges of installed packages excludes them.
#
# Best-effort by contract: unknown element shapes are skipped rather than fatal, and
# the caller always receives a valid (possibly empty) CycloneDX envelope.
import json
import os
import sys

CDX_VERSION = "1.6"

# SPDX 3.0 VEX relationship types we understand. Anything else leaves the
# vulnerability unresolved, which is the safe direction (it stays visible).
VEX_FIXED = "security_VexFixedVulnAssessmentRelationship"
VEX_NOT_AFFECTED = "security_VexNotAffectedVulnAssessmentRelationship"
REL_TYPES = ("Relationship", "LifecycleScopedRelationship")


def _iter_graph(doc):
    g = doc.get("@graph")
    return g if isinstance(g, list) else []


def _ext_ids(element, kind):
    """External identifiers of one type, e.g. 'cpe23' or 'cve'."""
    out = []
    for x in element.get("externalIdentifier") or []:
        if isinstance(x, dict) and x.get("externalIdentifierType") == kind:
            ident = x.get("identifier")
            if ident:
                out.append(ident)
    return out


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def _licenses_cdx(expression):
    """CycloneDX licenses[] for one SPDX license expression.

    A compound expression (AND/OR) is not a license id, so it goes in `expression`;
    a bare id goes in `license.id`. Same shape enrich-cpe.sh produces, so downstream
    license classification sees one format regardless of which path built the SBOM.
    """
    if not expression:
        return []
    if " AND " in expression or " OR " in expression or " WITH " in expression:
        return [{"expression": expression}]
    return [{"license": {"id": expression}}]


def load_document(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def is_yocto_spdx3(doc):
    """True when this looks like a Yocto-produced SPDX 3.x document."""
    ctx = doc.get("@context")
    ctx_s = ctx if isinstance(ctx, str) else json.dumps(ctx or "")
    if "spdx.org/rdf/3" not in ctx_s:
        return False
    for e in _iter_graph(doc):
        if e.get("type") == "Tool" and "bitbake" in str(e.get("name", "")).lower():
            return True
        # The document namespace carries the producer even when the Tool element
        # is named differently across releases.
        if "bitbake" in str(e.get("spdxId", "")).lower():
            return True
    return False


def extract(doc):
    """Return (components, vuln_rows, counts) from a Yocto SPDX 3.0 document."""
    graph = _iter_graph(doc)
    by_id = {e["spdxId"]: e for e in graph if isinstance(e, dict) and e.get("spdxId")}

    installed = {
        e["spdxId"]: e
        for e in graph
        if e.get("type") == "software_Package"
        and e.get("software_primaryPurpose") == "install"
        and e.get("spdxId")
    }

    fixed_ids = {e.get("from") for e in graph if e.get("type") == VEX_FIXED}
    not_affected_ids = {e.get("from") for e in graph if e.get("type") == VEX_NOT_AFFECTED}

    license_of = {}
    vulns_of = {}
    for rel in graph:
        if rel.get("type") not in REL_TYPES:
            continue
        rtype = rel.get("relationshipType")
        src = rel.get("from")
        if src not in installed:
            continue
        if rtype == "hasConcludedLicense":
            targets = _as_list(rel.get("to"))
            if targets:
                lic = by_id.get(targets[0], {})
                expr = lic.get("simplelicensing_licenseExpression")
                if expr:
                    license_of[src] = expr
        elif rtype == "hasAssociatedVulnerability":
            vulns_of.setdefault(src, []).extend(_as_list(rel.get("to")))

    components = []
    for spdx_id, pkg in sorted(installed.items(), key=lambda kv: kv[1].get("name") or ""):
        name = pkg.get("name")
        if not name:
            continue
        version = pkg.get("software_packageVersion") or ""
        comp = {
            "bom-ref": spdx_id,
            "type": "library",
            "name": name,
            "version": version,
            "properties": [
                {"name": "bomlens:layer", "value": "yocto"},
                {"name": "bomlens:identifiedBy", "value": "yocto-spdx"},
            ],
        }
        cpes = _ext_ids(pkg, "cpe23")
        if cpes:
            comp["cpe"] = cpes[0]
        licenses = _licenses_cdx(license_of.get(spdx_id))
        if licenses:
            comp["licenses"] = licenses
        components.append(comp)

    counts = {"fixed": 0, "notAffected": 0, "affected": 0}
    vuln_rows = []
    seen = set()
    for spdx_id, vuln_ids in vulns_of.items():
        pkg = installed[spdx_id]
        for vid in vuln_ids:
            vuln = by_id.get(vid)
            if not vuln:
                continue
            if vid in fixed_ids:
                counts["fixed"] += 1
                continue
            if vid in not_affected_ids:
                counts["notAffected"] += 1
                continue
            counts["affected"] += 1
            cve_ids = _ext_ids(vuln, "cve")
            cve = cve_ids[0] if cve_ids else None
            if not cve:
                continue
            key = (cve, pkg.get("name"), pkg.get("software_packageVersion") or "")
            if key in seen:
                continue
            seen.add(key)
            vuln_rows.append(
                {
                    "VulnerabilityID": cve,
                    "PkgName": pkg.get("name") or "",
                    "InstalledVersion": pkg.get("software_packageVersion") or "",
                    "Severity": "UNKNOWN",
                    "PrimaryURL": "https://nvd.nist.gov/vuln/detail/" + cve,
                    "source": "yocto-spdx",
                }
            )

    return components, vuln_rows, counts


def write_cyclonedx(path, components, source_name):
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_VERSION,
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "bomlens-yocto-spdx"}]},
            "component": {"type": "operating-system", "name": source_name},
        },
        "components": components,
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=False)
        fh.write("\n")


def write_sidecars(out_prefix, vuln_rows, counts):
    """Security sidecar (unresolved only) plus the judgement counts for the UI."""
    if vuln_rows:
        sidecar = {
            "Results": [
                {
                    "Target": "yocto image (SPDX VEX)",
                    "Class": "os-pkgs",
                    "Vulnerabilities": vuln_rows,
                }
            ]
        }
        with open(out_prefix + "_security_yocto.json", "w", encoding="utf-8") as fh:
            json.dump(sidecar, fh, indent=2)
            fh.write("\n")
    with open(out_prefix + "_yocto_vex.json", "w", encoding="utf-8") as fh:
        json.dump(
            {
                "source": "yocto-spdx",
                "judgements": counts,
                "unresolved": len(vuln_rows),
                "note": (
                    "Counts come from the VEX statements Yocto wrote during the build. "
                    "'fixed' means the recipe applied the patch for that CVE."
                ),
            },
            fh,
            indent=2,
        )
        fh.write("\n")


def main():
    if len(sys.argv) < 3:
        print(
            "usage: parse-yocto-spdx.py <image.spdx.json> <out.cdx.json> [out_prefix]",
            file=sys.stderr,
        )
        return 2
    src, out = sys.argv[1], sys.argv[2]
    out_prefix = sys.argv[3] if len(sys.argv) > 3 else ""

    try:
        doc = load_document(src)
    except (OSError, ValueError) as exc:
        print("[yocto-spdx] cannot read %s: %s" % (src, exc), file=sys.stderr)
        return 1

    if not is_yocto_spdx3(doc):
        print("[yocto-spdx] not a Yocto SPDX 3.x document; leaving it to syft.", file=sys.stderr)
        return 3

    components, vuln_rows, counts = extract(doc)
    if not components:
        # A Yocto document with no installed packages means we read the wrong
        # element set — fail rather than hand the pipeline an empty SBOM that
        # would render as "nothing found".
        print(
            "[yocto-spdx] no installed packages found (software_primaryPurpose=install).",
            file=sys.stderr,
        )
        return 1

    write_cyclonedx(out, components, os.path.basename(src))
    if out_prefix:
        write_sidecars(out_prefix, vuln_rows, counts)

    print(
        "[yocto-spdx] %d installed package(s); vulnerabilities: %d fixed, %d not-affected, "
        "%d unresolved."
        % (len(components), counts["fixed"], counts["notAffected"], counts["affected"]),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
