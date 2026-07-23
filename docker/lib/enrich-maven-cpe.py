#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# Licensed under the Apache License, Version 2.0.
#
# enrich-maven-cpe.py — attach an NVD-matchable cpe:2.3 to maven components so a
# CPE-aware scanner (grype) can find their NVD-only CVEs.
#
# Usage: enrich-maven-cpe.py <sbom.json>   (CycloneDX JSON, edited in place)
#
# Why: maven libraries carry a PURL (pkg:maven/group/artifact@version) but no CPE.
# Trivy/OSV/grype match maven against GitHub Security Advisory, which lacks the
# NVD-only CVEs of older Apache libraries (pdfbox 1.8.7, poi 3.6, tomcat 7.0.50).
# Those CVEs live in NVD, keyed by CPE (e.g. cpe:2.3:a:apache:pdfbox). A scanner
# can only reach them if the component carries the right CPE. grype's own CPE
# generation is unusable here — it packs the whole coordinate into vendor:product
# ("org.apache.pdfbox:pdfbox"), which never matches NVD's "apache:pdfbox".
#
# What it does: derive vendor:product from the maven groupId and attach
# cpe:2.3:a:<vendor>:<product>:<version>. Two sources, accuracy first:
#   1. A curated map (MAVEN_CPE_MAP) for well-known groups whose CPE cannot be
#      derived mechanically — each entry verified against NVD. Spring is
#      vmware:spring_framework, Jackson's product is the artifact not the group
#      tail, org.json is stleary:json-java. Guessing these would inject wrong CVEs.
#   2. A conservative rule for org.apache.* only, where the pattern holds
#      (org.apache.pdfbox -> apache:pdfbox, org.apache.poi -> apache:poi).
# Anything else gets NO CPE — a wrong vendor:product is worse than none, so we
# never guess outside the map and the apache rule.
#
# A pre-existing cpe is never overwritten. Best-effort, idempotent, and a no-op
# when the SBOM has no maven components. Toggle: ENRICH_MAVEN_CPE (default on);
# the entrypoint skips it for AI SBOMs.
#
# NOTE: attaching the CPE is only half the path — a CPE-matching engine (grype
# with GRYPE_MATCH_JAVA_USING_CPES) must run to turn it into findings, and its
# results should be version-filtered against NVD to drop the loose-version
# false-positives grype emits on tomcat modules. Those live in the security step.
import json
import re
import sys

# Curated groupId -> (vendor, product_source). Verified against NVD.
# product_source: a literal string, or the sentinel "@artifact" meaning "use the
# component's artifactId as the product" (Jackson: fasterxml:jackson-databind).
MAVEN_CPE_MAP = {
    "com.fasterxml.jackson.core": ("fasterxml", "@artifact"),
    "com.fasterxml.jackson.dataformat": ("fasterxml", "@artifact"),
    "org.springframework": ("vmware", "spring_framework"),
    "org.springframework.security": ("vmware", "spring_security"),
    "commons-beanutils": ("apache", "commons_beanutils"),
    "commons-fileupload": ("apache", "commons_fileupload"),
    "commons-collections": ("apache", "commons_collections"),
    "org.json": ("stleary", "json-java"),
}

# Versions with a CPE-unsafe shape are left alone: a ':' (cpe field separator),
# whitespace, or a wildcard would shift or break the 13-field cpe:2.3 grammar.
_CPE_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


def _parse_maven(purl):
    """pkg:maven/<group>/<artifact>@<version> -> (group, artifact, version)."""
    m = re.match(r"pkg:maven/([^/]+)/([^@]+)@(.+)$", purl)
    if not m:
        return None
    group, artifact, version = m.group(1), m.group(2), m.group(3).split("?", 1)[0]
    return group, artifact, version


def derive_cpe(purl):
    """Return an NVD-matchable cpe:2.3 string, or None if we cannot map it safely."""
    parsed = _parse_maven(purl)
    if not parsed:
        return None
    group, artifact, version = parsed
    if not _CPE_SAFE_VERSION.match(version):
        return None

    vendor = product = None
    # 1. Curated map (longest groupId prefix wins, so *.security beats *).
    for prefix in sorted(MAVEN_CPE_MAP, key=len, reverse=True):
        if group == prefix or group.startswith(prefix + "."):
            vendor, src = MAVEN_CPE_MAP[prefix]
            product = artifact if src == "@artifact" else src
            break
    else:
        # 2. Conservative rule: org.apache.<product> -> apache:<product>.
        parts = group.split(".")
        if len(parts) >= 3 and parts[0] == "org" and parts[1] == "apache":
            vendor, product = "apache", parts[2]

    if not vendor or not product:
        return None
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def enrich(path):
    try:
        with open(path) as f:
            doc = json.load(f)
    except (OSError, ValueError) as exc:
        print(f"[maven-cpe] WARN: could not read SBOM ({exc}); skipping", file=sys.stderr)
        return
    if doc.get("bomFormat") != "CycloneDX":
        return
    components = doc.get("components")
    if not isinstance(components, list):
        return

    n = 0
    for c in components:
        purl = c.get("purl", "")
        if not purl.startswith("pkg:maven/") or c.get("cpe"):
            continue  # not maven, or a CPE is already present (never overwrite)
        cpe = derive_cpe(purl)
        if not cpe:
            continue
        c["cpe"] = cpe
        props = [p for p in (c.get("properties") or []) if p.get("name") != "bomlens:cpeSource"]
        props.append({"name": "bomlens:cpeSource", "value": "maven-groupid"})
        c["properties"] = props
        n += 1

    if n:
        with open(path, "w") as f:
            json.dump(doc, f, ensure_ascii=False)
        print(f"[maven-cpe] attached an NVD-matchable cpe:2.3 to {n} maven component(s) "
              f"for CPE-based CVE matching.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: enrich-maven-cpe.py <sbom.json>", file=sys.stderr)
        sys.exit(2)
    enrich(sys.argv[1])
