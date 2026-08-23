#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
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
# A pre-existing cpe is left alone UNLESS it is a mechanical copy of the maven
# groupId/artifactId into vendor:product (some generators do this as a fallback
# when they have no real CPE dictionary match, e.g. "org.apache.pdfbox:pdfbox" or
# "com.zaxxer.HikariCP:HikariCP" -- the coordinate glued in verbatim, never a
# looked-up vendor). That narrow, structurally-certain shape is replaced by
# derive_cpe(); any other pre-existing cpe -- including one already set to a
# MAVEN_CPE_MAP vendor, which never has this shape -- is never touched. See
# _is_mechanical_maven_cpe(). Best-effort, idempotent, and a no-op when the SBOM
# has no maven components. Toggle: ENRICH_MAVEN_CPE (default on); the entrypoint
# skips it for AI SBOMs.
#
# A second mechanical shape covers multi-module projects (netty, istack, jna):
# the artifactId is "<last groupId segment>-<submodule>" (io.netty / netty-buffer)
# and some generators build vendor as "<groupId>.<submodule>" (io.netty.buffer) --
# still nothing but the coordinate glued back together, this time per submodule.
# Left as-is it defeats derive_cpe()'s umbrella cpe:2.3:a:netty:netty for every
# submodule, so NVD-only Netty CVEs (which NVD files once under netty:netty, not
# per submodule) never match. See _is_submodule_mechanical_cpe().
#
# NOTE: attaching the CPE is only half the path — a CPE-matching engine (grype
# with GRYPE_MATCH_JAVA_USING_CPES) must run to turn it into findings, and its
# results should be version-filtered against NVD to drop the loose-version
# false-positives grype emits on tomcat modules. Those live in the security step.
import json
import re
import sys

# Curated groupId -> (vendor, product_source) or (vendor, product_source,
# alternates). Verified against NVD. product_source: a literal string, or the
# sentinel "@artifact" meaning "use the component's artifactId as the product"
# (Jackson: fasterxml:jackson-databind).
#
# alternates, when present, is a tuple of extra (vendor, product_source) pairs
# for a project NVD has filed under more than one CPE vendor over its history
# -- a rename or corporate acquisition, where NVD keeps assigning the vendor
# current at each CVE's disclosure date rather than backfilling old ones to
# the new name. A CycloneDX component carries exactly one cpe field, so the
# primary entry above still drives that field; the alternates are attached
# separately (bomlens:cpeAlternates) and looked up as their own grype CPE
# queries by scan-nvd-cpe.py, since a single cpe:2.3 string cannot express
# more than one vendor:product.
MAVEN_CPE_MAP = {
    "com.fasterxml.jackson.core": ("fasterxml", "@artifact"),
    "com.fasterxml.jackson.dataformat": ("fasterxml", "@artifact"),
    # Spring Framework spans three NVD CPE vendors across its corporate history
    # (SpringSource -> acquired by VMware in 2009 -> spun off as Pivotal in
    # 2013 -> reabsorbed into VMware in 2019); NVD assigns whichever vendor was
    # current at each CVE's disclosure date, never backfilling. Confirmed via
    # direct grype CPE lookups: springsource:spring_framework and
    # pivotal_software:spring_framework each carry CVEs vmware:spring_framework
    # alone does not.
    "org.springframework": ("vmware", "spring_framework", (
        ("pivotal_software", "spring_framework"),
        ("springsource", "spring_framework"),
    )),
    # Same split, minus the SpringSource-era name (verified absent).
    "org.springframework.security": ("vmware", "spring_security", (
        ("pivotal_software", "spring_security"),
    )),
    "org.springframework.boot": ("vmware", "spring_boot"),
    "commons-beanutils": ("apache", "commons_beanutils"),
    "commons-fileupload": ("apache", "commons_fileupload"),
    "commons-collections": ("apache", "commons_collections"),
    "org.json": ("stleary", "json-java"),
    # The generic org.apache.* rule (vendor=2nd segment, product=last segment)
    # only holds when NVD's own CPE reuses the groupId's tail. These groups
    # need an explicit override because NVD's product (or vendor) differs from
    # what the rule would derive — each verified against NVD's own cpeMatch
    # data, not guessed.
    "log4j": ("apache", "log4j"),  # single-segment group: the generic rule needs 2+ segments, so this old-style Log4j 1.x groupId gets no CPE without an override
    "org.apache.sshd": ("apache", "mina_sshd"),  # rule would derive apache:sshd; NVD files it under mina_sshd
    "org.apache.xmlgraphics": ("apache", "batik"),  # rule would derive apache:xmlgraphics; this groupId is Batik's, and NVD's product is batik
    "com.h2database": ("h2database", "h2"),  # rule would derive h2database:h2database; NVD's product is h2 (the artifactId, not the groupId tail)
    "rhino": ("mozilla", "rhino"),  # single-segment group, map-only like log4j above
    "net.sourceforge.nekohtml": ("cyberneko_html_project", "cyberneko_html"),  # rule would derive sourceforge:nekohtml
    "org.owasp.antisamy": ("antisamy_project", "antisamy"),  # rule would derive owasp:antisamy
    "org.postgresql": ("postgresql", "postgresql_jdbc_driver"),  # rule would derive postgresql:postgresql
    "org.quartz-scheduler": ("softwareag", "quartz"),  # rule would derive quartz-scheduler:quartz-scheduler
    "org.codehaus.woodstox": ("fasterxml", "woodstox"),  # the pre-rename groupId; NVD files Woodstox CVEs under the current fasterxml vendor regardless of which groupId a given release used
    "com.mchange": ("mchange", "c3p0"),  # rule would derive mchange:mchange; NVD's product is the artifactId c3p0
    "io.opentelemetry.instrumentation": ("linuxfoundation", "opentelemetry_instrumentation_for_java"),  # rule would derive opentelemetry:instrumentation
    "io.undertow": ("redhat", "undertow"),  # rule would derive undertow:undertow; NVD files it under redhat
    "org.eclipse.angus": ("eclipse", "angus_mail"),  # rule would derive eclipse:angus (missing the _mail suffix NVD's product carries)
    "org.bouncycastle": ("bouncycastle", "bc-java"),  # the modern (post-rename) Bouncy Castle groupId; rule would derive bouncycastle:bouncycastle
    "bouncycastle": ("bouncycastle", "bouncy-castle-crypto-package"),  # the legacy (pre-rename) groupId, single-segment so map-only; covers releases up to 1.35, distinct from bc-java above
    # org.mortbay.jetty is Jetty's pre-Eclipse-Foundation groupId (6.x era).
    # The generic rule already derives mortbay:jetty correctly for it -- this
    # entry exists only to attach the eclipse:jetty alternate, since NVD filed
    # at least one Jetty 6.x CVE (CVE-2009-5045) under the current Eclipse
    # vendor even though the release predates the foundation's involvement.
    "org.mortbay.jetty": ("mortbay", "jetty", (
        ("eclipse", "jetty"),
    )),
}

# Versions with a CPE-unsafe shape are left alone: a ':' (cpe field separator),
# whitespace, or a wildcard would shift or break the 13-field cpe:2.3 grammar.
_CPE_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")

# Splits a cpe:2.3 string on unescaped ':' (a field may carry an escaped '\:').
_CPE_FIELD_SPLIT = re.compile(r"(?<!\\):")
_CPE_UNESCAPE = re.compile(r"\\(.)")


def _cpe_vendor_product(cpe):
    """Return (vendor, product) from a cpe:2.3:a:vendor:product:... string, or
    None if it does not look like a well-formed cpe:2.3 URI."""
    parts = _CPE_FIELD_SPLIT.split(cpe)
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return parts[3], parts[4]


def _cpe_norm(s):
    """Undo cpe:2.3 backslash-escaping and lowercase, for text comparison."""
    return _CPE_UNESCAPE.sub(r"\1", s).lower()


def _is_mechanical_maven_cpe(cpe, group, artifact):
    """True when a pre-existing cpe's vendor:product is nothing but the maven
    groupId and/or artifactId copied in verbatim, e.g. vendor=<group> (the whole
    dotted string), vendor=<artifact>, or vendor=<group>+<artifact> concatenated
    -- always paired with product=<artifact>. That shape is a generator's
    fallback when it has no real CPE dictionary match, not a vendor lookup, so
    it carries no more information than an absent cpe and is safe to replace
    with derive_cpe(). Anything else (a real vendor token, however unusual) is
    left alone -- including any cpe already set to a MAVEN_CPE_MAP vendor, which
    by construction never has this shape.
    """
    parsed = _cpe_vendor_product(cpe)
    if not parsed:
        return False
    vendor, product = _cpe_norm(parsed[0]), _cpe_norm(parsed[1])
    na = _cpe_norm(artifact)
    if product != na:
        return False
    ng = _cpe_norm(group)
    return vendor in (ng, na, ng + "." + na, ng + na)


def _is_submodule_mechanical_cpe(cpe, group, artifact):
    """True when a pre-existing cpe's vendor is "<groupId>.<submodule>" and the
    artifactId is exactly "<last groupId segment>-<submodule>" -- e.g. group
    io.netty / artifact netty-buffer / vendor io.netty.buffer. Requires an exact
    reconstruction (last segment + "-" + submodule == artifactId), so a group
    whose last segment does not prefix the artifactId this way never matches.
    Distinct from _is_mechanical_maven_cpe(): that one is the whole
    groupId/artifactId glued in; this one is the groupId with the shared project
    prefix stripped from the artifactId's tail, applied per submodule. Left
    unmatched: extra classifier segments (netty-transport-native-epoll ->
    io.netty.transport-native-epoll.linux-x86_64) and dash-to-dot rewrites
    (swagger-core-jakarta -> io.swagger.core.v3.swagger-core.jakarta) -- both
    still mechanical, but not safe to reconstruct with one exact-match rule.
    """
    parsed = _cpe_vendor_product(cpe)
    if not parsed:
        return False
    vendor, product = _cpe_norm(parsed[0]), _cpe_norm(parsed[1])
    na = _cpe_norm(artifact)
    if product != na:
        return False
    ng = _cpe_norm(group)
    if not vendor.startswith(ng + "."):
        return False
    submodule = vendor[len(ng) + 1:]
    last_segment = ng.rsplit(".", 1)[-1]
    return na == last_segment + "-" + submodule


def _parse_maven(purl):
    """pkg:maven/<group>/<artifact>@<version> -> (group, artifact, version)."""
    m = re.match(r"pkg:maven/([^/]+)/([^@]+)@(.+)$", purl)
    if not m:
        return None
    group, artifact, version = m.group(1), m.group(2), m.group(3).split("?", 1)[0]
    return group, artifact, version


def _cpe_string(vendor, product, version):
    return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"


def derive_cpe(purl):
    """Return (cpe, alt_cpes): an NVD-matchable cpe:2.3 string (or None if we
    cannot map it safely) and a list of additional cpe:2.3 strings for a
    project NVD splits across more than one CPE vendor (see MAVEN_CPE_MAP's
    alternates). alt_cpes is always [] when derive_cpe returns None."""
    parsed = _parse_maven(purl)
    if not parsed:
        return None, []
    group, artifact, version = parsed
    if not _CPE_SAFE_VERSION.match(version):
        return None, []

    vendor = product = None
    alt_specs = ()
    # 1. Curated map (longest groupId prefix wins, so *.security beats *). These
    # override the generic rule where it is known wrong (spring -> vmware, Jackson
    # product = artifact, org.json -> stleary:json-java).
    for prefix in sorted(MAVEN_CPE_MAP, key=len, reverse=True):
        if group == prefix or group.startswith(prefix + "."):
            entry = MAVEN_CPE_MAP[prefix]
            vendor, src = entry[0], entry[1]
            product = artifact if src == "@artifact" else src
            alt_specs = entry[2] if len(entry) > 2 else ()
            break
    else:
        # 2. Generic reverse-domain rule for 2+ segment groups (parts[1]:parts[-1]):
        # org.apache.pdfbox -> apache:pdfbox, com.google.guava -> google:guava,
        # io.netty -> netty:netty (2-segment, where parts[1] == parts[-1]). A wrong
        # guess is self-correcting: grype produces an nvd:cpe finding only when the
        # vendor:product actually exists in NVD, so a mis-derived product (e.g.
        # org.springframework -> springframework:springframework) simply matches
        # nothing — and the curated map above already overrides the ones we know
        # (spring -> vmware). The residual risk (right product, loose version range)
        # is handled by the NVD version filter in scan-nvd-cpe.py. A single-segment
        # group (commons-fileupload) has no domain to split, so it is map-only.
        parts = group.split(".")
        if len(parts) >= 2:
            vendor, product = parts[1], parts[-1]

    if not vendor or not product:
        return None, []
    alt_cpes = [
        _cpe_string(alt_vendor, artifact if alt_src == "@artifact" else alt_src, version)
        for alt_vendor, alt_src in alt_specs
    ]
    return _cpe_string(vendor, product, version), alt_cpes


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
        if not purl.startswith("pkg:maven/"):
            continue  # not maven
        existing = c.get("cpe")
        if existing:
            parsed = _parse_maven(purl)
            if not parsed or not (
                _is_mechanical_maven_cpe(existing, parsed[0], parsed[1])
                or _is_submodule_mechanical_cpe(existing, parsed[0], parsed[1])
            ):
                continue  # a real cpe is already present; never overwrite it
        cpe, alt_cpes = derive_cpe(purl)
        if not cpe or cpe == existing:
            continue
        c["cpe"] = cpe
        props = [p for p in (c.get("properties") or [])
                 if p.get("name") not in ("bomlens:cpeSource", "bomlens:cpeAlternates")]
        props.append({"name": "bomlens:cpeSource", "value": "maven-groupid"})
        if alt_cpes:
            # A second cpe:2.3 the component itself cannot carry (CycloneDX
            # allows exactly one), read back by scan-nvd-cpe.py as extra
            # individual grype CPE lookups. See MAVEN_CPE_MAP's alternates.
            props.append({"name": "bomlens:cpeAlternates", "value": json.dumps(alt_cpes)})
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
