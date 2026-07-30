#!/usr/bin/env python3
# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
#
# enrich-os-context.py — synthesize an operating-system component from distro
# package PURLs so the vulnerability scanner can match rpm/deb/apk CVEs.
#
# Usage: enrich-os-context.py <sbom.json>   (CycloneDX JSON, edited in place)
#
# Why: a supplier SBOM can list every OS package (pkg:rpm/centos/...,
# pkg:deb/debian/..., pkg:apk/alpine/...) yet omit an `operating-system`
# component. Trivy needs that OS component to know which distro advisory database
# to match against; without it, an SBOM full of distro packages returns ZERO
# findings even though the PURLs are perfectly formed. Adding one OS component
# recovers them — measured with Trivy v0.72: a CentOS SBOM went from 0 to tens of
# thousands of findings, and single-package probes for openssl went 0 -> 39
# (alpine 3.17), 0 -> 15 (debian 10), 0 -> 22 (ubuntu 18.04) once the OS component
# was present. deb and apk need the OS component just as rpm does; they are NOT
# recovered by the PURL alone.
#
# What it does: infer (distro, version) from the dominant distro PURL and append a
# single `operating-system` component.
#   - rpm  : namespace (centos/rocky/redhat/...) + `.elN` suffix or a `distro=`
#            qualifier -> MAJOR version (Trivy keys rpm distros by major).
#   - apk  : `distro=alpine-<ver>` qualifier -> alpine + that version (Trivy
#            tolerates the patch, e.g. 3.17 / 3.17.10 both match).
#   - deb  : `distro=<debian|ubuntu>-<ver>` qualifier -> debian (reduced to major,
#            Trivy keys debian by major) or ubuntu (kept as major.minor, its
#            advisory key). A distro version is REQUIRED — a deb/apk PURL without a
#            `distro=` qualifier carries no OS version to match against, so nothing
#            is synthesized (the version is never guessed).
# If the SBOM already carries an OS component, only normalize its version to the
# major for RHEL-like distros (a syft-supplied "rocky 8.10" matches nothing and is
# corrected to "8"); syft's native deb/apk OS versions already match and are left
# as-is.
#
# Not covered: distros Trivy carries no advisory DB for (e.g. OpenWRT/Buildroot —
# verified 0 findings even with an `openwrt` OS component). Those firmware images
# are matched by the cve-bin-tool sidecar in FIRMWARE mode instead.
#
# Accuracy first: only namespaces/qualifiers we can name a Trivy distro for are
# voted on; an unrecognized distro or a version-less PURL is left untouched.
# Best-effort: any failure leaves the SBOM unchanged and never aborts the scan.
# Idempotent: re-running is a no-op once the OS component exists and its version is
# already normalized.
#
# Toggle: ENRICH_OS_CONTEXT (default on); the entrypoint skips it for AI SBOMs.
import json
import re
import sys

# rpm PURL namespace -> the OS `name` Trivy matches on. Only namespaces we can map
# to a distro Trivy actually carries are listed; anything else is not voted on.
NS_TO_OS = {
    "centos": "centos",
    "rocky": "rocky",
    "rhel": "redhat",
    "redhat": "redhat",
    "almalinux": "alma",
    "alma": "alma",
    "amazon": "amazon",
    "amzn": "amazon",
    "fedora": "fedora",
}

# apk / deb distro id (from the `distro=<id>-<ver>` qualifier, or the PURL
# namespace) -> the OS `name` Trivy matches on. Same closed-list discipline as rpm.
APK_TO_OS = {"alpine": "alpine"}
DEB_TO_OS = {"debian": "debian", "ubuntu": "ubuntu"}

# Distros Trivy matches by MAJOR version only; a minor-carrying version ("8.10")
# matches nothing and must be reduced to the major ("8"). Debian is keyed by major
# too ("11"), while alpine (3.17) and ubuntu (18.04) keep their full release id.
RHEL_LIKE = {"centos", "rocky", "redhat", "alma", "fedora", "amazon"}
DEB_MAJOR_ONLY = {"debian"}


def _ns(purl, prefix):
    """pkg:<type>/<ns>/name@ver -> <ns> (lowercased) for the given pkg: prefix."""
    return purl[len(prefix):].split("/", 1)[0].split("@", 1)[0].lower()


def _classify(purl):
    """Map one distro PURL to a (os_name, version) Trivy can match, or None.

    rpm keys by major version; deb (debian) by major, ubuntu by major.minor;
    apk (alpine) by its release id. deb/apk REQUIRE a `distro=` qualifier for the
    version — it is never guessed."""
    if not purl:
        return None

    if purl.startswith("pkg:rpm/"):
        os_name = NS_TO_OS.get(_ns(purl, "pkg:rpm/"))
        if not os_name:
            return None
        # A `distro=<name>-<major>[.minor]` qualifier is authoritative; the
        # `[0-9]+` stops at the dot so we take the major only (Trivy keys rpm
        # distros by major version).
        mq = re.search(r"distro=([a-z]+)-([0-9]+)", purl)
        if mq:
            return (NS_TO_OS.get(mq.group(1), mq.group(1)), mq.group(2))
        # Otherwise the `.elN` release suffix carries the major version.
        me = re.search(r"\.el(\d+)", purl)
        if me:
            return (os_name, me.group(1))
        return None

    if purl.startswith("pkg:apk/") or purl.startswith("pkg:deb/"):
        # apk/deb PURLs from syft carry `distro=<id>-<versionId>` (e.g.
        # alpine-3.17.10, debian-11, ubuntu-18.04). The version is required — no
        # qualifier means no matchable OS version, so we skip rather than guess.
        dq = re.search(r"[?&]distro=([a-z][a-z0-9]*)-([0-9][0-9.]*)", purl)
        table = APK_TO_OS if purl.startswith("pkg:apk/") else DEB_TO_OS
        ns = _ns(purl, "pkg:apk/" if purl.startswith("pkg:apk/") else "pkg:deb/")
        did = dq.group(1) if dq else None
        os_name = table.get(did) or table.get(ns)
        if not os_name or not dq:
            return None
        ver = dq.group(2)
        if os_name in DEB_MAJOR_ONLY:
            ver = ver.split(".", 1)[0]
        return (os_name, ver)

    return None


def infer_os(purls):
    """Vote a dominant (os_name, version) from distro PURLs. None if none map."""
    votes = {}
    for p in purls:
        key = _classify(p)
        if key:
            votes[key] = votes.get(key, 0) + 1
    if not votes:
        return None
    (os_name, version), n = max(votes.items(), key=lambda kv: kv[1])
    return {"name": os_name, "version": version, "votes": n,
            "total": sum(votes.values())}


def enrich(path):
    try:
        with open(path) as f:
            doc = json.load(f)
    except (OSError, ValueError) as exc:
        print(f"[os-context] WARN: could not read SBOM ({exc}); skipping", file=sys.stderr)
        return
    if doc.get("bomFormat") != "CycloneDX":
        return  # pipeline is CycloneDX here; anything else is left untouched

    components = doc.get("components")
    if not isinstance(components, list):
        return

    purls = [c.get("purl") for c in components if c.get("purl")]
    existing = [c for c in components if c.get("type") == "operating-system"]

    if existing:
        # Do not add a second OS; only fix a minor-carrying version on RHEL-like
        # distros so Trivy can match (e.g. "rocky 8.10" -> "8").
        fixed = 0
        for c in existing:
            name = str(c.get("name", "")).lower()
            ver = str(c.get("version", ""))
            if name in RHEL_LIKE and "." in ver:
                c["version"] = ver.split(".", 1)[0]
                fixed += 1
        if fixed:
            _write(path, doc)
            print(f"[os-context] normalized {fixed} existing OS component version(s) "
                  f"to major for distro matching.")
        return

    os_info = infer_os(purls)
    if not os_info:
        return  # no recognizable distro packages (non-OS SBOM, an unsupported
        # distro like OpenWRT, or deb/apk PURLs with no distro= version qualifier)

    components.append({
        "type": "operating-system",
        "name": os_info["name"],
        "version": os_info["version"],
        "bom-ref": "bomlens-os-context",
    })
    _write(path, doc)
    print(f"[os-context] synthesized operating-system component "
          f"{os_info['name']} {os_info['version']} "
          f"({os_info['votes']}/{os_info['total']} distro packages) for CVE matching.")


def _write(path, doc):
    with open(path, "w") as f:
        json.dump(doc, f, ensure_ascii=False)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: enrich-os-context.py <sbom.json>", file=sys.stderr)
        sys.exit(2)
    enrich(sys.argv[1])
